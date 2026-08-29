//! Incremental Traefik access-log reader.
//!
//! The log is only ever read *forward* from a saved byte offset, so a 2 GB
//! access log costs the same per tick as an empty one. Rotation is detected by
//! (inode, size): a new inode or a file that shrank means "start again at 0".
//! A single tick will never ingest more than `MAX_TICK_BYTES`, so a log that
//! explodes during an attack cannot turn the reader itself into the outage.
//!
//! Both Traefik formats are understood: JSON (`--accesslog.format=json`) and
//! the default extended CLF.
use crate::util::valid_ip;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

/// Hard cap on bytes consumed per tick (~48 MB of log, several 100k requests).
const MAX_TICK_BYTES: u64 = 48 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Req {
    pub ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    pub ua: String,
    pub duration_ms: f64,
}

impl Req {
    /// The resource being requested: the path with its query string and
    /// fragment removed, e.g. `/api/search?q=cat` -> `/api/search`.
    ///
    /// Deliberately NOT id-folded. Folding `/article/1` and `/article/2` into
    /// one endpoint would make a news site — where a crowd reads *different*
    /// articles — look like a flood on a single endpoint, which is exactly the
    /// false positive the detector must avoid. Raw-path diversity is a signal,
    /// not noise: a botnet hammering `/api/search` concentrates here, while a
    /// crowd browsing many articles spreads out here. Parameterised floods
    /// (`/api/user/8412`, `/api/user/8413`, …) are still caught by the
    /// volumetric, rate, source and behavioural signals.
    pub fn endpoint(&self) -> String {
        let p = self.path.split(['?', '#']).next().unwrap_or("/");
        if p.is_empty() {
            return "/".into();
        }
        // cap length so a pathological URL cannot bloat the key space
        p.chars().take(120).collect()
    }

    /// A coarse template with trailing id-like segments folded, used only for
    /// grouping in display lists — never for detection.
    pub fn template(&self) -> String {
        let p = self.path.split(['?', '#']).next().unwrap_or("/");
        let mut out = String::with_capacity(p.len());
        for seg in p.split('/') {
            if seg.is_empty() {
                continue;
            }
            out.push('/');
            let digits = seg.chars().filter(|c| c.is_ascii_digit()).count();
            if (seg.len() >= 8 && digits * 3 >= seg.len())
                || (!seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()))
            {
                out.push_str(":id");
            } else {
                out.push_str(&seg.chars().take(48).collect::<String>());
            }
        }
        if out.is_empty() {
            out.push('/');
        }
        out
    }
}

fn json_str(v: &serde_json::Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn json_u64(v: &serde_json::Value, k: &str) -> u64 {
    v.get(k)
        .and_then(|x| x.as_u64().or_else(|| x.as_f64().map(|f| f.max(0.0) as u64)))
        .unwrap_or(0)
}

/// Traefik JSON line -> Req.
fn parse_json(line: &str) -> Option<Req> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if !v.is_object() {
        return None;
    }
    let mut ip = json_str(&v, "ClientHost");
    if ip.is_empty() {
        // ClientAddr carries "ip:port"
        ip = json_str(&v, "ClientAddr")
            .rsplit_once(':')
            .map(|(a, _)| a.to_string())
            .unwrap_or_default();
    }
    let ip = valid_ip(ip.trim_matches(['[', ']']))?;
    // Duration is nanoseconds in Traefik's JSON output
    let dur_ns = v
        .get("Duration")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0)
        .max(0.0);
    Some(Req {
        ip,
        method: json_str(&v, "RequestMethod"),
        host: json_str(&v, "RequestHost"),
        path: json_str(&v, "RequestPath"),
        status: json_u64(&v, "DownstreamStatus").min(u16::MAX as u64) as u16,
        bytes: json_u64(&v, "DownstreamContentSize"),
        ua: {
            let u = json_str(&v, "request_User-Agent");
            if u.is_empty() {
                json_str(&v, "RequestUserAgent")
            } else {
                u
            }
        },
        duration_ms: dur_ns / 1.0e6,
    })
}

/// Split a CLF line into its bare fields and its quoted fields, in order.
fn clf_fields(line: &str) -> (Vec<String>, Vec<String>) {
    let (mut bare, mut quoted) = (Vec::new(), Vec::new());
    let mut cur = String::new();
    let mut in_q = false;
    let mut in_b = false;
    for c in line.chars() {
        match c {
            '"' => {
                if in_q {
                    quoted.push(std::mem::take(&mut cur));
                    in_q = false;
                } else {
                    in_q = true;
                    cur.clear();
                }
            }
            '[' if !in_q => in_b = true,
            ']' if !in_q => in_b = false,
            ' ' if !in_q && !in_b => {
                if !cur.is_empty() {
                    bare.push(std::mem::take(&mut cur));
                }
            }
            _ => {
                if !in_b || in_q {
                    cur.push(c)
                }
            }
        }
    }
    if !cur.is_empty() && !in_q {
        bare.push(cur);
    }
    (bare, quoted)
}

/// Traefik extended CLF:
/// `host - user [time] "METHOD path proto" status size "referer" "ua" n "router" "url" durationms`
fn parse_clf(line: &str) -> Option<Req> {
    let (bare, quoted) = clf_fields(line);
    if bare.is_empty() || quoted.is_empty() {
        return None;
    }
    let ip = valid_ip(&bare[0])?;
    let reqline: Vec<&str> = quoted[0].split_whitespace().collect();
    // bare after the address: "-", user, status, size, count, duration
    let nums: Vec<&String> = bare.iter().skip(1).filter(|s| s.as_str() != "-").collect();
    let status = nums
        .iter()
        .find_map(|s| s.parse::<u16>().ok().filter(|n| (100..=599).contains(n)))
        .unwrap_or(0);
    let size = nums
        .iter()
        .filter_map(|s| s.parse::<u64>().ok())
        .find(|n| *n != status as u64)
        .unwrap_or(0);
    let duration_ms = bare
        .last()
        .and_then(|s| s.trim_end_matches("ms").parse::<f64>().ok())
        .filter(|_| bare.last().map(|s| s.ends_with("ms")).unwrap_or(false))
        .unwrap_or(0.0);
    Some(Req {
        ip,
        method: reqline.first().unwrap_or(&"").to_string(),
        host: String::new(), // CLF puts the host in the router field, not reliably
        path: reqline.get(1).unwrap_or(&"/").to_string(),
        status,
        bytes: size,
        // Traefik CLF quotes the request line, then the referer, then the
        // user-agent: "METHOD path proto" "referer" "user-agent"
        ua: quoted.get(2).cloned().unwrap_or_default(),
        duration_ms,
    })
}

pub fn parse_line(line: &str) -> Option<Req> {
    let l = line.trim();
    if l.is_empty() {
        return None;
    }
    if l.starts_with('{') {
        parse_json(l)
    } else {
        parse_clf(l)
    }
}

/// Stateful tail reader. One instance lives in the shield engine.
pub struct Tailer {
    pub path: String,
    offset: u64,
    inode: u64,
    /// Total lines the reader could not parse — surfaced so a format mismatch
    /// is visible instead of silently reading as "no traffic".
    pub unparsed: u64,
    pub parsed: u64,
    pub present: bool,
}

#[cfg(unix)]
fn inode_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}
#[cfg(not(unix))]
fn inode_of(_m: &std::fs::Metadata) -> u64 {
    0
}

impl Tailer {
    pub fn new(path: &str) -> Self {
        Tailer {
            path: path.to_string(),
            offset: 0,
            inode: 0,
            unparsed: 0,
            parsed: 0,
            present: false,
        }
    }

    /// Start at the END of an existing log so the first tick does not ingest
    /// hours of history as if it had all arrived in the last five seconds.
    pub fn seek_to_end(&mut self) {
        if let Ok(m) = std::fs::metadata(&self.path) {
            self.inode = inode_of(&m);
            self.offset = m.len();
            self.present = true;
        }
    }

    /// Read everything appended since the last call.
    pub fn read_new(&mut self) -> Vec<Req> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => {
                self.present = false;
                return Vec::new();
            }
        };
        self.present = true;
        let ino = inode_of(&meta);
        let size = meta.len();
        if ino != self.inode || size < self.offset {
            // rotated or truncated — resume from the start of the new file
            self.inode = ino;
            self.offset = 0;
        }
        if size == self.offset {
            return Vec::new();
        }
        let start = if size - self.offset > MAX_TICK_BYTES {
            // fell far behind: skip to the tail of the window rather than stall
            size - MAX_TICK_BYTES
        } else {
            self.offset
        };
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        if f.seek(SeekFrom::Start(start)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let mut reader = BufReader::new(&mut f).take(MAX_TICK_BYTES);
        if reader.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        // stop at the last newline so a half-written line is re-read next tick
        let end = match buf.iter().rposition(|b| *b == b'\n') {
            Some(i) => i + 1,
            None => return Vec::new(),
        };
        self.offset = start + end as u64;
        let mut out = Vec::new();
        for line in BufReader::new(&buf[..end]).lines().map_while(Result::ok) {
            match parse_line(&line) {
                Some(r) => {
                    self.parsed += 1;
                    out.push(r);
                }
                None => self.unparsed += 1,
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_traefik_json() {
        let l = r#"{"ClientHost":"203.0.113.7","RequestMethod":"GET","RequestHost":"api.example.com","RequestPath":"/api/search?q=1","DownstreamStatus":200,"DownstreamContentSize":512,"Duration":12000000,"request_User-Agent":"curl/8.0"}"#;
        let r = parse_line(l).expect("should parse");
        assert_eq!(r.ip, "203.0.113.7");
        assert_eq!(r.method, "GET");
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.status, 200);
        assert_eq!(r.bytes, 512);
        assert_eq!(r.ua, "curl/8.0");
        assert!((r.duration_ms - 12.0).abs() < 1e-6);
        assert_eq!(r.endpoint(), "/api/search");
    }

    #[test]
    fn parses_client_addr_with_port() {
        let l = r#"{"ClientAddr":"198.51.100.4:53422","RequestPath":"/","DownstreamStatus":204}"#;
        assert_eq!(parse_line(l).unwrap().ip, "198.51.100.4");
    }

    #[test]
    fn parses_extended_clf() {
        let l = r#"192.0.2.9 - - [29/Aug/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 27 "-" "Mozilla/5.0" 4 "web@docker" "http://172.18.0.5:80" 31ms"#;
        let r = parse_line(l).expect("should parse");
        assert_eq!(r.ip, "192.0.2.9");
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/login");
        assert_eq!(r.status, 401);
        assert_eq!(r.ua, "Mozilla/5.0");
        assert!((r.duration_ms - 31.0).abs() < 1e-6);
    }

    #[test]
    fn rejects_junk_without_panicking() {
        assert!(parse_line("").is_none());
        assert!(parse_line("not a log line at all").is_none());
        assert!(parse_line("{broken json").is_none());
        assert!(parse_line(r#"{"ClientHost":"not-an-ip","RequestPath":"/"}"#).is_none());
    }

    #[test]
    fn endpoint_strips_query_but_keeps_the_resource_distinct() {
        let mk = |p: &str| Req {
            path: p.into(),
            ..Default::default()
        };
        // query stripped, but distinct resources stay distinct — a crowd
        // reading different articles must not look like one endpoint
        assert_eq!(mk("/api/search?q=cat").endpoint(), "/api/search");
        assert_eq!(mk("/api/search?q=dog").endpoint(), "/api/search");
        assert_ne!(mk("/article/1").endpoint(), mk("/article/2").endpoint());
        assert_eq!(mk("/").endpoint(), "/");
        assert_eq!(mk("").endpoint(), "/");
    }

    #[test]
    fn template_folds_ids_for_display_grouping() {
        let mk = |p: &str| Req {
            path: p.into(),
            ..Default::default()
        };
        assert_eq!(mk("/api/user/8412").template(), "/api/user/:id");
        assert_eq!(mk("/api/user/9930").template(), "/api/user/:id");
        assert_eq!(
            mk("/v1/o/550e8400e29b41d4a716446655440000").template(),
            "/v1/o/:id"
        );
    }

    #[test]
    fn tailer_reads_only_new_bytes_and_survives_rotation() {
        let dir = std::env::temp_dir().join(format!("nimbusa-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("access.log");
        let line = |ip: &str| {
            format!(
                "{{\"ClientHost\":\"{}\",\"RequestPath\":\"/x\",\"DownstreamStatus\":200}}\n",
                ip
            )
        };
        std::fs::write(&p, line("1.1.1.1")).unwrap();
        let mut t = Tailer::new(p.to_str().unwrap());
        assert_eq!(t.read_new().len(), 1);
        assert_eq!(t.read_new().len(), 0, "second read must see nothing new");

        std::fs::write(&p, format!("{}{}", line("1.1.1.1"), line("2.2.2.2"))).unwrap();
        let got = t.read_new();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, "2.2.2.2");

        // truncation (log rotated in place) must reset rather than read garbage
        std::fs::write(&p, line("3.3.3.3")).unwrap();
        let got = t.read_new();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, "3.3.3.3");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tailer_on_missing_file_is_silent() {
        let mut t = Tailer::new("/nonexistent/nimbusa/access.log");
        assert!(t.read_new().is_empty());
        assert!(!t.present);
    }

    #[test]
    fn partial_last_line_is_deferred() {
        let dir = std::env::temp_dir().join(format!("nimbusa-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.log");
        std::fs::write(
            &p,
            "{\"ClientHost\":\"9.9.9.9\",\"RequestPath\":\"/\"}\n{\"ClientHost\":\"8.8.8",
        )
        .unwrap();
        let mut t = Tailer::new(p.to_str().unwrap());
        assert_eq!(t.read_new().len(), 1);
        std::fs::write(
            &p,
            "{\"ClientHost\":\"9.9.9.9\",\"RequestPath\":\"/\"}\n{\"ClientHost\":\"8.8.8.8\",\"RequestPath\":\"/\"}\n",
        )
        .unwrap();
        let got = t.read_new();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, "8.8.8.8");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
