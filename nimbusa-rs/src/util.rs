//! Shell/exec helpers, formatting, validation, time.
//!
//! SAFETY: `sh()` runs a *fixed, literal* command string and must never be fed
//! caller-controlled data. Anything that carries an IP, username, container name
//! or other outside value goes through `run()`, which passes argv directly to
//! execve and therefore has no shell metacharacter surface at all.
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// Run a literal command through `sh -c`. Call sites must contain no interpolation.
pub fn sh(cmd: &str) -> String {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
        .unwrap_or_default()
}

/// Run a program with an explicit argv. No shell, no interpolation. Preferred.
pub fn run(prog: &str, args: &[&str]) -> String {
    Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
        .unwrap_or_default()
}

/// Like `run`, but merges stderr and reports the exit status.
pub fn run_status(prog: &str, args: &[&str]) -> (bool, String) {
    match Command::new(prog).args(args).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).trim_end().to_string();
            let e = String::from_utf8_lossy(&o.stderr).trim_end().to_string();
            if !e.is_empty() {
                if !s.is_empty() {
                    s.push('\n');
                }
                s.push_str(&e);
            }
            (o.status.success(), s)
        }
        Err(e) => (false, format!("{}: {}", prog, e)),
    }
}

/// Is `prog` on PATH? Cached — probing costs a fork, and the answer never changes
/// within one run.
pub fn have(prog: &str) -> bool {
    static C: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = c.lock().unwrap().get(prog) {
        return *v;
    }
    // sanitised on the way in: only a bare program name can reach the shell
    let safe: String = prog
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let v = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {} >/dev/null 2>&1", safe))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    c.lock().unwrap().insert(prog.to_string(), v);
    v
}

pub fn human(n: f64) -> String {
    let mut n = n;
    for u in ["B", "K", "M", "G", "T"] {
        if n < 1024.0 {
            return if u == "B" {
                format!("{:.0}{}", n, u)
            } else {
                format!("{:.1}{}", n, u)
            };
        }
        n /= 1024.0;
    }
    format!("{:.1}P", n)
}

/// bits/sec -> human readable (network convention: decimal multiples).
pub fn human_bps(bps: f64) -> String {
    let mut v = bps;
    for u in ["bps", "Kbps", "Mbps", "Gbps"] {
        if v < 1000.0 {
            return format!("{:.1} {}", v, u);
        }
        v /= 1000.0;
    }
    format!("{:.1} Tbps", v)
}

pub fn now_str() -> String {
    sh("date '+%Y-%m-%d %H:%M:%S'")
}

/// Seconds since the unix epoch (portable, no libc dependency).
pub fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn dur_str(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

// IST = +05:30. Minutes to add to a SERVER-local time to get IST.
pub fn ist_delta_min() -> i64 {
    let z = sh("date +%z");
    let sign = if z.starts_with('-') { -1 } else { 1 };
    let d: String = z.chars().filter(|c| c.is_ascii_digit()).collect();
    let off = if d.len() >= 4 {
        sign * (d[0..2].parse::<i64>().unwrap_or(0) * 60 + d[2..4].parse::<i64>().unwrap_or(0))
    } else {
        0
    };
    330 - off
}

pub fn ist_of_hm(h: i64, m: i64, delta: i64) -> String {
    let t = (h * 60 + m + delta).rem_euclid(1440);
    format!("{:02}:{:02}", t / 60, t % 60)
}

/// Find the first HH:MM[:SS] token in a line and append "  (HH:MM IST)".
pub fn with_ist(line: &str, delta: i64) -> String {
    for tok in line.split_whitespace() {
        let p: Vec<&str> = tok.split(':').collect();
        if p.len() >= 2 && p[0].len() <= 2 && !p[0].is_empty() {
            if let (Ok(h), Ok(m)) = (p[0].parse::<i64>(), p[1].parse::<i64>()) {
                if h < 24 && m < 60 {
                    return format!("{}  ({} IST)", line, ist_of_hm(h, m, delta));
                }
            }
        }
    }
    line.to_string()
}

// ------------------------------------------------------------------ validation
pub fn valid_ip(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
    {
        Some(s.to_string())
    } else {
        None
    }
}

/// IPv4 address or CIDR, e.g. "10.0.0.0/24". Checked before ANY firewall action.
pub fn valid_ip_or_cidr(s: &str) -> bool {
    let (ip, mask) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    if valid_ip(ip).is_none() {
        return false;
    }
    match mask {
        None => true,
        Some(m) => m.parse::<u8>().map(|n| n <= 32).unwrap_or(false),
    }
}

/// Hostnames accepted by the firewall helper (resolved there, never shell-expanded).
pub fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('-')
        && !s.starts_with('.')
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

pub fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.chars()
            .next()
            .map(|c| c.is_ascii_lowercase())
            .unwrap_or(false)
        && u.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

pub fn find_ip(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut dots = 0;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots == 3 {
                if let Some(ip) = valid_ip(&s[start..j]) {
                    return Some(ip);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

pub fn is_private(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip
            .strip_prefix("172.")
            .and_then(|r| r.split('.').next())
            .and_then(|o| o.parse::<u8>().ok())
            .map(|n| (16..=31).contains(&n))
            .unwrap_or(false)
}

/// /24 network key — the cheap stand-in for an ASN when no ASN database exists.
pub fn slash24(ip: &str) -> String {
    let p: Vec<&str> = ip.split('.').collect();
    if p.len() == 4 {
        format!("{}.{}.{}.0/24", p[0], p[1], p[2])
    } else {
        ip.to_string()
    }
}

pub fn ts_of(line: &str) -> String {
    if line.len() >= 19 && line.as_bytes()[4] == b'-' {
        return line[..19].replace('T', " ");
    }
    line.split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn user_of(line: &str) -> Option<String> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    for (i, t) in toks.iter().enumerate() {
        if (*t == "user" || *t == "Invalid") && i + 1 < toks.len() {
            let u = toks[i + 1].trim_matches(|c: char| {
                !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-'
            });
            if !u.is_empty() && u != "user" {
                return Some(u.to_string());
            }
        }
    }
    None
}

// ------------------------------------------------------------------ geo
fn geo_cache() -> &'static Mutex<HashMap<String, String>> {
    static C: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn geo(ip: &str) -> String {
    if valid_ip(ip).is_none() {
        return "?".into();
    }
    if let Some(c) = geo_cache().lock().unwrap().get(ip) {
        return c.clone();
    }
    let out = if have("geoiplookup") {
        run("geoiplookup", &[ip])
    } else {
        String::new()
    };
    let c = out
        .split("Country Edition:")
        .nth(1)
        .and_then(|s| s.split(',').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "?".into());
    geo_cache()
        .lock()
        .unwrap()
        .insert(ip.to_string(), c.clone());
    c
}

/// Atomic write: temp file in the same directory, then rename. Never leaves a
/// half-written state file behind if the process dies mid-save.
pub fn write_atomic(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_validation() {
        assert!(valid_ip("192.168.1.1").is_some());
        assert!(valid_ip("256.1.1.1").is_none());
        assert!(valid_ip("1.2.3").is_none());
        assert!(valid_ip("1.2.3.4.5").is_none());
        assert!(valid_ip("").is_none());
    }

    #[test]
    fn cidr_validation() {
        assert!(valid_ip_or_cidr("10.0.0.0/24"));
        assert!(valid_ip_or_cidr("10.0.0.1"));
        assert!(!valid_ip_or_cidr("10.0.0.0/33"));
        assert!(!valid_ip_or_cidr("10.0.0.0/x"));
        // shell metacharacters must never validate
        assert!(!valid_ip_or_cidr("1.2.3.4; rm -rf /"));
        assert!(!valid_ip_or_cidr("$(id)"));
        assert!(!valid_ip_or_cidr("1.2.3.4 && reboot"));
    }

    #[test]
    fn domain_validation() {
        assert!(valid_domain("api.example.com"));
        assert!(!valid_domain("no-dot"));
        assert!(!valid_domain("bad;host.com"));
        assert!(!valid_domain("`id`.com"));
    }

    #[test]
    fn username_validation() {
        assert!(valid_username("alice"));
        assert!(!valid_username("Alice"));
        assert!(!valid_username("alice;rm"));
        assert!(!valid_username(""));
    }

    #[test]
    fn finds_embedded_ip() {
        assert_eq!(
            find_ip("Failed password for root from 1.2.3.4 port 22").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(find_ip("no address here"), None);
    }

    #[test]
    fn private_ranges() {
        assert!(is_private("10.1.2.3"));
        assert!(is_private("172.16.0.1"));
        assert!(!is_private("172.32.0.1"));
        assert!(!is_private("8.8.8.8"));
    }

    #[test]
    fn network_key() {
        assert_eq!(slash24("203.0.113.55"), "203.0.113.0/24");
    }

    #[test]
    fn durations() {
        assert_eq!(dur_str(45), "45s");
        assert_eq!(dur_str(125), "2m 5s");
        assert_eq!(dur_str(7500), "2h 5m");
    }
}
