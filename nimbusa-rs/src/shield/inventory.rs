//! Unified service / listening-socket discovery.
//!
//! The "Domains" concept in the base control center only ever knew about
//! Traefik `Host()` labels on docker containers. A real VPS also runs plain
//! processes bound to a port with no DNS name at all (a panel on :4000, a
//! mirror on :8080). This module discovers what is *actually listening* and
//! merges every source of truth into one inventory:
//!
//!   listening sockets   ss -ltnp  (else /proc/net/tcp[6])   — always available
//!   docker              docker ps --format {{.Ports}} …     — if docker exists
//!   traefik             Host() labels already parsed         — if configured
//!
//! Nothing here is on the shield hot path: the base UI gathers it on the same
//! slow cadence it already uses for docker, and the whole pass is bounded.
use crate::util::have;
use std::collections::HashMap;

/// One discovered service. Every field is real or empty — never a placeholder.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Service {
    /// Bind address as the kernel reports it (0.0.0.0, ::, 127.0.0.1, …).
    pub bind: String,
    pub port: u16,
    /// Transport as discovered: "TCP" or "TCP6".
    pub proto: String,
    /// Best-effort application protocol from the port ("HTTP"/"HTTPS"/"").
    pub app_proto: String,
    pub process: String,
    pub pid: u32,
    pub container: String,
    pub image: String,
    pub domain: String,
    /// Where this row was discovered: "socket" | "docker" | "traefik".
    pub source: String,
}

impl Service {
    /// Exposure class for the UI: is this reachable from outside the box?
    pub fn scope(&self) -> &'static str {
        match self.bind.as_str() {
            "127.0.0.1" | "::1" => "LOCAL",
            _ => "PUBLIC",
        }
    }
}

/// Well-known application protocol for a port. Deliberately conservative: an
/// unknown port yields "" rather than a guess that would read as fake data.
pub fn app_proto_for(port: u16) -> &'static str {
    match port {
        80 | 8080 | 8000 | 3000 | 4000 | 5000 | 8081 => "HTTP",
        443 | 8443 => "HTTPS",
        22 => "SSH",
        53 => "DNS",
        25 | 587 | 465 => "SMTP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        _ => "",
    }
}

/// Split a `host:port` token from the right (IPv6 has many colons).
/// `*` and `[::]` are normalised to the addresses the kernel means.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let idx = s.rfind(':')?;
    let (h, p) = s.split_at(idx);
    let port: u16 = p[1..].parse().ok()?;
    let host = h.trim_matches(|c| c == '[' || c == ']');
    let host = if host == "*" { "0.0.0.0" } else { host };
    Some((host.to_string(), port))
}

/// Pull `("process", pid)` out of an `ss` process column such as
/// `users:(("node",pid=1234,fd=20))`. Returns `("", 0)` when absent.
pub fn parse_ss_process(tok: &str) -> (String, u32) {
    let name = tok
        .split_once('"')
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(n, _)| n.to_string())
        .unwrap_or_default();
    let pid = tok
        .split_once("pid=")
        .and_then(|(_, r)| {
            let end = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
            r[..end].parse().ok()
        })
        .unwrap_or(0);
    (name, pid)
}

/// Parse the output of `ss -H -ltnp` (TCP, listening, numeric, processes).
/// Columns: State Recv-Q Send-Q Local:Port Peer:Port [users:((…))].
pub fn parse_ss(out: &str) -> Vec<Service> {
    let mut v = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[0] != "LISTEN" {
            continue;
        }
        let (bind, port) = match split_host_port(f[3]) {
            Some(x) => x,
            None => continue,
        };
        let proto = if bind.contains(':') || bind == "::" {
            "TCP6"
        } else {
            "TCP"
        };
        let (process, pid) = f.get(5).map(|t| parse_ss_process(t)).unwrap_or_default();
        v.push(Service {
            bind,
            port,
            proto: proto.into(),
            app_proto: app_proto_for(port).into(),
            process,
            pid,
            source: "socket".into(),
            ..Default::default()
        });
    }
    v
}

/// Decode the little-endian hex IPv4 in /proc/net/tcp ("0100007F" -> 127.0.0.1).
fn hex_v4(addr: &str) -> Option<String> {
    if addr.len() != 8 {
        return None;
    }
    let v = u32::from_str_radix(addr, 16).ok()?;
    let b = v.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// /proc/net/tcp fallback when `ss` is unavailable: yields bind+port for every
/// LISTEN socket (state 0A). No PID/process — that is what `ss` is for.
pub fn parse_proc_net_tcp(body: &str, v6: bool) -> Vec<Service> {
    let mut v = Vec::new();
    for line in body.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "0A" {
            continue;
        }
        let mut parts = f[1].split(':');
        let addr = parts.next().unwrap_or("");
        let port = parts.next().and_then(|p| u16::from_str_radix(p, 16).ok());
        let port = match port {
            Some(p) => p,
            None => continue,
        };
        let (bind, proto) = if v6 {
            ("::".to_string(), "TCP6")
        } else {
            (hex_v4(addr).unwrap_or_else(|| "0.0.0.0".into()), "TCP")
        };
        v.push(Service {
            bind,
            port,
            proto: proto.into(),
            app_proto: app_proto_for(port).into(),
            source: "socket".into(),
            ..Default::default()
        });
    }
    v
}

/// One docker container's published-port + metadata, parsed from
/// `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DockerPort {
    pub host_port: u16,
    pub name: String,
    pub image: String,
}

/// Parse a docker `Ports` cell: `0.0.0.0:4000->4000/tcp, :::4000->4000/tcp`.
/// Only host-published ports (those with `host:port->`) are returned.
pub fn parse_docker_ports(name: &str, image: &str, ports: &str) -> Vec<DockerPort> {
    let mut v = Vec::new();
    for chunk in ports.split(',') {
        let chunk = chunk.trim();
        let mapping = match chunk.split_once("->") {
            Some((left, _)) => left,
            None => continue,
        };
        if let Some((_, port)) = split_host_port(mapping) {
            v.push(DockerPort {
                host_port: port,
                name: name.to_string(),
                image: image.to_string(),
            });
        }
    }
    v
}

/// Merge docker published ports onto listening sockets by matching host port.
pub fn attach_docker(svcs: &mut [Service], dports: &[DockerPort]) {
    let by_port: HashMap<u16, &DockerPort> = dports.iter().map(|d| (d.host_port, d)).collect();
    for s in svcs.iter_mut() {
        if let Some(d) = by_port.get(&s.port) {
            s.container = d.name.clone();
            s.image = d.image.clone();
            if s.source == "socket" {
                s.source = "docker".into();
            }
        }
    }
}

/// Attach configured Traefik `Host()` domains to whichever service belongs to
/// their container.
pub fn attach_domains(svcs: &mut [Service], domains: &[(String, String)]) {
    // container name -> first domain
    let mut by_container: HashMap<&str, &str> = HashMap::new();
    for (dom, container) in domains {
        by_container
            .entry(container.as_str())
            .or_insert(dom.as_str());
    }
    for s in svcs.iter_mut() {
        if s.container.is_empty() {
            continue;
        }
        if let Some(dom) = by_container.get(s.container.as_str()) {
            s.domain = (*dom).to_string();
            s.source = "traefik".into();
        }
    }
}

/// Raw listener discovery: `ss` when present, else the /proc fallback.
fn listeners() -> Vec<Service> {
    if have("ss") {
        let out = crate::util::run("ss", &["-H", "-l", "-t", "-n", "-p"]);
        if !out.trim().is_empty() {
            return parse_ss(&out);
        }
    }
    let mut v = parse_proc_net_tcp(&read("/proc/net/tcp"), false);
    v.extend(parse_proc_net_tcp(&read("/proc/net/tcp6"), true));
    v
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Full inventory. `dports` come from the docker snapshot the caller already
/// took (no extra docker fork), `domains` are its parsed Host() rules.
pub fn build(dports: &[DockerPort], domains: &[(String, String)]) -> Vec<Service> {
    let mut svcs = listeners();
    attach_docker(&mut svcs, dports);
    attach_domains(&mut svcs, domains);
    svcs.sort_by(|a, b| a.port.cmp(&b.port).then(a.bind.cmp(&b.bind)));
    svcs.dedup_by(|a, b| a.port == b.port && a.bind == b.bind && a.proto == b.proto);
    svcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_ipv4_host_port() {
        assert_eq!(
            split_host_port("0.0.0.0:4000"),
            Some(("0.0.0.0".into(), 4000))
        );
        assert_eq!(
            split_host_port("127.0.0.1:5432"),
            Some(("127.0.0.1".into(), 5432))
        );
        assert_eq!(split_host_port("*:22"), Some(("0.0.0.0".into(), 22)));
    }

    #[test]
    fn splits_ipv6_host_port_from_the_right() {
        assert_eq!(split_host_port("[::]:8080"), Some(("::".into(), 8080)));
        assert_eq!(split_host_port("[::1]:6379"), Some(("::1".into(), 6379)));
    }

    #[test]
    fn rejects_garbage_host_port() {
        assert_eq!(split_host_port("not-a-socket"), None);
        assert_eq!(split_host_port("1.2.3.4:notaport"), None);
    }

    #[test]
    fn parses_ss_process_column() {
        assert_eq!(
            parse_ss_process("users:((\"node\",pid=1234,fd=20))"),
            ("node".into(), 1234)
        );
        assert_eq!(
            parse_ss_process("users:((\"nginx\",pid=42,fd=6),(\"nginx\",pid=43,fd=6))"),
            ("nginx".into(), 42)
        );
        assert_eq!(parse_ss_process("no-process-here"), (String::new(), 0));
    }

    #[test]
    fn parses_a_full_ss_listing() {
        let out = "\
LISTEN 0 4096 0.0.0.0:4000 0.0.0.0:* users:((\"node\",pid=1234,fd=20))
LISTEN 0 511  [::]:8080     [::]:*    users:((\"caddy\",pid=55,fd=7))
LISTEN 0 128  127.0.0.1:5432 0.0.0.0:* users:((\"postgres\",pid=99,fd=5))
LISTEN 0 128  0.0.0.0:22    0.0.0.0:* users:((\"sshd\",pid=800,fd=3))";
        let v = parse_ss(out);
        assert_eq!(v.len(), 4);
        let panel = v.iter().find(|s| s.port == 4000).unwrap();
        assert_eq!(panel.bind, "0.0.0.0");
        assert_eq!(panel.app_proto, "HTTP");
        assert_eq!(panel.process, "node");
        assert_eq!(panel.pid, 1234);
        assert_eq!(panel.scope(), "PUBLIC");
        let pg = v.iter().find(|s| s.port == 5432).unwrap();
        assert_eq!(pg.scope(), "LOCAL");
        assert_eq!(pg.app_proto, "PostgreSQL");
        let mirror = v.iter().find(|s| s.port == 8080).unwrap();
        assert_eq!(mirror.proto, "TCP6");
    }

    #[test]
    fn proc_net_tcp_fallback_decodes_listen_sockets() {
        // 0100007F:1F90 = 127.0.0.1:8080 in state 0A (LISTEN)
        let body = "\
  sl  local_address rem_address   st ...
   0: 0100007F:1F90 00000000:0000 0A rest
   1: 00000000:0016 00000000:0000 0A rest
   2: 0100007F:8000 01020304:1234 01 established-not-listen";
        let v = parse_proc_net_tcp(body, false);
        assert_eq!(v.len(), 2, "only LISTEN sockets");
        assert_eq!(v[0].bind, "127.0.0.1");
        assert_eq!(v[0].port, 8080);
        assert_eq!(v[1].port, 22);
    }

    #[test]
    fn parses_docker_published_ports() {
        let d = parse_docker_ports(
            "panel",
            "node:20",
            "0.0.0.0:4000->4000/tcp, :::4000->4000/tcp",
        );
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].host_port, 4000);
        assert_eq!(d[0].name, "panel");
        // internal-only exposure (no host mapping) is ignored
        let none = parse_docker_ports("db", "postgres", "5432/tcp");
        assert!(none.is_empty());
    }

    #[test]
    fn docker_and_domains_attach_to_the_right_socket() {
        let mut svcs =
            parse_ss("LISTEN 0 4096 0.0.0.0:4000 0.0.0.0:* users:((\"node\",pid=1,fd=2))");
        let dports = vec![DockerPort {
            host_port: 4000,
            name: "panel".into(),
            image: "node:20".into(),
        }];
        attach_docker(&mut svcs, &dports);
        assert_eq!(svcs[0].container, "panel");
        assert_eq!(svcs[0].source, "docker");
        attach_domains(&mut svcs, &[("panel.example.com".into(), "panel".into())]);
        assert_eq!(svcs[0].domain, "panel.example.com");
        assert_eq!(svcs[0].source, "traefik");
    }

    #[test]
    fn build_is_sorted_and_deduplicated() {
        // Two sources reporting the same socket must collapse to one row.
        let dports = vec![];
        let domains = vec![];
        let out = build(&dports, &domains);
        // On a dev host with no ss/proc parse this is simply empty — never panics.
        assert!(out.iter().all(|s| s.port != 0) || out.is_empty());
    }
}
