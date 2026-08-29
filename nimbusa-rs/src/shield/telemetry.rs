//! NIMBUSA SHIELD — traffic telemetry engine.
//!
//! Everything on this path is a `/proc` read, never a subprocess: the engine
//! ticks every few seconds and must cost effectively nothing. Kernel counters
//! are cumulative, so each collector keeps the previous reading and reports the
//! delta as a rate.
//!
//! Sources
//!   /proc/net/dev      per-interface rx/tx bytes and packets
//!   /proc/net/snmp     TCP PassiveOpens (connection creation), CurrEstab, AttemptFails
//!   /proc/net/sockstat socket pressure (inuse / tw / orphan)
//!   /proc/net/tcp[6]   live connections with their remote address and state
use crate::util::{epoch, is_private};
use std::collections::HashMap;
use std::fs;

/// A raw cumulative reading of the kernel counters.
#[derive(Clone, Debug, Default)]
pub struct RawCounters {
    pub t: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Sum over docker bridge interfaces (docker0, br-*) — internal cloud traffic.
    pub br_rx_bytes: u64,
    pub br_tx_bytes: u64,
    pub passive_opens: u64,
    pub active_opens: u64,
    pub attempt_fails: u64,
    pub curr_estab: u64,
}

/// One derived telemetry sample: rates, not totals.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // full telemetry surface; some fields consumed only by future signals
pub struct Sample {
    pub t: u64,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    /// Docker bridge throughput, bits/sec (internal cloud traffic).
    pub internal_bps: f64,
    /// Accepted inbound connections per second (TCP PassiveOpens delta).
    pub conn_rate: f64,
    /// Failed connection attempts per second (TCP AttemptFails delta).
    pub conn_fail_rate: f64,
    pub established: u32,
    pub syn_recv: u32,
    pub time_wait: u32,
    /// Distinct public remote addresses currently connected.
    pub conn_sources: u32,
    /// Connections whose remote address is inside a private/container range.
    pub internal_conns: u32,
    pub sockets_inuse: u32,
}

fn read(p: &str) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

/// The uplink interface. Cached: the default route does not move during a run,
/// and resolving it is the only fork in this module.
pub fn primary_iface() -> String {
    use std::sync::OnceLock;
    static C: OnceLock<String> = OnceLock::new();
    C.get_or_init(|| {
        let o = crate::util::sh("ip route get 1.1.1.1 2>/dev/null");
        o.split_whitespace()
            .skip_while(|t| *t != "dev")
            .nth(1)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "eth0".into())
    })
    .clone()
}

fn is_docker_bridge(name: &str) -> bool {
    name == "docker0" || name.starts_with("br-")
}

/// Parse /proc/net/dev for the uplink and (separately) the docker bridges.
fn read_net_dev(iface: &str, c: &mut RawCounters) {
    for line in read("/proc/net/dev").lines().skip(2) {
        let (name, rest) = match line.split_once(':') {
            Some((a, b)) => (a.trim(), b),
            None => continue,
        };
        let f: Vec<u64> = rest
            .split_whitespace()
            .map(|x| x.parse().unwrap_or(0))
            .collect();
        if f.len() < 10 {
            continue;
        }
        // columns: rx bytes packets errs drop fifo frame compressed multicast, then tx bytes packets ...
        let (rxb, rxp, txb, txp) = (f[0], f[1], f[8], f[9]);
        if name == iface {
            c.rx_bytes = rxb;
            c.rx_packets = rxp;
            c.tx_bytes = txb;
            c.tx_packets = txp;
        } else if is_docker_bridge(name) {
            c.br_rx_bytes += rxb;
            c.br_tx_bytes += txb;
        }
    }
}

/// /proc/net/snmp is two lines per protocol: a header of field names and a
/// matching line of values, so fields are looked up by name rather than index
/// (the set differs between kernels).
fn read_snmp(c: &mut RawCounters) {
    let s = read("/proc/net/snmp");
    let lines: Vec<&str> = s.lines().collect();
    let mut i = 0;
    while i + 1 < lines.len() {
        if lines[i].starts_with("Tcp:") && !lines[i + 1].starts_with("Tcp:") {
            i += 1;
            continue;
        }
        if lines[i].starts_with("Tcp:") {
            let keys: Vec<&str> = lines[i].split_whitespace().collect();
            let vals: Vec<&str> = lines[i + 1].split_whitespace().collect();
            for (k, v) in keys.iter().zip(vals.iter()) {
                let n = v.parse::<i64>().unwrap_or(0).max(0) as u64;
                match *k {
                    "PassiveOpens" => c.passive_opens = n,
                    "ActiveOpens" => c.active_opens = n,
                    "AttemptFails" => c.attempt_fails = n,
                    "CurrEstab" => c.curr_estab = n,
                    _ => {}
                }
            }
            return;
        }
        i += 1;
    }
}

fn read_sockstat() -> u32 {
    for l in read("/proc/net/sockstat").lines() {
        if let Some(rest) = l.strip_prefix("TCP: inuse ") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Decode the little-endian hex address used by /proc/net/tcp ("0100007F:1F90").
fn hex_ipv4(field: &str) -> Option<String> {
    let addr = field.split(':').next()?;
    if addr.len() != 8 {
        return None;
    }
    let v = u32::from_str_radix(addr, 16).ok()?;
    let b = v.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// Live connection census. Returns state counts plus the per-source connection
/// map, which the detector uses for connection-concentration signals.
#[derive(Default)]
pub struct ConnCensus {
    pub established: u32,
    pub syn_recv: u32,
    pub time_wait: u32,
    pub internal: u32,
    /// remote public IP -> live connection count
    pub by_source: HashMap<String, u32>,
    /// container/private remote IP -> live connection count
    pub internal_by_source: HashMap<String, u32>,
}

pub fn connections() -> ConnCensus {
    let mut c = ConnCensus::default();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let body = read(path);
        for line in body.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let st = f[3];
            match st {
                "01" => c.established += 1,
                "03" => c.syn_recv += 1,
                "06" => c.time_wait += 1,
                "0A" => continue, // LISTEN sockets have no peer
                _ => {}
            }
            // only IPv4 remotes are resolvable to a source key here; v6 still
            // counts toward the state totals above
            if let Some(ip) = hex_ipv4(f[2]) {
                if ip == "0.0.0.0" {
                    continue;
                }
                if is_private(&ip) {
                    c.internal += 1;
                    *c.internal_by_source.entry(ip).or_insert(0) += 1;
                } else {
                    *c.by_source.entry(ip).or_insert(0) += 1;
                }
            }
        }
    }
    c
}

pub fn raw() -> RawCounters {
    let mut c = RawCounters {
        t: epoch(),
        ..Default::default()
    };
    read_net_dev(&primary_iface(), &mut c);
    read_snmp(&mut c);
    c
}

/// Counter deltas are only meaningful when they go up: a reboot, an interface
/// reset or a 32-bit counter wrap makes them go down, and reporting a negative
/// rate as a huge positive one would fake an attack. Those samples read as 0.
fn rate(now: u64, prev: u64, dt: f64) -> f64 {
    if now < prev || dt <= 0.0 {
        return 0.0;
    }
    (now - prev) as f64 / dt
}

/// Turn two consecutive raw readings plus a connection census into a Sample.
pub fn derive(prev: &RawCounters, now: &RawCounters, cc: &ConnCensus, inuse: u32) -> Sample {
    let dt = (now.t.saturating_sub(prev.t)) as f64;
    Sample {
        t: now.t,
        rx_bps: rate(now.rx_bytes, prev.rx_bytes, dt) * 8.0,
        tx_bps: rate(now.tx_bytes, prev.tx_bytes, dt) * 8.0,
        rx_pps: rate(now.rx_packets, prev.rx_packets, dt),
        tx_pps: rate(now.tx_packets, prev.tx_packets, dt),
        internal_bps: (rate(now.br_rx_bytes, prev.br_rx_bytes, dt)
            + rate(now.br_tx_bytes, prev.br_tx_bytes, dt))
            * 8.0,
        conn_rate: rate(now.passive_opens, prev.passive_opens, dt),
        conn_fail_rate: rate(now.attempt_fails, prev.attempt_fails, dt),
        established: cc.established,
        syn_recv: cc.syn_recv,
        time_wait: cc.time_wait,
        conn_sources: cc.by_source.len() as u32,
        internal_conns: cc.internal,
        sockets_inuse: inuse,
    }
}

/// One full tick: read the counters, census the connections, derive a sample.
pub fn tick(prev: &RawCounters) -> (RawCounters, Sample, ConnCensus) {
    let now = raw();
    let cc = connections();
    let inuse = read_sockstat();
    let s = derive(prev, &now, &cc, inuse);
    (now, s, cc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_proc_net_tcp_address() {
        assert_eq!(hex_ipv4("0100007F:1F90").as_deref(), Some("127.0.0.1"));
        assert_eq!(hex_ipv4("0F02000A:0050").as_deref(), Some("10.0.2.15"));
        assert_eq!(hex_ipv4("short:0050"), None);
    }

    #[test]
    fn rates_are_per_second() {
        let prev = RawCounters {
            t: 100,
            rx_bytes: 1_000,
            passive_opens: 10,
            ..Default::default()
        };
        let now = RawCounters {
            t: 110,
            rx_bytes: 11_000,
            passive_opens: 110,
            ..Default::default()
        };
        let s = derive(&prev, &now, &ConnCensus::default(), 0);
        assert_eq!(s.rx_bps, 1_000.0 * 8.0); // 10 kB over 10 s = 1 kB/s = 8 kbps
        assert_eq!(s.conn_rate, 10.0);
    }

    #[test]
    fn counter_reset_reads_as_zero_not_as_a_spike() {
        let prev = RawCounters {
            t: 100,
            rx_bytes: 5_000_000,
            ..Default::default()
        };
        let now = RawCounters {
            t: 105,
            rx_bytes: 12,
            ..Default::default()
        };
        assert_eq!(derive(&prev, &now, &ConnCensus::default(), 0).rx_bps, 0.0);
    }

    #[test]
    fn zero_interval_does_not_divide_by_zero() {
        let c = RawCounters {
            t: 100,
            rx_bytes: 10,
            ..Default::default()
        };
        let s = derive(&c, &c, &ConnCensus::default(), 0);
        assert!(s.rx_bps.is_finite() && s.rx_bps == 0.0);
    }

    #[test]
    fn bridge_interfaces_are_recognised() {
        assert!(is_docker_bridge("docker0"));
        assert!(is_docker_bridge("br-1a2b3c"));
        assert!(!is_docker_bridge("eth0"));
        assert!(!is_docker_bridge("vethabc"));
    }
}
