//! Application health correlation.
//!
//! Health is a *detection signal*, not decoration: high traffic with a healthy
//! application is a traffic surge, the same traffic with a degrading
//! application is an attack. It is also the thing that makes recovery honest —
//! rollback only happens once the services actually answer again, and reported
//! downtime is measured from these probes rather than assumed to be zero.
use crate::config::Config;
use crate::util::{epoch, run, valid_domain};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum State {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Healthy => "HEALTHY",
            State::Degraded => "DEGRADED",
            State::Unavailable => "UNAVAILABLE",
            State::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Kind {
    Domain,
    Container,
    Proxy,
    Firewall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub kind: Kind,
    pub state: State,
    pub http: u16,
    pub latency_ms: u64,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub checks: Vec<Check>,
    pub checked_at: u64,
    /// Seconds of accumulated outage attributed to the current incident.
    pub downtime_secs: u64,
}

#[allow(dead_code)]
impl Report {
    /// Worst state across everything monitored.
    pub fn overall(&self) -> State {
        self.checks
            .iter()
            .filter(|c| c.state != State::Unknown)
            .map(|c| c.state)
            .max()
            .unwrap_or(State::Unknown)
    }
    pub fn unavailable(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.state == State::Unavailable)
            .count()
    }
    pub fn degraded(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.state == State::Degraded)
            .count()
    }
    pub fn get(&self, name: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.name == name)
    }
    /// 0.0 (all down) .. 1.0 (all healthy). Feeds the detection signal.
    pub fn score(&self) -> f64 {
        let live: Vec<&Check> = self
            .checks
            .iter()
            .filter(|c| c.state != State::Unknown)
            .collect();
        if live.is_empty() {
            return 1.0;
        }
        let s: f64 = live
            .iter()
            .map(|c| match c.state {
                State::Healthy => 1.0,
                State::Degraded => 0.5,
                State::Unavailable => 0.0,
                State::Unknown => 1.0,
            })
            .sum();
        s / live.len() as f64
    }
}

/// Probe one HTTPS endpoint. Domain is validated first: it is interpolated into
/// a URL, and an unvalidated one would be an injection point.
pub fn probe_domain(domain: &str, cfg: &Config) -> Check {
    let mut c = Check {
        name: domain.to_string(),
        kind: Kind::Domain,
        state: State::Unknown,
        http: 0,
        latency_ms: 0,
        detail: String::new(),
    };
    if !valid_domain(domain) {
        c.detail = "invalid domain".into();
        return c;
    }
    let timeout = cfg.health_timeout_secs.to_string();
    let out = run(
        "curl",
        &[
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{time_total}",
            "--max-time",
            &timeout,
            "-L",
            &format!("https://{}/", domain),
        ],
    );
    let f: Vec<&str> = out.split_whitespace().collect();
    let code: u16 = f.first().and_then(|x| x.parse().ok()).unwrap_or(0);
    let secs: f64 = f.get(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    c.http = code;
    c.latency_ms = (secs * 1000.0) as u64;
    c.state = classify_http(code, c.latency_ms, cfg);
    c.detail = match c.state {
        State::Unavailable if code == 0 => "no response".into(),
        _ => format!("HTTP {} in {} ms", code, c.latency_ms),
    };
    c
}

pub fn classify_http(code: u16, latency_ms: u64, cfg: &Config) -> State {
    match code {
        0 => State::Unavailable,
        500..=599 => State::Unavailable,
        408 | 429 => State::Degraded,
        _ if latency_ms >= cfg.health_degraded_ms => State::Degraded,
        200..=499 => State::Healthy,
        _ => State::Degraded,
    }
}

/// Container health straight from the `docker ps` status string already
/// collected by the main snapshot — no extra docker round-trip.
pub fn container_check(name: &str, status: &str) -> Check {
    let s = if status.contains("unhealthy") {
        State::Degraded
    } else if status.starts_with("Up") {
        State::Healthy
    } else if status.starts_with("Exited (0)") {
        State::Unknown // deliberately stopped, not an outage
    } else {
        State::Unavailable
    };
    Check {
        name: name.to_string(),
        kind: Kind::Container,
        state: s,
        http: 0,
        latency_ms: 0,
        detail: status.to_string(),
    }
}

/// Is the shield's own enforcement path actually in place? A dashboard that
/// says "IP filtering ACTIVE" while the ipset is missing would be a lie.
pub fn firewall_check() -> Check {
    let sets = run("ipset", &["list", "-n"]);
    let have_set = sets.lines().any(|l| l.trim() == super::mitigate::DDOS_SET);
    let rules = run("iptables", &["-S", "INPUT"]);
    let have_rule = rules.contains(super::mitigate::DDOS_SET);
    let (state, detail) = match (have_set, have_rule) {
        (true, true) => (State::Healthy, "ipset + INPUT rule present".to_string()),
        (true, false) => (
            State::Degraded,
            "ipset present, INPUT rule missing".to_string(),
        ),
        _ => (
            State::Unavailable,
            "shield ipset not installed (run: nimbusa ddos enable)".to_string(),
        ),
    };
    Check {
        name: "firewall".into(),
        kind: Kind::Firewall,
        state,
        http: 0,
        latency_ms: 0,
        detail,
    }
}

/// Build a full report. Domains are probed in parallel so the whole pass costs
/// about one timeout, not one per domain.
pub fn collect(domains: &[String], containers: &[(String, String)], cfg: &Config) -> Report {
    let mut r = Report {
        checked_at: epoch(),
        ..Default::default()
    };
    if !cfg.health_enabled {
        return r;
    }
    // cap the fan-out: a box with 60 domains must not fork 60 curls at once
    let probe: Vec<&String> = domains.iter().take(12).collect();
    std::thread::scope(|s| {
        let handles: Vec<_> = probe
            .iter()
            .map(|d| s.spawn(move || probe_domain(d, cfg)))
            .collect();
        for h in handles {
            if let Ok(c) = h.join() {
                r.checks.push(c);
            }
        }
    });
    for (name, status) in containers {
        r.checks.push(container_check(name, status));
    }
    r.checks.push(firewall_check());
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(name: &str, state: State) -> Check {
        Check {
            name: name.into(),
            kind: Kind::Domain,
            state,
            http: 0,
            latency_ms: 0,
            detail: String::new(),
        }
    }

    #[test]
    fn http_classification() {
        let cfg = Config::default();
        assert_eq!(classify_http(200, 40, &cfg), State::Healthy);
        assert_eq!(classify_http(404, 40, &cfg), State::Healthy); // reachable
        assert_eq!(classify_http(503, 40, &cfg), State::Unavailable);
        assert_eq!(classify_http(0, 0, &cfg), State::Unavailable);
        assert_eq!(classify_http(429, 10, &cfg), State::Degraded);
        assert_eq!(classify_http(200, 9_000, &cfg), State::Degraded);
    }

    #[test]
    fn overall_is_the_worst_state() {
        let r = Report {
            checks: vec![
                c("a", State::Healthy),
                c("b", State::Degraded),
                c("c", State::Healthy),
            ],
            ..Default::default()
        };
        assert_eq!(r.overall(), State::Degraded);
        assert_eq!(r.degraded(), 1);
    }

    #[test]
    fn unknown_checks_do_not_drag_the_score() {
        let r = Report {
            checks: vec![c("a", State::Healthy), c("b", State::Unknown)],
            ..Default::default()
        };
        assert_eq!(r.score(), 1.0);
        assert_eq!(r.overall(), State::Healthy);
    }

    #[test]
    fn score_is_proportional() {
        let r = Report {
            checks: vec![
                c("a", State::Healthy),
                c("b", State::Unavailable),
                c("c", State::Degraded),
                c("d", State::Healthy),
            ],
            ..Default::default()
        };
        assert!((r.score() - (1.0 + 0.0 + 0.5 + 1.0) / 4.0).abs() < 1e-9);
        assert_eq!(r.unavailable(), 1);
    }

    #[test]
    fn empty_report_is_not_an_outage() {
        let r = Report::default();
        assert_eq!(r.score(), 1.0);
        assert_eq!(r.overall(), State::Unknown);
    }

    #[test]
    fn container_states() {
        assert_eq!(container_check("api", "Up 3 hours").state, State::Healthy);
        assert_eq!(
            container_check("api", "Up 3 hours (unhealthy)").state,
            State::Degraded
        );
        assert_eq!(
            container_check("api", "Exited (137) 2 minutes ago").state,
            State::Unavailable
        );
        assert_eq!(
            container_check("api", "Exited (0) 2 days ago").state,
            State::Unknown,
            "a cleanly stopped container is not an outage"
        );
    }

    #[test]
    fn invalid_domain_is_not_probed() {
        let cfg = Config::default();
        let ch = probe_domain("bad;host.com", &cfg);
        assert_eq!(ch.state, State::Unknown);
        assert_eq!(ch.detail, "invalid domain");
    }
}
