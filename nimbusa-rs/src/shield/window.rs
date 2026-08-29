//! Bounded rolling windows over telemetry and requests.
//!
//! Memory is capped in two directions: a window only ever holds
//! `window_seconds` worth of ticks, and each per-tick distribution holds at most
//! a fixed number of distinct keys. Anything past the key cap is folded into a
//! single `OTHER` bucket, so totals stay exact even under a 100k-source flood
//! while the map cannot grow without bound.
use super::accesslog::Req;
use super::telemetry::Sample;
use std::collections::{HashMap, VecDeque};

pub const OTHER: &str = "(other)";

const MAX_IPS: usize = 20_000;
const MAX_ENDPOINTS: usize = 2_000;
const MAX_UAS: usize = 500;
const MAX_HOSTS: usize = 200;
const MAX_NETS: usize = 4_000;

/// A counter map that refuses to grow past `cap`.
#[derive(Clone, Debug, Default)]
pub struct Bounded {
    pub map: HashMap<String, u32>,
    cap: usize,
    /// Distinct keys that were seen but folded into OTHER.
    pub overflowed: u32,
}

#[allow(dead_code)]
impl Bounded {
    pub fn new(cap: usize) -> Self {
        Bounded {
            map: HashMap::new(),
            cap,
            overflowed: 0,
        }
    }
    pub fn add(&mut self, k: &str, n: u32) {
        if let Some(v) = self.map.get_mut(k) {
            *v += n;
            return;
        }
        if self.map.len() >= self.cap {
            *self.map.entry(OTHER.into()).or_insert(0) += n;
            self.overflowed += 1;
            return;
        }
        self.map.insert(k.to_string(), n);
    }
    pub fn total(&self) -> u64 {
        self.map.values().map(|v| *v as u64).sum()
    }
    /// Distinct keys, not counting the overflow bucket, plus the keys it hides.
    pub fn distinct(&self) -> u32 {
        let base = self.map.len() as u32 - self.map.contains_key(OTHER) as u32;
        base + self.overflowed
    }
    pub fn top(&self, n: usize) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self.map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
    /// Share of the total held by the single largest key, ignoring OTHER
    /// (OTHER is by definition many different keys, so it is not concentration).
    pub fn top_share(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            return 0.0;
        }
        let m = self
            .map
            .iter()
            .filter(|(k, _)| k.as_str() != OTHER)
            .map(|(_, v)| *v)
            .max()
            .unwrap_or(0);
        m as f64 / t as f64
    }
    fn merge_from(&mut self, other: &Bounded) {
        for (k, v) in &other.map {
            self.add(k, *v);
        }
    }
}

/// Everything observed in one engine tick.
#[derive(Clone, Debug)]
pub struct TickAgg {
    pub t: u64,
    pub requests: u32,
    pub bytes: u64,
    pub s2xx: u32,
    pub s4xx: u32,
    pub s5xx: u32,
    pub dur_sum_ms: f64,
    pub by_ip: Bounded,
    pub by_endpoint: Bounded,
    pub by_ua: Bounded,
    pub by_host: Bounded,
    pub by_method: Bounded,
    pub by_net: Bounded,
    /// `ip \x01 endpoint` pairs — the raw material for measuring how many
    /// DIFFERENT sources converge on the SAME endpoint, which is the whole
    /// difference between a busy site and a coordinated flood.
    pub by_ip_ep: Bounded,
}

impl Default for TickAgg {
    fn default() -> Self {
        TickAgg {
            t: 0,
            requests: 0,
            bytes: 0,
            s2xx: 0,
            s4xx: 0,
            s5xx: 0,
            dur_sum_ms: 0.0,
            by_ip: Bounded::new(MAX_IPS),
            by_endpoint: Bounded::new(MAX_ENDPOINTS),
            by_ua: Bounded::new(MAX_UAS),
            by_host: Bounded::new(MAX_HOSTS),
            by_method: Bounded::new(MAX_METHODS),
            by_net: Bounded::new(MAX_NETS),
            by_ip_ep: Bounded::new(MAX_IPS),
        }
    }
}

const MAX_METHODS: usize = 24;

impl TickAgg {
    pub fn from_requests(t: u64, reqs: &[Req]) -> Self {
        let mut a = TickAgg {
            t,
            ..Default::default()
        };
        for r in reqs {
            a.requests += 1;
            a.bytes += r.bytes;
            match r.status {
                200..=299 => a.s2xx += 1,
                400..=499 => a.s4xx += 1,
                500..=599 => a.s5xx += 1,
                _ => {}
            }
            a.dur_sum_ms += r.duration_ms;
            a.by_ip.add(&r.ip, 1);
            a.by_endpoint.add(&r.endpoint(), 1);
            a.by_ua
                .add(if r.ua.is_empty() { "(none)" } else { &r.ua }, 1);
            if !r.host.is_empty() {
                a.by_host.add(&r.host, 1);
            }
            if !r.method.is_empty() {
                a.by_method.add(&r.method, 1);
            }
            a.by_net.add(&crate::util::slash24(&r.ip), 1);
            a.by_ip_ep.add(&format!("{}\u{1}{}", r.ip, r.endpoint()), 1);
        }
        a
    }
}

/// A merged view over the whole window.
#[derive(Clone, Debug, Default)]
pub struct WindowView {
    pub secs: u64,
    pub requests: u64,
    pub bytes: u64,
    pub s2xx: u64,
    pub s4xx: u64,
    pub s5xx: u64,
    pub dur_sum_ms: f64,
    pub by_ip: Bounded,
    pub by_endpoint: Bounded,
    pub by_ua: Bounded,
    pub by_host: Bounded,
    pub by_method: Bounded,
    pub by_net: Bounded,
    pub by_ip_ep: Bounded,
}

impl WindowView {
    pub fn rps(&self) -> f64 {
        if self.secs == 0 {
            0.0
        } else {
            self.requests as f64 / self.secs as f64
        }
    }
    pub fn error_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            (self.s4xx + self.s5xx) as f64 / self.requests as f64
        }
    }
    pub fn avg_latency_ms(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.dur_sum_ms / self.requests as f64
        }
    }
    /// Mean requests per source. A distributed flood pushes this DOWN while the
    /// aggregate rate goes up — which is exactly why one-IP thresholds miss it.
    pub fn reqs_per_source(&self) -> f64 {
        let d = self.by_ip.distinct();
        if d == 0 {
            0.0
        } else {
            self.requests as f64 / d as f64
        }
    }
}

/// Ring of ticks plus derived telemetry samples.
pub struct Window {
    pub span_secs: u64,
    ticks: VecDeque<TickAgg>,
    samples: VecDeque<Sample>,
    /// Per-source live-connection census from the latest tick.
    pub conn_by_source: HashMap<String, u32>,
    pub internal_by_source: HashMap<String, u32>,
}

#[allow(dead_code)]
impl Window {
    pub fn new(span_secs: u64) -> Self {
        Window {
            span_secs,
            ticks: VecDeque::new(),
            samples: VecDeque::new(),
            conn_by_source: HashMap::new(),
            internal_by_source: HashMap::new(),
        }
    }

    pub fn push(&mut self, tick: TickAgg, sample: Sample) {
        let now = tick.t.max(sample.t);
        self.ticks.push_back(tick);
        self.samples.push_back(sample);
        let cutoff = now.saturating_sub(self.span_secs);
        while self.ticks.front().map(|x| x.t < cutoff).unwrap_or(false) {
            self.ticks.pop_front();
        }
        while self.samples.front().map(|x| x.t < cutoff).unwrap_or(false) {
            self.samples.pop_front();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ticks.is_empty()
    }
    pub fn latest(&self) -> Option<&Sample> {
        self.samples.back()
    }
    pub fn samples(&self) -> impl Iterator<Item = &Sample> {
        self.samples.iter()
    }
    pub fn ticks(&self) -> impl Iterator<Item = &TickAgg> {
        self.ticks.iter()
    }

    /// Merged view over the last `secs` seconds (clamped to what is retained).
    pub fn view(&self, secs: u64) -> WindowView {
        let now = self.ticks.back().map(|t| t.t).unwrap_or(0);
        let from = now.saturating_sub(secs);
        let mut v = WindowView {
            by_ip: Bounded::new(MAX_IPS),
            by_endpoint: Bounded::new(MAX_ENDPOINTS),
            by_ua: Bounded::new(MAX_UAS),
            by_host: Bounded::new(MAX_HOSTS),
            by_method: Bounded::new(MAX_METHODS),
            by_net: Bounded::new(MAX_NETS),
            by_ip_ep: Bounded::new(MAX_IPS),
            ..Default::default()
        };
        let mut first = u64::MAX;
        for t in self.ticks.iter().filter(|t| t.t > from) {
            first = first.min(t.t);
            v.requests += t.requests as u64;
            v.bytes += t.bytes;
            v.s2xx += t.s2xx as u64;
            v.s4xx += t.s4xx as u64;
            v.s5xx += t.s5xx as u64;
            v.dur_sum_ms += t.dur_sum_ms;
            v.by_ip.merge_from(&t.by_ip);
            v.by_endpoint.merge_from(&t.by_endpoint);
            v.by_ua.merge_from(&t.by_ua);
            v.by_host.merge_from(&t.by_host);
            v.by_method.merge_from(&t.by_method);
            v.by_net.merge_from(&t.by_net);
            v.by_ip_ep.merge_from(&t.by_ip_ep);
        }
        // Rate over the observed span, not the requested one: 12 s of data must
        // not be divided by 60 and reported as a fifth of the real rate.
        v.secs = if first == u64::MAX {
            0
        } else {
            (now.saturating_sub(first)).max(1).min(secs)
        };
        v
    }

    /// Mean of a per-sample field over the last `secs` seconds.
    pub fn mean<F: Fn(&Sample) -> f64>(&self, secs: u64, f: F) -> f64 {
        let now = self.samples.back().map(|s| s.t).unwrap_or(0);
        let from = now.saturating_sub(secs);
        let vals: Vec<f64> = self.samples.iter().filter(|s| s.t > from).map(&f).collect();
        if vals.is_empty() {
            0.0
        } else {
            vals.iter().sum::<f64>() / vals.len() as f64
        }
    }

    pub fn peak<F: Fn(&Sample) -> f64>(&self, secs: u64, f: F) -> f64 {
        let now = self.samples.back().map(|s| s.t).unwrap_or(0);
        let from = now.saturating_sub(secs);
        self.samples
            .iter()
            .filter(|s| s.t > from)
            .map(&f)
            .fold(0.0, f64::max)
    }

    /// Last `n` values of a field, oldest first — for the TUI sparklines.
    pub fn series<F: Fn(&Sample) -> f64>(&self, n: usize, f: F) -> Vec<u64> {
        let skip = self.samples.len().saturating_sub(n);
        self.samples
            .iter()
            .skip(skip)
            .map(|s| f(s).max(0.0) as u64)
            .collect()
    }

    pub fn request_series(&self, n: usize, interval: u64) -> Vec<u64> {
        let skip = self.ticks.len().saturating_sub(n);
        self.ticks
            .iter()
            .skip(skip)
            .map(|t| (t.requests as u64) / interval.max(1))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(ip: &str, path: &str, status: u16) -> Req {
        Req {
            ip: ip.into(),
            method: "GET".into(),
            host: "app.example.com".into(),
            path: path.into(),
            status,
            bytes: 100,
            ua: "curl/8".into(),
            duration_ms: 10.0,
        }
    }

    #[test]
    fn bounded_map_caps_keys_but_keeps_totals() {
        let mut b = Bounded::new(3);
        for i in 0..10 {
            b.add(&format!("k{}", i), 1);
        }
        assert_eq!(b.total(), 10, "no request may be lost to the cap");
        assert!(b.map.len() <= 4, "cap + the OTHER bucket");
        assert_eq!(b.distinct(), 10);
    }

    #[test]
    fn top_share_ignores_the_overflow_bucket() {
        let mut b = Bounded::new(2);
        b.add("a", 5);
        b.add("b", 1);
        for i in 0..50 {
            b.add(&format!("x{}", i), 1); // all land in OTHER
        }
        // OTHER holds 50 but is many distinct keys, so it is not concentration
        assert!((b.top_share() - 5.0 / 56.0).abs() < 1e-9);
    }

    #[test]
    fn window_evicts_old_ticks() {
        let mut w = Window::new(30);
        for t in 0..20u64 {
            let s = Sample {
                t: t * 5,
                ..Default::default()
            };
            w.push(
                TickAgg::from_requests(t * 5, &[req("1.1.1.1", "/", 200)]),
                s,
            );
        }
        assert!(w.ticks.len() <= 7, "30 s at 5 s per tick keeps ~6 ticks");
        assert!(w.view(30).requests <= 7);
    }

    #[test]
    fn view_rate_uses_the_observed_span_not_the_requested_one() {
        let mut w = Window::new(300);
        // 3 ticks 5 s apart = 10 s of observation, 30 requests
        for i in 0..3u64 {
            let reqs: Vec<Req> = (0..10).map(|_| req("1.1.1.1", "/", 200)).collect();
            w.push(
                TickAgg::from_requests(1000 + i * 5, &reqs),
                Sample {
                    t: 1000 + i * 5,
                    ..Default::default()
                },
            );
        }
        let v = w.view(300);
        assert_eq!(v.requests, 30);
        assert_eq!(v.secs, 10);
        assert!((v.rps() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn concentration_and_diversity_are_distinguishable() {
        // one endpoint, many sources = a distributed endpoint flood
        let mut reqs = Vec::new();
        for i in 0..100 {
            reqs.push(req(&format!("203.0.113.{}", i % 250), "/api/search", 200));
        }
        let a = TickAgg::from_requests(1, &reqs);
        assert!(a.by_endpoint.top_share() > 0.99);
        assert!(a.by_ip.top_share() < 0.05);

        // many endpoints, many sources = an ordinary busy site
        let mut reqs = Vec::new();
        for i in 0..100 {
            reqs.push(req(&format!("203.0.113.{}", i), &format!("/p/{}", i), 200));
        }
        let b = TickAgg::from_requests(1, &reqs);
        assert!(b.by_endpoint.top_share() < 0.05);
    }

    #[test]
    fn error_rate_and_latency() {
        let reqs = vec![
            req("1.1.1.1", "/", 200),
            req("1.1.1.1", "/", 500),
            req("1.1.1.1", "/", 404),
            req("1.1.1.1", "/", 200),
        ];
        let mut w = Window::new(60);
        w.push(
            TickAgg::from_requests(10, &reqs),
            Sample {
                t: 10,
                ..Default::default()
            },
        );
        let v = w.view(60);
        assert!((v.error_rate() - 0.5).abs() < 1e-9);
        assert!((v.avg_latency_ms() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn empty_window_is_safe() {
        let w = Window::new(60);
        let v = w.view(60);
        assert_eq!(v.rps(), 0.0);
        assert_eq!(v.error_rate(), 0.0);
        assert_eq!(v.reqs_per_source(), 0.0);
        assert!(w.latest().is_none());
    }
}
