//! Multi-signal DDoS detection, risk scoring, and attack classification.
//!
//! There is deliberately no `if rate > threshold { attack }` anywhere in here.
//! Nine independent signals each contribute a bounded number of points, every
//! one of them carries the measurement that produced it, and the final score is
//! their sum. That is what makes the verdict explainable: the dashboard never
//! says "DDoS detected", it says *which* measurements moved and by how much.
//!
//! Signal                     weight   what it answers
//!   traffic anomaly            20     is the pipe carrying far more than normal?
//!   request-rate anomaly       20     is the application being asked for far more?
//!   source concentration       15     is one address or network responsible?
//!   endpoint concentration     10     is one URL absorbing everything?
//!   behaviour similarity       10     do many sources act like one script?
//!   connection anomaly         10     are sockets being created abnormally fast?
//!   error-rate anomaly          5     is the application starting to fail?
//!   temporal anomaly            5     is this abnormal *for this hour*?
//!   application health          5     are the protected services actually hurting?
use super::baseline::Baseline;
use super::health::{Report, State};
use super::window::{Window, WindowView, OTHER};
use crate::config::{Config, Threat};
use crate::util::slash24;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::HashMap;

/// Linear ramp: <= lo scores 0, >= hi scores 1.
fn ramp(x: f64, lo: f64, hi: f64) -> f64 {
    if !x.is_finite() || hi <= lo {
        return 0.0;
    }
    ((x - lo) / (hi - lo)).clamp(0.0, 1.0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signal {
    pub key: String,
    pub label: String,
    pub weight: u32,
    /// Points actually awarded (0..=weight).
    pub points: u32,
    /// The measurement, in words, e.g. "traffic is 18.4x baseline".
    pub evidence: String,
    pub fired: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AttackType {
    None,
    TrafficSurge,
    VolumetricAnomaly,
    HttpFlood,
    DistributedHttpFlood,
    EndpointExhaustion,
    ConnectionExhaustion,
    BurstAttack,
    SlowRequestAnomaly,
    InternalAnomaly,
}

impl AttackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackType::None => "NONE",
            AttackType::TrafficSurge => "TRAFFIC SURGE",
            AttackType::VolumetricAnomaly => "VOLUMETRIC ANOMALY",
            AttackType::HttpFlood => "HTTP FLOOD",
            AttackType::DistributedHttpFlood => "DISTRIBUTED HTTP FLOOD",
            AttackType::EndpointExhaustion => "ENDPOINT EXHAUSTION",
            AttackType::ConnectionExhaustion => "CONNECTION EXHAUSTION",
            AttackType::BurstAttack => "BURST ATTACK",
            AttackType::SlowRequestAnomaly => "SLOW REQUEST ANOMALY",
            AttackType::InternalAnomaly => "INTERNAL TRAFFIC ANOMALY",
        }
    }
    /// A surge is explicitly NOT an attack — it is the false-positive verdict.
    pub fn is_attack(&self) -> bool {
        !matches!(self, AttackType::None | AttackType::TrafficSurge)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }
}

/// Every measured value the assessment used. Persisted into incidents so a
/// report can be re-read months later and still mean something.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metrics {
    pub rps: f64,
    pub rps_base: f64,
    pub rps_short: f64,
    pub rx_bps: f64,
    pub rx_bps_base: f64,
    pub tx_bps: f64,
    pub pps: f64,
    pub pps_base: f64,
    pub conn_rate: f64,
    pub conn_rate_base: f64,
    pub established: u32,
    pub established_base: f64,
    pub syn_recv: u32,
    pub sources: u32,
    pub sources_base: f64,
    /// Distinct sources seen in the ACCESS LOG (HTTP requesters), as opposed to
    /// `sources` which also counts live TCP peers. Attack-shape classification
    /// keys off this so idle background connections do not make a few-source
    /// endpoint flood look "distributed".
    pub request_sources: u32,
    pub networks: u32,
    pub reqs_per_source: f64,
    pub top_endpoint: String,
    pub top_endpoint_share: f64,
    pub top_source: String,
    pub top_source_share: f64,
    pub top_network: String,
    pub top_network_share: f64,
    pub top_ua: String,
    pub top_ua_share: f64,
    pub sources_on_top_endpoint: f64,
    pub uniformity: f64,
    pub similarity: f64,
    pub error_rate: f64,
    pub error_rate_base: f64,
    pub latency_ms: f64,
    pub latency_ms_base: f64,
    pub internal_bps: f64,
    pub internal_bps_base: f64,
    pub internal_conns: u32,
    pub internal_conns_base: f64,
    pub health_score: f64,
    pub health_state: String,
    pub top_domain: String,
    pub window_secs: u64,
    pub requests_in_window: u64,
}

/// A source considered for mitigation, with the reason it was picked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Suspect {
    pub ip: String,
    pub requests: u32,
    pub rpm: f64,
    pub connections: u32,
    /// 0-100, drives which mitigation level touches it.
    pub score: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    pub at: u64,
    pub score: u32,
    pub threat: Threat,
    pub attack: AttackType,
    pub confidence: Confidence,
    pub signals: Vec<Signal>,
    pub reasons: Vec<String>,
    pub metrics: Metrics,
    pub baseline_warm: bool,
    pub baseline_pct: u32,
    pub top_sources: Vec<(String, u32)>,
    pub top_endpoints: Vec<(String, u32)>,
    pub top_networks: Vec<(String, u32)>,
    pub top_uas: Vec<(String, u32)>,
    pub suspects: Vec<Suspect>,
    /// Set when the score was deliberately held down by false-positive damping.
    pub damped: Option<String>,
}

impl Default for Assessment {
    fn default() -> Self {
        Assessment {
            at: 0,
            score: 0,
            threat: Threat::Normal,
            attack: AttackType::None,
            confidence: Confidence::Low,
            signals: vec![],
            reasons: vec![],
            metrics: Metrics::default(),
            baseline_warm: false,
            baseline_pct: 0,
            top_sources: vec![],
            top_endpoints: vec![],
            top_networks: vec![],
            top_uas: vec![],
            suspects: vec![],
            damped: None,
        }
    }
}

/// Coefficient of variation of per-source request counts, folded into a 0-1
/// "these sources all behave identically" number. A crowd of real users has
/// wildly uneven request counts; a botnet issuing N requests each does not.
fn uniformity(by_ip: &HashMap<String, u32>) -> f64 {
    let vals: Vec<f64> = by_ip
        .iter()
        .filter(|(k, v)| k.as_str() != OTHER && **v >= 2)
        .map(|(_, v)| *v as f64)
        .collect();
    if vals.len() < 5 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    if mean <= 0.0 {
        return 0.0;
    }
    let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
    let cv = var.sqrt() / mean;
    (1.0 - cv).clamp(0.0, 1.0)
}

/// Share of active sources that are all hitting the single busiest endpoint.
/// This is the distributed-coordination measurement: it is high when 10,000
/// different addresses converge on `/api/search`, and low when the same 10,000
/// addresses browse a real site.
fn sources_on_top_endpoint(view: &WindowView, top_ep: &str) -> f64 {
    if top_ep.is_empty() || top_ep == OTHER {
        return 0.0;
    }
    let total = view.by_ip.distinct();
    if total == 0 {
        return 0.0;
    }
    let suffix = format!("\u{1}{}", top_ep);
    let n = view
        .by_ip_ep
        .map
        .keys()
        .filter(|k| k.ends_with(&suffix))
        .count() as f64;
    (n / total as f64).clamp(0.0, 1.0)
}

fn sig(key: &str, label: &str, weight: u32, frac: f64, evidence: String) -> Signal {
    let points = (weight as f64 * frac.clamp(0.0, 1.0)).round() as u32;
    Signal {
        key: key.into(),
        label: label.into(),
        weight,
        points,
        evidence,
        fired: points > 0,
    }
}

/// Run the full assessment for the current window.
pub fn assess(
    win: &Window,
    base: &Baseline,
    health: &Report,
    cfg: &Config,
    hour: usize,
) -> Assessment {
    let view = win.view(cfg.window_seconds);
    let short = win.view(10);
    let latest = win.latest().cloned().unwrap_or_default();
    let warm = base.warm(cfg);

    let mut m = Metrics {
        window_secs: view.secs,
        requests_in_window: view.requests,
        rps: view.rps(),
        rps_base: base.rps.mean,
        rps_short: short.rps(),
        rx_bps: latest.rx_bps,
        rx_bps_base: base.rx_bps.mean,
        tx_bps: latest.tx_bps,
        pps: latest.rx_pps,
        pps_base: base.pps.mean,
        conn_rate: latest.conn_rate,
        conn_rate_base: base.conn_rate.mean,
        established: latest.established,
        established_base: base.established.mean,
        syn_recv: latest.syn_recv,
        sources: view.by_ip.distinct().max(latest.conn_sources),
        sources_base: base.sources.mean,
        request_sources: view.by_ip.distinct(),
        networks: view.by_net.distinct(),
        reqs_per_source: view.reqs_per_source(),
        error_rate: view.error_rate(),
        error_rate_base: base.error_rate.mean,
        latency_ms: view.avg_latency_ms(),
        latency_ms_base: base.latency_ms.mean,
        internal_bps: latest.internal_bps,
        internal_bps_base: base.internal_bps.mean,
        internal_conns: latest.internal_conns,
        internal_conns_base: base.internal_conns.mean,
        health_score: health.score(),
        health_state: health.overall().as_str().into(),
        ..Default::default()
    };

    let top_ep = view.by_endpoint.top(1);
    let top_src = view.by_ip.top(1);
    let top_net = view.by_net.top(1);
    let top_ua = view.by_ua.top(1);
    let top_host = view.by_host.top(1);
    m.top_endpoint = top_ep.first().map(|x| x.0.clone()).unwrap_or_default();
    m.top_endpoint_share = view.by_endpoint.top_share();
    m.top_source = top_src.first().map(|x| x.0.clone()).unwrap_or_default();
    m.top_source_share = view.by_ip.top_share();
    m.top_network = top_net.first().map(|x| x.0.clone()).unwrap_or_default();
    m.top_network_share = view.by_net.top_share();
    m.top_ua = top_ua.first().map(|x| x.0.clone()).unwrap_or_default();
    m.top_ua_share = view.by_ua.top_share();
    m.top_domain = top_host.first().map(|x| x.0.clone()).unwrap_or_default();
    m.uniformity = uniformity(&view.by_ip.map);
    m.sources_on_top_endpoint = sources_on_top_endpoint(&view, &m.top_endpoint);
    m.similarity = 0.45 * m.sources_on_top_endpoint + 0.30 * m.top_ua_share + 0.25 * m.uniformity;

    // Until the baseline is warm nothing is scored against it: an empty
    // baseline would make the very first request look like a 100x surge.
    if !warm {
        return Assessment {
            at: latest.t,
            baseline_warm: false,
            baseline_pct: base.warmup_pct(cfg),
            metrics: m,
            reasons: vec![format!(
                "baseline learning — {}% of {} samples collected; scoring starts when warm",
                base.warmup_pct(cfg),
                cfg.baseline_warmup_samples
            )],
            top_sources: view.by_ip.top(10),
            top_endpoints: view.by_endpoint.top(10),
            top_networks: view.by_net.top(10),
            top_uas: view.by_ua.top(5),
            ..Default::default()
        };
    }

    let mut signals = Vec::new();

    // 1 — traffic anomaly. Needs an absolute floor: 20x of 2 kbps is still nothing.
    // Internal (docker-bridge) throughput is folded in so a container-origin
    // flood scores here even when the edge link looks normal.
    let bw_ratio = base.rx_bps.ratio(m.rx_bps, 64_000.0);
    let pps_ratio = base.pps.ratio(m.pps, 20.0);
    let internal_ratio = base.internal_bps.ratio(m.internal_bps, 64_000.0);
    let internal_scored = m.internal_bps > 1_000_000.0 && internal_ratio > 3.0;
    let traffic_ratio = bw_ratio.max(pps_ratio);
    let edge_quiet = m.rx_bps < 500_000.0 && m.pps < 200.0;
    let traffic_frac = if edge_quiet && !internal_scored {
        0.0
    } else {
        ramp(traffic_ratio, 2.0, 10.0)
            .max(ramp(base.rx_bps.z(m.rx_bps, 1000.0), 3.0, 12.0))
            .max(if internal_scored {
                ramp(internal_ratio, 3.0, 12.0)
            } else {
                0.0
            })
    };
    signals.push(sig(
        "traffic",
        "Traffic anomaly",
        20,
        traffic_frac,
        if internal_scored {
            format!(
                "internal/container traffic {} vs {} baseline ({:.1}x); edge inbound {} ({:.1}x)",
                crate::util::human_bps(m.internal_bps),
                crate::util::human_bps(m.internal_bps_base),
                internal_ratio,
                crate::util::human_bps(m.rx_bps),
                bw_ratio
            )
        } else {
            format!(
                "inbound {} vs {} baseline ({:.1}x), {:.0} pkt/s vs {:.0} ({:.1}x)",
                crate::util::human_bps(m.rx_bps),
                crate::util::human_bps(m.rx_bps_base),
                bw_ratio,
                m.pps,
                m.pps_base,
                pps_ratio
            )
        },
    ));

    // 2 — request-rate anomaly (only meaningful with an access log).
    let rps_ratio = base.rps.ratio(m.rps, 0.5);
    let rps_frac = if m.rps < cfg.min_rps_for_signal {
        0.0
    } else {
        ramp(rps_ratio, 2.0, 12.0).max(ramp(base.rps.z(m.rps, 0.5), 3.0, 12.0))
    };
    signals.push(sig(
        "requests",
        "Request-rate anomaly",
        20,
        rps_frac,
        format!(
            "{:.0} req/s vs {:.1} baseline ({:.1}x) over {} s",
            m.rps, m.rps_base, rps_ratio, m.window_secs
        ),
    ));

    // 3 — source concentration. One address, or one /24, doing all the work.
    let conc = m.top_source_share.max(m.top_network_share * 0.85);
    let conc_frac = if view.requests < 30 {
        0.0
    } else {
        ramp(conc, 0.25, 0.75)
    };
    signals.push(sig(
        "source_concentration",
        "Source concentration",
        15,
        conc_frac,
        format!(
            "top source {} holds {:.0}% of requests; top network {} holds {:.0}% ({} sources, {} networks)",
            if m.top_source.is_empty() { "-" } else { &m.top_source },
            m.top_source_share * 100.0,
            if m.top_network.is_empty() { "-" } else { &m.top_network },
            m.top_network_share * 100.0,
            m.sources,
            m.networks
        ),
    ));

    // 4 — endpoint concentration.
    let ep_frac = if view.requests < 50 {
        0.0
    } else {
        ramp(
            m.top_endpoint_share,
            (cfg.endpoint_concentration - 0.2).max(0.1),
            0.95,
        )
    };
    signals.push(sig(
        "endpoint_concentration",
        "Endpoint concentration",
        10,
        ep_frac,
        format!(
            "{} receives {:.0}% of all requests ({} distinct endpoints)",
            if m.top_endpoint.is_empty() {
                "-"
            } else {
                &m.top_endpoint
            },
            m.top_endpoint_share * 100.0,
            view.by_endpoint.distinct()
        ),
    ));

    // 5 — behaviour similarity: the distributed-coordination signal.
    let sim_frac = if m.sources < 5 || view.requests < 50 {
        0.0
    } else {
        ramp(m.similarity, cfg.behavior_similarity - 0.2, 0.9)
    };
    signals.push(sig(
        "behavior",
        "Behaviour similarity",
        10,
        sim_frac,
        format!(
            "{:.0}% similarity — {:.0}% of sources share the busiest endpoint, {:.0}% share one user-agent, {:.0}% request-count uniformity",
            m.similarity * 100.0,
            m.sources_on_top_endpoint * 100.0,
            m.top_ua_share * 100.0,
            m.uniformity * 100.0
        ),
    ));

    // 6 — connection anomaly.
    let cr_ratio = base.conn_rate.ratio(m.conn_rate, 1.0);
    let est_ratio = base.established.ratio(m.established as f64, 10.0);
    let syn_frac = if m.established > 0 {
        m.syn_recv as f64 / (m.established as f64 + m.syn_recv as f64)
    } else if m.syn_recv > 50 {
        1.0
    } else {
        0.0
    };
    let internal_conn_ratio = base.internal_conns.ratio(m.internal_conns as f64, 5.0);
    let conn_frac = ramp(cr_ratio.max(est_ratio), 2.0, 10.0)
        .max(ramp(syn_frac, 0.15, 0.6))
        .max(if m.internal_conns > 50 {
            ramp(internal_conn_ratio, 3.0, 12.0)
        } else {
            0.0
        });
    signals.push(sig(
        "connections",
        "Connection anomaly",
        10,
        conn_frac,
        format!(
            "{:.0} new conn/s vs {:.1} baseline ({:.1}x); {} established vs {:.0}; {} half-open; {} internal conns ({:.1}x)",
            m.conn_rate, m.conn_rate_base, cr_ratio, m.established, m.established_base, m.syn_recv, m.internal_conns, internal_conn_ratio
        ),
    ));

    // 7 — error-rate anomaly: the application starting to shed load.
    let err_ratio = base.error_rate.ratio(m.error_rate, 0.01);
    let err_frac = if view.requests < 50 || m.error_rate < 0.05 {
        0.0
    } else {
        ramp(err_ratio, 1.5, 6.0)
    };
    signals.push(sig(
        "errors",
        "Error-rate anomaly",
        5,
        err_frac,
        format!(
            "{:.1}% of responses are 4xx/5xx vs {:.1}% baseline ({:.1}x)",
            m.error_rate * 100.0,
            m.error_rate_base * 100.0,
            err_ratio
        ),
    ));

    // 8 — temporal anomaly: abnormal *for this hour of the day*.
    let expected = base.expected_rps_at(hour);
    let t_ratio = if expected > 0.2 {
        m.rps / expected
    } else {
        0.0
    };
    let temporal_frac = if m.rps < cfg.min_rps_for_signal {
        0.0
    } else {
        ramp(t_ratio, 3.0, 12.0)
    };
    signals.push(sig(
        "temporal",
        "Temporal anomaly",
        5,
        temporal_frac,
        format!(
            "{:.0} req/s at hour {:02}:00, where {:.1} req/s is normal ({:.1}x)",
            m.rps, hour, expected, t_ratio
        ),
    ));

    // 9 — application health.
    let health_frac = ramp(1.0 - m.health_score, 0.05, 0.5);
    signals.push(sig(
        "health",
        "Application health",
        5,
        health_frac,
        format!(
            "protected services are {} ({} degraded, {} unavailable)",
            m.health_state,
            health.degraded(),
            health.unavailable()
        ),
    ));

    let raw_score: u32 = signals.iter().map(|s| s.points).sum::<u32>().min(100);

    // ---- false-positive damping -------------------------------------------
    // Volume alone is not an attack. A real crowd is diverse, spread across
    // endpoints, and leaves the application healthy — a flash crowd after a
    // link goes viral looks exactly like that, and blocking it would be the
    // outage. Corroborating signals are the ones that separate the two.
    let corroborating: u32 = signals
        .iter()
        .filter(|s| {
            matches!(
                s.key.as_str(),
                "source_concentration"
                    | "endpoint_concentration"
                    | "behavior"
                    | "connections"
                    | "errors"
                    | "health"
            )
        })
        .map(|s| s.points)
        .sum();
    let volumetric: u32 = signals
        .iter()
        .filter(|s| matches!(s.key.as_str(), "traffic" | "requests" | "temporal"))
        .map(|s| s.points)
        .sum();

    let mut score = raw_score;
    let mut damped = None;
    let diverse = m.top_endpoint_share < 0.5 && m.top_source_share < 0.2 && m.similarity < 0.5;
    let healthy = health.overall() == State::Healthy || health.overall() == State::Unknown;
    // A flash crowd: lots of volume, but the corroborating signals that separate
    // an attack from a crowd (a dominant source, a hammered endpoint, coordinated
    // behaviour, a failing application) are all quiet. Treat it as a surge, not
    // an attack — and hold the score below the ATTACK band so nothing auto-blocks
    // a legitimate spike.
    let benign_surge = volumetric > 0 && corroborating <= 5 && diverse && healthy;
    if benign_surge {
        let cap = cfg.score_suspicious.saturating_sub(1);
        damped = Some(format!(
            "traffic is {:.1}x baseline but sources are diverse ({} sources over {} networks), no endpoint holds more than {:.0}%, behavioural similarity is only {:.0}%, and every protected service is healthy — classified as a surge, not an attack",
            rps_ratio.max(traffic_ratio), m.sources, m.networks, m.top_endpoint_share * 100.0, m.similarity * 100.0
        ));
        if score > cap {
            score = cap;
        }
    }

    let fired: Vec<&Signal> = signals.iter().filter(|s| s.fired).collect();
    let corroborating_fired = fired
        .iter()
        .filter(|s| {
            matches!(
                s.key.as_str(),
                "source_concentration"
                    | "endpoint_concentration"
                    | "behavior"
                    | "connections"
                    | "errors"
                    | "health"
            )
        })
        .count();
    let confidence = if fired.len() >= 4 && corroborating_fired >= 2 {
        Confidence::High
    } else if fired.len() >= 3 && corroborating_fired >= 1 {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    let threat = cfg.band(score);
    let attack = classify(&m, &signals, threat, damped.is_some());

    let mut reasons: Vec<String> = signals
        .iter()
        .filter(|s| s.fired)
        .map(|s| format!("{} (+{}) — {}", s.label, s.points, s.evidence))
        .collect();
    if reasons.is_empty() {
        reasons.push(format!(
            "all signals within baseline: {:.0} req/s (normal {:.1}), {} inbound (normal {}), {} sources",
            m.rps,
            m.rps_base,
            crate::util::human_bps(m.rx_bps),
            crate::util::human_bps(m.rx_bps_base),
            m.sources
        ));
    }
    if let Some(d) = &damped {
        reasons.push(format!("FALSE-POSITIVE DAMPING — {}", d));
    }

    Assessment {
        at: latest.t,
        score,
        threat,
        attack,
        confidence,
        suspects: rank_suspects(&view, win, &m, cfg),
        signals,
        reasons,
        metrics: m,
        baseline_warm: true,
        baseline_pct: 100,
        top_sources: view.by_ip.top(10),
        top_endpoints: view.by_endpoint.top(10),
        top_networks: view.by_net.top(10),
        top_uas: view.by_ua.top(5),
        damped,
    }
}

fn points(signals: &[Signal], key: &str) -> u32 {
    signals
        .iter()
        .find(|s| s.key == key)
        .map(|s| s.points)
        .unwrap_or(0)
}

/// Name the shape of the attack from the signals that actually fired.
pub fn classify(m: &Metrics, signals: &[Signal], threat: Threat, damped: bool) -> AttackType {
    if threat == Threat::Normal {
        return AttackType::None;
    }
    if damped {
        return AttackType::TrafficSurge;
    }
    let traffic = points(signals, "traffic");
    let requests = points(signals, "requests");
    let conc = points(signals, "source_concentration");
    let endpoint = points(signals, "endpoint_concentration");
    let behavior = points(signals, "behavior");
    let conns = points(signals, "connections");

    // Internal first: container-originated floods are a different response path.
    let internal_ratio = if m.internal_bps_base > 1000.0 {
        m.internal_bps / m.internal_bps_base
    } else {
        0.0
    };
    let internal_conn_ratio = if m.internal_conns_base > 2.0 {
        m.internal_conns as f64 / m.internal_conns_base
    } else {
        0.0
    };
    // Internal anomaly: container-origin traffic/connections dominate while the
    // edge HTTP request rate stays quiet (the flood is not coming through the
    // front door).
    if (internal_ratio > 5.0 || internal_conn_ratio > 5.0) && requests <= 6 {
        return AttackType::InternalAnomaly;
    }

    // Sockets under pressure while the application is barely being asked for
    // anything = the connection table is the target, not the app.
    if conns >= 6 && requests <= 6 {
        return AttackType::ConnectionExhaustion;
    }
    // Many open connections, high latency, low request completion = slowloris shape.
    if m.established as f64 > m.established_base * 4.0
        && m.latency_ms > m.latency_ms_base.max(200.0) * 3.0
        && requests <= 6
    {
        return AttackType::SlowRequestAnomaly;
    }
    // A spike that exists in the last 10 s but not across the window.
    if m.rps_short > m.rps * 2.5 && m.rps_short > m.rps_base * 5.0 && requests > 0 {
        return AttackType::BurstAttack;
    }
    if requests > 0 || endpoint > 0 {
        // A distributed attack: many *requesting* sources, none individually
        // dominant, but acting alike. Uses the access-log source count, not the
        // TCP peer count, so idle background connections cannot inflate it.
        let distributed = m.request_sources >= 20 && m.top_source_share < 0.25;
        let single_source = m.top_source_share >= 0.5;
        if distributed && (behavior >= 3 || endpoint >= 5) {
            return AttackType::DistributedHttpFlood;
        }
        // one address doing the damage is a plain HTTP flood, even if it all
        // lands on one endpoint
        if single_source {
            return AttackType::HttpFlood;
        }
        // a handful of sources concentrating on one resource is exhaustion
        if endpoint >= 5 {
            return AttackType::EndpointExhaustion;
        }
        if conc >= 7 {
            return AttackType::HttpFlood;
        }
        if requests >= 8 {
            return if distributed {
                AttackType::DistributedHttpFlood
            } else {
                AttackType::HttpFlood
            };
        }
    }
    if traffic >= 8 {
        return AttackType::VolumetricAnomaly;
    }
    AttackType::TrafficSurge
}

/// Score individual sources so mitigation can start with the worst offenders
/// instead of blocking everything that appeared during the window.
fn rank_suspects(view: &WindowView, win: &Window, m: &Metrics, cfg: &Config) -> Vec<Suspect> {
    let secs = view.secs.max(1) as f64;
    let mut out: Vec<Suspect> = Vec::new();
    for (ip, count) in view.by_ip.map.iter() {
        if ip == OTHER || crate::util::valid_ip(ip).is_none() {
            continue;
        }
        let rpm = *count as f64 * 60.0 / secs;
        let conns = win.conn_by_source.get(ip).copied().unwrap_or(0);
        let share = *count as f64 / view.requests.max(1) as f64;
        // three independent grounds, so one alone cannot get an address blocked
        let rate_pts = ramp(rpm / cfg.source_rpm_threshold.max(1.0), 0.5, 3.0) * 55.0;
        let share_pts = ramp(share, 0.05, 0.5) * 25.0;
        let conn_pts = ramp(conns as f64, 20.0, 200.0) * 20.0;
        let score = (rate_pts + share_pts + conn_pts).round() as u32;
        if score < 20 {
            continue;
        }
        out.push(Suspect {
            ip: ip.clone(),
            requests: *count,
            rpm,
            connections: conns,
            score: score.min(100),
            reason: format!(
                "{:.0} req/min ({:.1}% of window traffic), {} live connections",
                rpm,
                share * 100.0,
                conns
            ),
        });
    }
    // connection-only offenders: a socket flood leaves no access-log trace
    for (ip, conns) in win.conn_by_source.iter() {
        if *conns < 60 || out.iter().any(|s| &s.ip == ip) {
            continue;
        }
        let score = (ramp(*conns as f64, 60.0, 400.0) * 70.0).round() as u32;
        out.push(Suspect {
            ip: ip.clone(),
            requests: 0,
            rpm: 0.0,
            connections: *conns,
            score,
            reason: format!("{} live connections with no matching HTTP requests", conns),
        });
    }
    let _ = m;
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.ip.cmp(&b.ip)));
    out.truncate(cfg.max_auto_blocks);
    out
}

/// Group suspects by /24 — used when a flood is spread thinly across a network
/// and blocking address by address would never keep up.
pub fn network_suspects(suspects: &[Suspect], min_members: usize) -> Vec<(String, usize, f64)> {
    let mut by_net: HashMap<String, (usize, f64)> = HashMap::new();
    for s in suspects {
        let e = by_net.entry(slash24(&s.ip)).or_insert((0, 0.0));
        e.0 += 1;
        e.1 += s.rpm;
    }
    let mut v: Vec<(String, usize, f64)> = by_net
        .into_iter()
        .filter(|(_, (n, _))| *n >= min_members)
        .map(|(k, (n, r))| (k, n, r))
        .collect();
    v.sort_by_key(|t| Reverse(t.1));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shield::accesslog::Req;
    use crate::shield::baseline::Observation;
    use crate::shield::telemetry::Sample;
    use crate::shield::window::TickAgg;

    fn cfg() -> Config {
        Config::default()
    }

    /// Build a warm baseline that has seen a quiet, healthy site.
    fn warm_baseline(c: &Config) -> Baseline {
        let mut b = Baseline::default();
        for _ in 0..c.baseline_warmup_samples + 200 {
            b.update(
                &Observation {
                    rps: 10.0,
                    rx_bps: 2_000_000.0,
                    tx_bps: 4_000_000.0,
                    pps: 400.0,
                    conn_rate: 4.0,
                    established: 60.0,
                    sources: 30.0,
                    error_rate: 0.02,
                    latency_ms: 60.0,
                    internal_bps: 500_000.0,
                    internal_conns: 20.0,
                    hour: 12,
                },
                0,
                c,
            );
        }
        b
    }

    fn healthy() -> Report {
        Report {
            checks: vec![crate::shield::health::Check {
                name: "app".into(),
                kind: crate::shield::health::Kind::Domain,
                state: State::Healthy,
                http: 200,
                latency_ms: 40,
                detail: String::new(),
            }],
            ..Default::default()
        }
    }

    fn degraded() -> Report {
        Report {
            checks: vec![crate::shield::health::Check {
                name: "app".into(),
                kind: crate::shield::health::Kind::Domain,
                state: State::Unavailable,
                http: 503,
                latency_ms: 4000,
                detail: String::new(),
            }],
            ..Default::default()
        }
    }

    /// Feed `secs` seconds of traffic at 5 s per tick.
    fn build_window(secs: u64, per_tick: impl Fn(u64) -> (Vec<Req>, Sample)) -> Window {
        let mut w = Window::new(300);
        let mut t = 1_000u64;
        while t < 1_000 + secs {
            let (reqs, mut s) = per_tick(t);
            s.t = t;
            w.push(TickAgg::from_requests(t, &reqs), s);
            t += 5;
        }
        w
    }

    fn base_sample() -> Sample {
        Sample {
            rx_bps: 2_000_000.0,
            tx_bps: 4_000_000.0,
            rx_pps: 400.0,
            conn_rate: 4.0,
            established: 60,
            conn_sources: 30,
            internal_bps: 500_000.0,
            internal_conns: 20,
            ..Default::default()
        }
    }

    fn req(ip: &str, path: &str, status: u16, ua: &str) -> Req {
        Req {
            ip: ip.into(),
            method: "GET".into(),
            host: "app.example.com".into(),
            path: path.into(),
            status,
            bytes: 800,
            ua: ua.into(),
            duration_ms: 50.0,
        }
    }

    // ---------------------------------------------------------------- normal
    #[test]
    fn normal_traffic_scores_normal() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |t| {
            let reqs: Vec<Req> = (0..50)
                .map(|i| {
                    req(
                        &format!("203.0.113.{}", (t as usize * 7 + i) % 200),
                        &format!("/page/{}", i % 30),
                        200,
                        if i % 3 == 0 { "Chrome" } else { "Firefox" },
                    )
                })
                .collect();
            (reqs, base_sample())
        });
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert_eq!(a.threat, Threat::Normal, "signals: {:?}", a.reasons);
        assert_eq!(a.attack, AttackType::None);
    }

    #[test]
    fn cold_baseline_never_scores() {
        let c = cfg();
        let b = Baseline::default();
        let w = build_window(60, |_| {
            let reqs: Vec<Req> = (0..2000)
                .map(|_| req("1.2.3.4", "/x", 200, "bot"))
                .collect();
            (reqs, base_sample())
        });
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert_eq!(a.score, 0);
        assert!(!a.baseline_warm);
        assert!(a.reasons[0].contains("baseline learning"));
    }

    // ------------------------------------------------------- single-source flood
    #[test]
    fn single_source_http_flood_is_detected_and_named() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |_| {
            let mut reqs: Vec<Req> = (0..1500)
                .map(|_| req("198.51.100.9", "/api/search", 200, "python-requests/2.31"))
                .collect();
            reqs.extend((0..20).map(|i| req(&format!("203.0.113.{}", i), "/", 200, "Chrome")));
            let mut s = base_sample();
            s.rx_bps = 40_000_000.0;
            s.rx_pps = 9_000.0;
            s.conn_rate = 60.0;
            s.established = 900;
            (reqs, s)
        });
        let a = assess(&w, &b, &degraded(), &c, 12);
        assert!(
            a.score >= c.score_attack,
            "score {} — {:?}",
            a.score,
            a.reasons
        );
        assert_eq!(a.attack, AttackType::HttpFlood);
        assert!(a.suspects.iter().any(|s| s.ip == "198.51.100.9"));
        assert!(a.reasons.iter().any(|r| r.contains("Source concentration")));
    }

    // ------------------------------------------------- distributed HTTP flood
    #[test]
    fn distributed_flood_is_detected_even_though_no_single_ip_stands_out() {
        let c = cfg();
        let b = warm_baseline(&c);
        // 3000 distinct sources, one endpoint, one user-agent, identical rates
        let w = build_window(120, |t| {
            let reqs: Vec<Req> = (0..1500)
                .map(|i| {
                    let n = (t as usize * 300 + i) % 3000;
                    req(
                        &format!("100.{}.{}.{}", n / 65536 % 200 + 1, n / 256 % 256, n % 256),
                        "/api/search",
                        200,
                        "Go-http-client/1.1",
                    )
                })
                .collect();
            let mut s = base_sample();
            s.rx_bps = 60_000_000.0;
            s.rx_pps = 14_000.0;
            s.conn_rate = 120.0;
            s.established = 1400;
            s.conn_sources = 3000;
            (reqs, s)
        });
        let a = assess(&w, &b, &degraded(), &c, 12);
        assert!(
            a.score >= c.score_attack,
            "score {} — {:?}",
            a.score,
            a.reasons
        );
        assert_eq!(a.attack, AttackType::DistributedHttpFlood);
        assert!(
            a.metrics.top_source_share < 0.05,
            "no single IP should dominate"
        );
        assert!(
            a.metrics.sources_on_top_endpoint > 0.8,
            "coordination must be visible: {}",
            a.metrics.sources_on_top_endpoint
        );
        assert_eq!(a.confidence, Confidence::High);
    }

    // ----------------------------------------------------- legitimate surge
    #[test]
    fn legitimate_traffic_spike_is_not_called_an_attack() {
        let c = cfg();
        let b = warm_baseline(&c);
        // 20x traffic, but diverse sources, diverse endpoints, healthy app
        let w = build_window(120, |t| {
            let reqs: Vec<Req> = (0..1000)
                .map(|i| {
                    let n = (t as usize * 211 + i) % 5000;
                    req(
                        &format!("203.{}.{}.{}", n / 65536 % 200 + 1, n / 256 % 256, n % 256),
                        &format!("/article/{}", i % 400),
                        200,
                        ["Chrome/120", "Safari/17", "Firefox/121", "Edge/119"][i % 4],
                    )
                })
                .collect();
            let mut s = base_sample();
            s.rx_bps = 40_000_000.0;
            s.rx_pps = 8_000.0;
            s.conn_sources = 5000;
            (reqs, s)
        });
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert!(
            a.score < c.score_attack,
            "a flash crowd must not reach ATTACK: {} — {:?}",
            a.score,
            a.reasons
        );
        assert_eq!(a.attack, AttackType::TrafficSurge);
        assert!(a.damped.is_some(), "damping must be recorded, not silent");
    }

    // ------------------------------------------------------ endpoint exhaustion
    #[test]
    fn endpoint_exhaustion_from_a_few_sources() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |i| {
            let reqs: Vec<Req> = (0..800)
                .map(|n| {
                    req(
                        &format!("192.0.2.{}", (n + i as usize) % 6),
                        "/api/report/export",
                        200,
                        "curl/8.4",
                    )
                })
                .collect();
            let mut s = base_sample();
            s.rx_bps = 20_000_000.0;
            s.conn_rate = 30.0;
            (reqs, s)
        });
        let a = assess(&w, &b, &degraded(), &c, 12);
        assert!(a.score >= c.score_suspicious);
        assert_eq!(a.attack, AttackType::EndpointExhaustion);
        assert!(a.metrics.top_endpoint == "/api/report/export");
    }

    // ---------------------------------------------------- connection exhaustion
    #[test]
    fn connection_flood_without_http_requests() {
        let c = cfg();
        let b = warm_baseline(&c);
        // A SYN/connection flood is a packet flood: the SYN rate is enormous and
        // the connection table fills, so the edge stops accepting new sessions.
        let mut w = build_window(120, |_| {
            let mut s = base_sample();
            s.conn_rate = 900.0;
            s.established = 4_000;
            s.syn_recv = 6_000;
            s.rx_pps = 80_000.0; // SYN packet storm
            (vec![], s)
        });
        for i in 0..300 {
            w.conn_by_source
                .insert(format!("45.9.{}.{}", i / 256, i % 256), 90);
        }
        // the connection table saturating makes the front end unavailable
        let a = assess(&w, &b, &degraded(), &c, 12);
        assert!(a.score >= c.score_elevated, "score {}", a.score);
        assert_eq!(a.attack, AttackType::ConnectionExhaustion);
        assert!(
            a.suspects
                .iter()
                .any(|s| s.requests == 0 && s.connections >= 60),
            "connection-only offenders must still be mitigable"
        );
    }

    // ------------------------------------------------------- internal anomaly
    #[test]
    fn internal_container_anomaly_is_separated_from_edge_traffic() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |_| {
            let mut s = base_sample();
            s.internal_bps = 40_000_000.0; // 80x the learned bridge traffic
            s.internal_conns = 3_000;
            s.conn_rate = 20.0;
            (vec![], s)
        });
        let a = assess(&w, &b, &degraded(), &c, 12);
        assert_eq!(a.attack, AttackType::InternalAnomaly);
    }

    // ------------------------------------------------------------- burst
    #[test]
    fn short_burst_is_classified_as_a_burst() {
        let c = cfg();
        let b = warm_baseline(&c);
        let mut w = Window::new(300);
        // 110 s of quiet, then one loud 10 s
        let mut t = 1_000u64;
        while t < 1_110 {
            let reqs: Vec<Req> = (0..30)
                .map(|i| {
                    req(
                        &format!("203.0.113.{}", i),
                        &format!("/p{}", i % 20),
                        200,
                        "Chrome",
                    )
                })
                .collect();
            let mut s = base_sample();
            s.t = t;
            w.push(TickAgg::from_requests(t, &reqs), s);
            t += 5;
        }
        while t < 1_120 {
            let reqs: Vec<Req> = (0..2500)
                .map(|i| {
                    req(
                        &format!("45.{}.{}.{}", i / 65536 % 200 + 1, i / 256 % 256, i % 256),
                        "/",
                        200,
                        "bot",
                    )
                })
                .collect();
            let mut s = base_sample();
            s.t = t;
            s.rx_bps = 90_000_000.0;
            s.rx_pps = 20_000.0;
            w.push(TickAgg::from_requests(t, &reqs), s);
            t += 5;
        }
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert!(a.score >= c.score_elevated);
        assert!(
            matches!(
                a.attack,
                AttackType::BurstAttack | AttackType::DistributedHttpFlood
            ),
            "got {:?}",
            a.attack
        );
    }

    // ------------------------------------------------------------ mechanics
    #[test]
    fn every_reason_carries_a_measurement() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |_| {
            let reqs: Vec<Req> = (0..1500)
                .map(|_| req("198.51.100.9", "/api/search", 500, "bot"))
                .collect();
            let mut s = base_sample();
            s.rx_bps = 50_000_000.0;
            s.rx_pps = 12_000.0;
            (reqs, s)
        });
        let a = assess(&w, &b, &degraded(), &c, 12);
        for r in &a.reasons {
            assert!(
                r.chars().any(|ch| ch.is_ascii_digit()),
                "reason without a number: {}",
                r
            );
        }
    }

    #[test]
    fn score_never_exceeds_one_hundred() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(120, |_| {
            let reqs: Vec<Req> = (0..20_000)
                .map(|_| req("198.51.100.9", "/api/search", 503, "bot"))
                .collect();
            let mut s = base_sample();
            s.rx_bps = 900_000_000.0;
            s.rx_pps = 300_000.0;
            s.conn_rate = 5_000.0;
            s.established = 60_000;
            s.syn_recv = 40_000;
            (reqs, s)
        });
        let a = assess(&w, &b, &degraded(), &c, 3);
        assert!(a.score <= 100);
        assert_eq!(a.threat, Threat::Critical);
    }

    #[test]
    fn signal_weights_sum_to_one_hundred() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(60, |_| (vec![], base_sample()));
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert_eq!(a.signals.iter().map(|s| s.weight).sum::<u32>(), 100);
    }

    #[test]
    fn uniformity_separates_scripts_from_people() {
        let mut bot = HashMap::new();
        for i in 0..100 {
            bot.insert(format!("10.0.0.{}", i), 20);
        }
        assert!(uniformity(&bot) > 0.9);

        let mut people = HashMap::new();
        for i in 0..100 {
            people.insert(format!("10.0.0.{}", i), 2 + (i as u32 * i as u32) % 300);
        }
        assert!(uniformity(&people) < 0.6);
    }

    #[test]
    fn network_grouping_finds_a_thinly_spread_subnet() {
        let suspects: Vec<Suspect> = (0..40)
            .map(|i| Suspect {
                ip: format!("45.66.77.{}", i),
                requests: 100,
                rpm: 300.0,
                connections: 2,
                score: 40,
                reason: String::new(),
            })
            .collect();
        let nets = network_suspects(&suspects, 10);
        assert_eq!(nets.len(), 1);
        assert_eq!(nets[0].0, "45.66.77.0/24");
        assert_eq!(nets[0].1, 40);
    }

    #[test]
    fn quiet_box_produces_a_readable_no_finding_reason() {
        let c = cfg();
        let b = warm_baseline(&c);
        let w = build_window(60, |_| (vec![], base_sample()));
        let a = assess(&w, &b, &healthy(), &c, 12);
        assert_eq!(a.score, 0);
        assert!(a.reasons[0].contains("within baseline"));
    }
}
