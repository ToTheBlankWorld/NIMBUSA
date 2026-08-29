//! Incident records — the durable, reviewable output of the whole pipeline.
//!
//! Everything here is measured. Detection, mitigation and recovery times come
//! from the recovery state machine's timestamps; downtime comes from the health
//! probes; peaks come from the telemetry window. Nothing is filled in with a
//! plausible-looking constant, because an incident report that flatters itself
//! is worse than none.
use super::detect::{Assessment, AttackType, Metrics, Signal};
use crate::config::Threat;
use crate::paths;
use crate::util::{epoch, now_str, write_atomic};
use serde::{Deserialize, Serialize};

/// Keep the store bounded — this is a VPS, not a SIEM.
const MAX_INCIDENTS: usize = 500;
const MAX_TIMELINE: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub ts: u64,
    pub time: String,
    pub kind: String,
    pub detail: String,
    /// Hash of the audit record this event produced, when auditing is on.
    #[serde(default)]
    pub audit_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub started: u64,
    pub started_time: String,
    #[serde(default)]
    pub ended: u64,
    #[serde(default)]
    pub ended_time: String,
    pub attack: AttackType,
    pub severity: Threat,
    pub peak_score: u32,
    pub confidence: String,
    /// The explanation, exactly as it was rendered at peak.
    pub reasons: Vec<String>,
    pub signals: Vec<Signal>,
    pub peak_metrics: Metrics,
    #[serde(default)]
    pub peak_rps: f64,
    #[serde(default)]
    pub peak_bps: f64,
    #[serde(default)]
    pub peak_conn_rate: f64,
    #[serde(default)]
    pub source_count: u32,
    #[serde(default)]
    pub network_count: u32,
    pub target_domain: String,
    pub target_endpoint: String,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub mitigations: Vec<String>,
    #[serde(default)]
    pub blocked_sources: u32,
    #[serde(default)]
    pub blocked_networks: u32,
    #[serde(default)]
    pub max_level: u8,
    #[serde(default)]
    pub escalations: u32,
    /// anomaly first seen -> classified as an attack (seconds)
    #[serde(default)]
    pub detection_secs: u64,
    /// classified -> first rule in place (seconds)
    #[serde(default)]
    pub mitigation_secs: u64,
    /// cooldown started -> back to NORMAL (seconds)
    #[serde(default)]
    pub recovery_secs: u64,
    #[serde(default)]
    pub duration_secs: u64,
    /// measured seconds a protected service was unreachable
    #[serde(default)]
    pub downtime_secs: u64,
    pub recovery_state: String,
    #[serde(default)]
    pub timeline: Vec<Event>,
    /// Head of the audit chain at the moment this record was finalised.
    #[serde(default)]
    pub audit_hash: String,
    #[serde(default)]
    pub simulated: bool,
    #[serde(default)]
    pub open: bool,
}

impl Incident {
    pub fn open_new(id: String, a: &Assessment, simulated: bool) -> Incident {
        Incident {
            id,
            started: if a.at > 0 { a.at } else { epoch() },
            started_time: now_str(),
            ended: 0,
            ended_time: String::new(),
            attack: a.attack,
            severity: a.threat,
            peak_score: a.score,
            confidence: a.confidence.as_str().into(),
            reasons: a.reasons.clone(),
            signals: a.signals.clone(),
            peak_metrics: a.metrics.clone(),
            peak_rps: a.metrics.rps,
            peak_bps: a.metrics.rx_bps,
            peak_conn_rate: a.metrics.conn_rate,
            source_count: a.metrics.sources,
            network_count: a.metrics.networks,
            target_domain: a.metrics.top_domain.clone(),
            target_endpoint: a.metrics.top_endpoint.clone(),
            services: vec![],
            mitigations: vec![],
            blocked_sources: 0,
            blocked_networks: 0,
            max_level: 0,
            escalations: 0,
            detection_secs: 0,
            mitigation_secs: 0,
            recovery_secs: 0,
            duration_secs: 0,
            downtime_secs: 0,
            recovery_state: "ATTACK_DETECTED".into(),
            timeline: vec![],
            audit_hash: String::new(),
            simulated,
            open: true,
        }
    }

    pub fn note(&mut self, kind: &str, detail: &str, audit_hash: &str) {
        if self.timeline.len() >= MAX_TIMELINE {
            self.timeline.remove(0);
        }
        self.timeline.push(Event {
            ts: epoch(),
            time: now_str(),
            kind: kind.into(),
            detail: detail.into(),
            audit_hash: audit_hash.into(),
        });
    }

    /// Fold a new assessment in, keeping the worst-case view of the episode.
    pub fn absorb(&mut self, a: &Assessment) {
        if a.score > self.peak_score {
            self.peak_score = a.score;
            self.severity = a.threat;
            self.confidence = a.confidence.as_str().into();
            self.reasons = a.reasons.clone();
            self.signals = a.signals.clone();
            self.peak_metrics = a.metrics.clone();
            if a.attack.is_attack() {
                self.attack = a.attack;
            }
        }
        self.peak_rps = self.peak_rps.max(a.metrics.rps);
        self.peak_bps = self.peak_bps.max(a.metrics.rx_bps);
        self.peak_conn_rate = self.peak_conn_rate.max(a.metrics.conn_rate);
        self.source_count = self.source_count.max(a.metrics.sources);
        self.network_count = self.network_count.max(a.metrics.networks);
        if !a.metrics.top_endpoint.is_empty() && a.score >= self.peak_score.saturating_sub(10) {
            self.target_endpoint = a.metrics.top_endpoint.clone();
        }
        if !a.metrics.top_domain.is_empty() {
            self.target_domain = a.metrics.top_domain.clone();
        }
    }

    pub fn close(&mut self, at: u64) {
        self.ended = at;
        self.ended_time = now_str();
        self.duration_secs = at.saturating_sub(self.started);
        self.open = false;
        self.recovery_state = "RECOVERED".into();
    }

    /// Availability across the incident, from measured downtime.
    pub fn availability_pct(&self) -> f64 {
        let d = self.duration_secs.max(1) as f64;
        (((d - self.downtime_secs.min(self.duration_secs) as f64) / d) * 100.0).clamp(0.0, 100.0)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub incidents: Vec<Incident>,
    #[serde(default)]
    pub last_seq: u32,
    #[serde(default)]
    pub last_day: String,
}

pub fn load() -> Store {
    match std::fs::read_to_string(paths::ddos("incidents.json")) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Store::default(),
    }
}

pub fn save(store: &Store) {
    let mut s = store.clone();
    if s.incidents.len() > MAX_INCIDENTS {
        let drop = s.incidents.len() - MAX_INCIDENTS;
        s.incidents.drain(0..drop);
    }
    if let Ok(j) = serde_json::to_string_pretty(&s) {
        let _ = write_atomic(&paths::ddos("incidents.json"), &j);
    }
}

/// `NIMBUSA-DDOS-YYYYMMDD-NNNN`, with the counter restarting each day.
pub fn next_id(store: &mut Store, day: &str) -> String {
    if store.last_day != day {
        store.last_day = day.to_string();
        store.last_seq = 0;
    }
    store.last_seq += 1;
    format!("NIMBUSA-DDOS-{}-{:04}", day, store.last_seq)
}

pub fn today() -> String {
    crate::util::sh("date '+%Y%m%d'")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shield::detect::Confidence;

    fn assessment(score: u32, attack: AttackType) -> Assessment {
        Assessment {
            at: 1000,
            score,
            threat: crate::config::Config::default().band(score),
            attack,
            confidence: Confidence::High,
            reasons: vec![format!("score {}", score)],
            metrics: Metrics {
                rps: score as f64 * 10.0,
                rx_bps: score as f64 * 1_000_000.0,
                sources: score * 3,
                networks: score,
                top_endpoint: "/api/search".into(),
                top_domain: "api.example.com".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn ids_increment_within_a_day_and_reset_across_days() {
        let mut s = Store::default();
        assert_eq!(next_id(&mut s, "20260829"), "NIMBUSA-DDOS-20260829-0001");
        assert_eq!(next_id(&mut s, "20260829"), "NIMBUSA-DDOS-20260829-0002");
        assert_eq!(next_id(&mut s, "20260830"), "NIMBUSA-DDOS-20260830-0001");
    }

    #[test]
    fn absorb_keeps_the_worst_case() {
        let mut i = Incident::open_new("I1".into(), &assessment(72, AttackType::HttpFlood), false);
        i.absorb(&assessment(94, AttackType::DistributedHttpFlood));
        i.absorb(&assessment(60, AttackType::HttpFlood));
        assert_eq!(i.peak_score, 94);
        assert_eq!(i.attack, AttackType::DistributedHttpFlood);
        assert_eq!(i.severity, Threat::Critical);
        assert!((i.peak_rps - 940.0).abs() < 1e-9);
        assert_eq!(i.source_count, 94 * 3);
    }

    #[test]
    fn availability_comes_from_measured_downtime() {
        let mut i = Incident::open_new("I1".into(), &assessment(90, AttackType::HttpFlood), false);
        i.started = 1000;
        i.close(1100);
        assert_eq!(i.duration_secs, 100);
        assert_eq!(i.availability_pct(), 100.0);
        i.downtime_secs = 10;
        assert!((i.availability_pct() - 90.0).abs() < 1e-9);
    }

    #[test]
    fn availability_cannot_go_negative() {
        let mut i = Incident::open_new("I1".into(), &assessment(90, AttackType::HttpFlood), false);
        i.started = 1000;
        i.close(1010);
        i.downtime_secs = 9_999;
        assert_eq!(i.availability_pct(), 0.0);
    }

    #[test]
    fn timeline_is_bounded() {
        let mut i = Incident::open_new("I1".into(), &assessment(90, AttackType::HttpFlood), false);
        for n in 0..(MAX_TIMELINE + 50) {
            i.note("TEST", &format!("event {}", n), "");
        }
        assert_eq!(i.timeline.len(), MAX_TIMELINE);
        assert!(i
            .timeline
            .last()
            .unwrap()
            .detail
            .contains(&format!("{}", MAX_TIMELINE + 49)));
    }

    #[test]
    fn incident_round_trips_through_json() {
        let mut i = Incident::open_new(
            "NIMBUSA-DDOS-20260829-0001".into(),
            &assessment(94, AttackType::DistributedHttpFlood),
            false,
        );
        i.note("MITIGATION", "rate limiting applied", "abc123");
        i.mitigations.push("adaptive rate limiting".into());
        i.close(i.started + 240);
        let j = serde_json::to_string(&i).unwrap();
        let back: Incident = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id, i.id);
        assert_eq!(back.attack, AttackType::DistributedHttpFlood);
        assert_eq!(back.timeline.len(), 1);
        assert_eq!(back.mitigations, i.mitigations);
        assert!(!back.open);
    }

    #[test]
    fn store_is_capped() {
        let mut s = Store::default();
        for n in 0..(MAX_INCIDENTS + 20) {
            s.incidents.push(Incident::open_new(
                format!("I{}", n),
                &assessment(80, AttackType::HttpFlood),
                false,
            ));
        }
        // save() trims; emulate its trimming rule
        let drop = s.incidents.len() - MAX_INCIDENTS;
        s.incidents.drain(0..drop);
        assert_eq!(s.incidents.len(), MAX_INCIDENTS);
        assert_eq!(s.incidents[0].id, format!("I{}", 20));
    }

    #[test]
    fn simulated_incidents_are_flagged() {
        let i = Incident::open_new("I1".into(), &assessment(90, AttackType::HttpFlood), true);
        assert!(i.simulated);
    }
}
