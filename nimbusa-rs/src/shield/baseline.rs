//! Rolling baseline — what "normal" looks like on THIS box.
//!
//! Each tracked metric keeps an exponentially-weighted mean and variance, which
//! gives both a ratio ("18x normal") and a z-score ("9 sigma out") for a few
//! bytes of state and no history buffer.
//!
//! Attack-awareness is the point of the `frozen` flag: once the risk score
//! crosses `baseline.freeze_score`, learning stops. Without that, a flood that
//! runs for ten minutes teaches the system that a flood is normal and the
//! second wave scores zero.
use crate::config::Config;
use crate::paths;
use crate::util::{epoch, write_atomic};
use serde::{Deserialize, Serialize};

/// Exponentially-weighted mean and variance.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Ewma {
    #[serde(default)]
    pub mean: f64,
    #[serde(default)]
    pub var: f64,
    #[serde(default)]
    pub n: u64,
}

impl Ewma {
    pub fn update(&mut self, x: f64, alpha: f64) {
        if !x.is_finite() {
            return;
        }
        if self.n == 0 {
            self.mean = x;
            self.var = 0.0;
            self.n = 1;
            return;
        }
        let d = x - self.mean;
        self.mean += alpha * d;
        // West's incremental EWM variance
        self.var = (1.0 - alpha) * (self.var + alpha * d * d);
        self.n = self.n.saturating_add(1);
    }

    pub fn sd(&self) -> f64 {
        self.var.max(0.0).sqrt()
    }

    /// How many times bigger than normal `x` is. `floor` keeps a near-zero
    /// baseline from turning a trickle into an infinite ratio.
    pub fn ratio(&self, x: f64, floor: f64) -> f64 {
        let m = self.mean.max(floor);
        if m <= 0.0 {
            return 0.0;
        }
        (x / m).max(0.0)
    }

    /// Sigmas above the mean. Values below the mean score 0 — this detector
    /// only cares about surges.
    pub fn z(&self, x: f64, floor_sd: f64) -> f64 {
        let sd = self.sd().max(floor_sd);
        if sd <= 0.0 {
            return 0.0;
        }
        ((x - self.mean) / sd).max(0.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    #[serde(default)]
    pub rps: Ewma,
    #[serde(default)]
    pub rx_bps: Ewma,
    #[serde(default)]
    pub tx_bps: Ewma,
    #[serde(default)]
    pub pps: Ewma,
    #[serde(default)]
    pub conn_rate: Ewma,
    #[serde(default)]
    pub established: Ewma,
    #[serde(default)]
    pub sources: Ewma,
    #[serde(default)]
    pub error_rate: Ewma,
    #[serde(default)]
    pub latency_ms: Ewma,
    #[serde(default)]
    pub internal_bps: Ewma,
    #[serde(default)]
    pub internal_conns: Ewma,
    /// Per hour-of-day request rate — the temporal-anomaly reference.
    #[serde(default = "default_hours")]
    pub hourly_rps: Vec<Ewma>,
    #[serde(default)]
    pub samples: u64,
    #[serde(default)]
    pub updated: u64,
    /// Ticks skipped because the score was too high to learn from.
    #[serde(default)]
    pub frozen_ticks: u64,
}

fn default_hours() -> Vec<Ewma> {
    vec![Ewma::default(); 24]
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            rps: Ewma::default(),
            rx_bps: Ewma::default(),
            tx_bps: Ewma::default(),
            pps: Ewma::default(),
            conn_rate: Ewma::default(),
            established: Ewma::default(),
            sources: Ewma::default(),
            error_rate: Ewma::default(),
            latency_ms: Ewma::default(),
            internal_bps: Ewma::default(),
            internal_conns: Ewma::default(),
            hourly_rps: default_hours(),
            samples: 0,
            updated: 0,
            frozen_ticks: 0,
        }
    }
}

/// The observation a baseline update consumes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    pub rps: f64,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub pps: f64,
    pub conn_rate: f64,
    pub established: f64,
    pub sources: f64,
    pub error_rate: f64,
    pub latency_ms: f64,
    pub internal_bps: f64,
    pub internal_conns: f64,
    /// 0-23 local hour, for the time-of-day profile.
    pub hour: usize,
}

impl Baseline {
    pub fn warm(&self, cfg: &Config) -> bool {
        self.samples >= cfg.baseline_warmup_samples
    }

    /// Fraction of the warm-up completed, for the UI.
    pub fn warmup_pct(&self, cfg: &Config) -> u32 {
        if cfg.baseline_warmup_samples == 0 {
            return 100;
        }
        ((self.samples as f64 / cfg.baseline_warmup_samples as f64) * 100.0).min(100.0) as u32
    }

    /// Learn from one observation. `score` is the current risk score: at or
    /// above the freeze threshold the sample is recorded as frozen and
    /// discarded, so an in-progress attack can never become the new normal.
    pub fn update(&mut self, o: &Observation, score: u32, cfg: &Config) -> bool {
        if score >= cfg.baseline_freeze_score {
            self.frozen_ticks = self.frozen_ticks.saturating_add(1);
            return false;
        }
        let a = cfg.baseline_alpha;
        self.rps.update(o.rps, a);
        self.rx_bps.update(o.rx_bps, a);
        self.tx_bps.update(o.tx_bps, a);
        self.pps.update(o.pps, a);
        self.conn_rate.update(o.conn_rate, a);
        self.established.update(o.established, a);
        self.sources.update(o.sources, a);
        self.error_rate.update(o.error_rate, a);
        self.latency_ms.update(o.latency_ms, a);
        self.internal_bps.update(o.internal_bps, a);
        self.internal_conns.update(o.internal_conns, a);
        if self.hourly_rps.len() != 24 {
            self.hourly_rps = default_hours();
        }
        // the hourly profile moves faster: it has 24x fewer samples to learn from
        self.hourly_rps[o.hour.min(23)].update(o.rps, (a * 4.0).min(0.5));
        self.samples = self.samples.saturating_add(1);
        self.updated = epoch();
        true
    }

    /// Expected request rate for this hour, falling back to the overall mean
    /// until that hour has been seen enough times to mean anything.
    pub fn expected_rps_at(&self, hour: usize) -> f64 {
        match self.hourly_rps.get(hour.min(23)) {
            Some(h) if h.n >= 5 => h.mean,
            _ => self.rps.mean,
        }
    }

    pub fn load() -> Baseline {
        match std::fs::read_to_string(paths::ddos("baseline.json")) {
            Ok(s) => match serde_json::from_str::<Baseline>(&s) {
                Ok(mut b) => {
                    if b.hourly_rps.len() != 24 {
                        b.hourly_rps = default_hours();
                    }
                    // A corrupt or absurd persisted value is worse than no
                    // baseline: it would suppress detection forever.
                    if !b.sane() {
                        Baseline::default()
                    } else {
                        b
                    }
                }
                Err(_) => Baseline::default(),
            },
            Err(_) => Baseline::default(),
        }
    }

    /// Every stored number must be finite and non-negative.
    pub fn sane(&self) -> bool {
        let all = [
            &self.rps,
            &self.rx_bps,
            &self.tx_bps,
            &self.pps,
            &self.conn_rate,
            &self.established,
            &self.sources,
            &self.error_rate,
            &self.latency_ms,
            &self.internal_bps,
            &self.internal_conns,
        ];
        all.iter()
            .chain(self.hourly_rps.iter().collect::<Vec<_>>().iter())
            .all(|e| e.mean.is_finite() && e.var.is_finite() && e.mean >= 0.0 && e.var >= 0.0)
    }

    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string(self) {
            let _ = write_atomic(&paths::ddos("baseline.json"), &s);
        }
    }

    #[allow(dead_code)]
    pub fn reset() {
        let _ = std::fs::remove_file(paths::ddos("baseline.json"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(rps: f64) -> Observation {
        Observation {
            rps,
            rx_bps: rps * 8000.0,
            conn_rate: rps / 2.0,
            sources: 20.0,
            hour: 12,
            ..Default::default()
        }
    }

    #[test]
    fn ewma_converges_to_a_steady_signal() {
        let mut e = Ewma::default();
        for _ in 0..500 {
            e.update(30.0, 0.05);
        }
        assert!((e.mean - 30.0).abs() < 0.01);
        assert!(e.sd() < 0.01);
    }

    #[test]
    fn ewma_variance_tracks_spread() {
        let mut e = Ewma::default();
        for i in 0..500 {
            e.update(if i % 2 == 0 { 20.0 } else { 40.0 }, 0.05);
        }
        assert!(e.sd() > 1.0, "alternating signal must have visible spread");
    }

    #[test]
    fn ratio_is_floored_so_idle_traffic_is_not_infinite() {
        let mut e = Ewma::default();
        e.update(0.0, 0.1);
        assert_eq!(e.ratio(5.0, 1.0), 5.0);
        assert!(e.ratio(5.0, 1.0).is_finite());
    }

    #[test]
    fn attack_does_not_poison_the_baseline() {
        let cfg = Config::default();
        let mut b = Baseline::default();
        for _ in 0..200 {
            b.update(&obs(30.0), 5, &cfg);
        }
        let learned = b.rps.mean;
        // a sustained flood, but the score says ATTACK the whole time
        for _ in 0..200 {
            b.update(&obs(3000.0), 92, &cfg);
        }
        assert!(
            (b.rps.mean - learned).abs() < 0.5,
            "frozen baseline must not move: {} -> {}",
            learned,
            b.rps.mean
        );
        assert_eq!(b.frozen_ticks, 200);
    }

    #[test]
    fn below_freeze_threshold_learning_continues() {
        let cfg = Config::default();
        let mut b = Baseline::default();
        for _ in 0..200 {
            b.update(&obs(30.0), 5, &cfg);
        }
        for _ in 0..200 {
            b.update(&obs(60.0), 40, &cfg); // ELEVATED but below freeze (50)
        }
        assert!(b.rps.mean > 55.0, "legitimate growth must be learned");
    }

    #[test]
    fn warmup_gates_trust() {
        let cfg = Config::default();
        let mut b = Baseline::default();
        assert!(!b.warm(&cfg));
        for _ in 0..cfg.baseline_warmup_samples {
            b.update(&obs(10.0), 0, &cfg);
        }
        assert!(b.warm(&cfg));
        assert_eq!(b.warmup_pct(&cfg), 100);
    }

    #[test]
    fn hourly_profile_separates_quiet_and_busy_hours() {
        let cfg = Config::default();
        let mut b = Baseline::default();
        for _ in 0..60 {
            b.update(
                &Observation {
                    rps: 5.0,
                    hour: 3,
                    ..Default::default()
                },
                0,
                &cfg,
            );
            b.update(
                &Observation {
                    rps: 90.0,
                    hour: 14,
                    ..Default::default()
                },
                0,
                &cfg,
            );
        }
        assert!(b.expected_rps_at(3) < 20.0);
        assert!(b.expected_rps_at(14) > 60.0);
    }

    #[test]
    fn z_score_ignores_dips() {
        let mut e = Ewma::default();
        for i in 0..300 {
            e.update(50.0 + (i % 5) as f64, 0.05);
        }
        assert_eq!(e.z(10.0, 0.1), 0.0, "a drop is not a surge");
        assert!(e.z(500.0, 0.1) > 10.0);
    }

    #[test]
    fn corrupt_values_are_rejected() {
        let mut b = Baseline::default();
        assert!(b.sane());
        b.rps.mean = f64::NAN;
        assert!(!b.sane());
        b.rps.mean = -1.0;
        assert!(!b.sane());
    }

    #[test]
    fn non_finite_input_is_ignored() {
        let mut e = Ewma::default();
        e.update(10.0, 0.1);
        e.update(f64::INFINITY, 0.1);
        e.update(f64::NAN, 0.1);
        assert_eq!(e.mean, 10.0);
    }
}
