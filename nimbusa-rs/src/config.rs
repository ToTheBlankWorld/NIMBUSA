//! NIMBUSA configuration — /etc/nimbusa/config.toml
//!
//! A deliberately small TOML subset (sections + `key = value`, values are
//! bare numbers, booleans or quoted strings). That keeps the binary
//! dependency-free and makes every knob explainable in one screen. Anything
//! the file does not set keeps the documented default, so a missing or
//! partially-corrupt config never stops the shield from running.
use crate::paths;
use std::collections::HashMap;
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    // [ddos]
    pub ddos_enabled: bool,
    /// Seconds between telemetry samples (the shield engine tick).
    pub sample_interval_secs: u64,

    // [detection]
    pub window_seconds: u64,
    pub score_elevated: u32,
    pub score_suspicious: u32,
    pub score_attack: u32,
    pub score_critical: u32,
    /// Minimum requests/sec before request-rate signals can fire at all — stops
    /// a jump from 0.2 to 4 req/s (a 20x ratio) reading as an attack.
    pub min_rps_for_signal: f64,
    /// Endpoint share (0-1) above which concentration counts as abnormal.
    pub endpoint_concentration: f64,
    /// Share of sources (0-1) that must look alike for "coordinated".
    pub behavior_similarity: f64,

    // [baseline]
    /// EWMA smoothing factor for the slow baseline (0-1, smaller = slower).
    pub baseline_alpha: f64,
    /// Samples required before the baseline is trusted for scoring.
    pub baseline_warmup_samples: u64,
    /// Above this score the baseline freezes so an attack cannot poison it.
    pub baseline_freeze_score: u32,

    // [mitigation]
    pub mitigation_enabled: bool,
    /// Requests/min per source above which a source is a mitigation candidate.
    pub source_rpm_threshold: f64,
    /// TTL for automatically-added firewall entries.
    pub block_ttl_secs: u64,
    /// Hard ceiling on simultaneously auto-blocked sources (blast-radius limit).
    pub max_auto_blocks: usize,
    /// Per-source connection limit installed at mitigation level 4+.
    pub connlimit: u32,

    // [recovery]
    pub recovery_enabled: bool,
    /// Consecutive healthy samples required before rollback starts.
    pub recovery_healthy_samples: u32,
    pub cooldown_secs: u64,

    // [health]
    pub health_enabled: bool,
    pub health_interval_secs: u64,
    pub health_timeout_secs: u64,
    /// Latency (ms) above which a healthy service is called DEGRADED.
    pub health_degraded_ms: u64,

    // [audit]
    pub audit_enabled: bool,
    /// Optional external anchor command (receives the chain head on stdin).
    /// Empty = local hash chain only. The shield never depends on this.
    pub audit_anchor_cmd: String,

    // [traefik]
    pub access_log: String,
    pub traefik_container: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ddos_enabled: true,
            sample_interval_secs: 5,

            window_seconds: 60,
            score_elevated: 30,
            score_suspicious: 50,
            score_attack: 70,
            score_critical: 85,
            min_rps_for_signal: 3.0,
            endpoint_concentration: 0.60,
            behavior_similarity: 0.55,

            baseline_alpha: 0.05,
            baseline_warmup_samples: 60,
            baseline_freeze_score: 50,

            mitigation_enabled: true,
            source_rpm_threshold: 600.0,
            block_ttl_secs: 300,
            max_auto_blocks: 512,
            connlimit: 40,

            recovery_enabled: true,
            recovery_healthy_samples: 6,
            cooldown_secs: 60,

            health_enabled: true,
            health_interval_secs: 20,
            health_timeout_secs: 5,
            health_degraded_ms: 1500,

            audit_enabled: true,
            audit_anchor_cmd: String::new(),

            access_log: "/var/log/traefik/access.log".into(),
            traefik_container: String::new(),
        }
    }
}

/// One parsed `section.key = value` pair table.
fn parse_pairs(src: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut section = String::new();
    for raw in src.lines() {
        let line = match raw.split_once('#') {
            // only strip a comment that is not inside a quoted value
            Some((before, _)) if before.matches('"').count() % 2 == 0 => before,
            _ => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_lowercase();
            let val = v.trim().trim_matches('"').trim().to_string();
            let full = if section.is_empty() {
                key
            } else {
                format!("{}.{}", section, key)
            };
            out.insert(full, val);
        }
    }
    out
}

pub struct Loaded {
    pub config: Config,
    /// Human-readable problems. Non-fatal: the default is kept for each.
    pub warnings: Vec<String>,
}

impl Config {
    pub fn parse_toml(src: &str) -> Loaded {
        let p = parse_pairs(src);
        let mut c = Config::default();
        let mut w = Vec::new();

        macro_rules! num {
            ($key:expr, $field:ident, $ty:ty) => {
                if let Some(v) = p.get($key) {
                    match v.parse::<$ty>() {
                        Ok(x) => c.$field = x,
                        Err(_) => w.push(format!(
                            "{}: '{}' is not a number — keeping default {}",
                            $key, v, c.$field
                        )),
                    }
                }
            };
        }
        macro_rules! flag {
            ($key:expr, $field:ident) => {
                if let Some(v) = p.get($key) {
                    match v.as_str() {
                        "true" | "yes" | "1" | "on" => c.$field = true,
                        "false" | "no" | "0" | "off" => c.$field = false,
                        _ => w.push(format!(
                            "{}: '{}' is not a boolean — keeping default {}",
                            $key, v, c.$field
                        )),
                    }
                }
            };
        }

        flag!("ddos.enabled", ddos_enabled);
        num!("ddos.sample_interval_secs", sample_interval_secs, u64);

        num!("detection.window_seconds", window_seconds, u64);
        num!("detection.score_elevated", score_elevated, u32);
        num!("detection.score_suspicious", score_suspicious, u32);
        num!("detection.score_threshold", score_attack, u32);
        num!("detection.score_attack", score_attack, u32);
        num!("detection.score_critical", score_critical, u32);
        num!("detection.min_rps_for_signal", min_rps_for_signal, f64);
        num!(
            "detection.endpoint_concentration",
            endpoint_concentration,
            f64
        );
        num!("detection.behavior_similarity", behavior_similarity, f64);

        num!("baseline.alpha", baseline_alpha, f64);
        num!("baseline.warmup_samples", baseline_warmup_samples, u64);
        num!("baseline.freeze_score", baseline_freeze_score, u32);

        flag!("mitigation.enabled", mitigation_enabled);
        num!("mitigation.source_rpm_threshold", source_rpm_threshold, f64);
        num!("mitigation.block_ttl_secs", block_ttl_secs, u64);
        num!("mitigation.max_auto_blocks", max_auto_blocks, usize);
        num!("mitigation.connlimit", connlimit, u32);

        flag!("recovery.enabled", recovery_enabled);
        num!("recovery.healthy_samples", recovery_healthy_samples, u32);
        num!("recovery.cooldown_secs", cooldown_secs, u64);

        flag!("health.enabled", health_enabled);
        num!("health.interval_secs", health_interval_secs, u64);
        num!("health.timeout_secs", health_timeout_secs, u64);
        num!("health.degraded_ms", health_degraded_ms, u64);

        flag!("audit.enabled", audit_enabled);
        if let Some(v) = p.get("audit.anchor_cmd") {
            c.audit_anchor_cmd = v.clone();
        }

        if let Some(v) = p.get("traefik.access_log") {
            c.access_log = v.clone();
        }
        if let Some(v) = p.get("traefik.container") {
            c.traefik_container = v.clone();
        }

        w.extend(c.clamp());
        Loaded {
            config: c,
            warnings: w,
        }
    }

    /// Force every value into a sane range. Returns the corrections made, so
    /// `nimbusa config validate` can report them instead of failing silently.
    pub fn clamp(&mut self) -> Vec<String> {
        let mut w = Vec::new();
        macro_rules! fix {
            ($cond:expr, $field:ident, $to:expr, $msg:expr) => {
                if $cond {
                    self.$field = $to;
                    w.push($msg.to_string());
                }
            };
        }
        fix!(
            self.sample_interval_secs == 0,
            sample_interval_secs,
            5,
            "ddos.sample_interval_secs must be >= 1 — set to 5"
        );
        fix!(
            self.sample_interval_secs > 60,
            sample_interval_secs,
            60,
            "ddos.sample_interval_secs capped at 60"
        );
        fix!(
            self.window_seconds < 10,
            window_seconds,
            10,
            "detection.window_seconds must be >= 10 — set to 10"
        );
        fix!(
            self.window_seconds > 900,
            window_seconds,
            900,
            "detection.window_seconds capped at 900"
        );
        fix!(
            !(0.001..=0.9).contains(&self.baseline_alpha),
            baseline_alpha,
            0.05,
            "baseline.alpha must be in 0.001..0.9 — set to 0.05"
        );
        fix!(
            !(0.0..=1.0).contains(&self.endpoint_concentration),
            endpoint_concentration,
            0.60,
            "detection.endpoint_concentration must be 0..1 — set to 0.60"
        );
        fix!(
            !(0.0..=1.0).contains(&self.behavior_similarity),
            behavior_similarity,
            0.55,
            "detection.behavior_similarity must be 0..1 — set to 0.55"
        );
        fix!(
            self.block_ttl_secs < 30,
            block_ttl_secs,
            30,
            "mitigation.block_ttl_secs must be >= 30 — set to 30"
        );
        fix!(
            self.block_ttl_secs > 86400,
            block_ttl_secs,
            86400,
            "mitigation.block_ttl_secs capped at 86400"
        );
        fix!(
            self.max_auto_blocks == 0,
            max_auto_blocks,
            1,
            "mitigation.max_auto_blocks must be >= 1"
        );
        fix!(
            self.max_auto_blocks > 65536,
            max_auto_blocks,
            65536,
            "mitigation.max_auto_blocks capped at 65536 (ipset maxelem)"
        );
        fix!(
            self.connlimit == 0,
            connlimit,
            40,
            "mitigation.connlimit must be >= 1 — set to 40"
        );
        fix!(
            self.recovery_healthy_samples == 0,
            recovery_healthy_samples,
            1,
            "recovery.healthy_samples must be >= 1"
        );
        fix!(
            self.health_timeout_secs == 0,
            health_timeout_secs,
            5,
            "health.timeout_secs must be >= 1 — set to 5"
        );
        fix!(
            self.health_timeout_secs > 30,
            health_timeout_secs,
            30,
            "health.timeout_secs capped at 30"
        );
        fix!(
            self.min_rps_for_signal < 0.0,
            min_rps_for_signal,
            3.0,
            "detection.min_rps_for_signal must be >= 0"
        );

        // thresholds must be strictly increasing, or a score can never land in a band
        let mut t = [
            self.score_elevated,
            self.score_suspicious,
            self.score_attack,
            self.score_critical,
        ];
        let sorted_ok = t.windows(2).all(|p| p[0] < p[1]) && t[3] <= 100;
        if !sorted_ok {
            t = [30, 50, 70, 85];
            self.score_elevated = t[0];
            self.score_suspicious = t[1];
            self.score_attack = t[2];
            self.score_critical = t[3];
            w.push("detection score thresholds must be strictly increasing and <= 100 — reset to 30/50/70/85".into());
        }
        w
    }

    /// Load from disk; missing file = defaults (and that is not an error).
    pub fn load() -> Loaded {
        match std::fs::read_to_string(paths::config_file()) {
            Ok(s) => Config::parse_toml(&s),
            Err(_) => Loaded {
                config: Config::default(),
                warnings: vec![],
            },
        }
    }

    /// Render the full effective configuration back out as TOML — used to seed
    /// /etc/nimbusa/config.toml on install so every knob is discoverable.
    pub fn to_toml(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# NIMBUSA configuration — see docs/DDOS.md for what each value does."
        );
        let _ = writeln!(
            s,
            "# Values shown are the effective ones; delete a line to fall back to the default.\n"
        );
        let _ = writeln!(
            s,
            "[ddos]\nenabled = {}\nsample_interval_secs = {}\n",
            self.ddos_enabled, self.sample_interval_secs
        );
        let _ = writeln!(s, "[detection]\nwindow_seconds = {}\nscore_elevated = {}\nscore_suspicious = {}\nscore_attack = {}\nscore_critical = {}\nmin_rps_for_signal = {}\nendpoint_concentration = {}\nbehavior_similarity = {}\n",
            self.window_seconds, self.score_elevated, self.score_suspicious, self.score_attack,
            self.score_critical, self.min_rps_for_signal, self.endpoint_concentration, self.behavior_similarity);
        let _ = writeln!(
            s,
            "[baseline]\nalpha = {}\nwarmup_samples = {}\nfreeze_score = {}\n",
            self.baseline_alpha, self.baseline_warmup_samples, self.baseline_freeze_score
        );
        let _ = writeln!(s, "[mitigation]\nenabled = {}\nsource_rpm_threshold = {}\nblock_ttl_secs = {}\nmax_auto_blocks = {}\nconnlimit = {}\n",
            self.mitigation_enabled, self.source_rpm_threshold, self.block_ttl_secs, self.max_auto_blocks, self.connlimit);
        let _ = writeln!(
            s,
            "[recovery]\nenabled = {}\nhealthy_samples = {}\ncooldown_secs = {}\n",
            self.recovery_enabled, self.recovery_healthy_samples, self.cooldown_secs
        );
        let _ = writeln!(
            s,
            "[health]\nenabled = {}\ninterval_secs = {}\ntimeout_secs = {}\ndegraded_ms = {}\n",
            self.health_enabled,
            self.health_interval_secs,
            self.health_timeout_secs,
            self.health_degraded_ms
        );
        let _ = writeln!(
            s,
            "[audit]\nenabled = {}\nanchor_cmd = \"{}\"\n",
            self.audit_enabled, self.audit_anchor_cmd
        );
        let _ = writeln!(
            s,
            "[traefik]\naccess_log = \"{}\"\ncontainer = \"{}\"",
            self.access_log, self.traefik_container
        );
        s
    }

    /// Threat band for a score, using the configured thresholds.
    pub fn band(&self, score: u32) -> Threat {
        if score >= self.score_critical {
            Threat::Critical
        } else if score >= self.score_attack {
            Threat::Attack
        } else if score >= self.score_suspicious {
            Threat::Suspicious
        } else if score >= self.score_elevated {
            Threat::Elevated
        } else {
            Threat::Normal
        }
    }
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize,
)]
pub enum Threat {
    Normal,
    Elevated,
    Suspicious,
    Attack,
    Critical,
}

impl Threat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Threat::Normal => "NORMAL",
            Threat::Elevated => "ELEVATED",
            Threat::Suspicious => "SUSPICIOUS",
            Threat::Attack => "ATTACK",
            Threat::Critical => "CRITICAL",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_self_consistent() {
        let mut c = Config::default();
        assert!(
            c.clamp().is_empty(),
            "shipped defaults must need no clamping"
        );
    }

    #[test]
    fn parses_sections_and_types() {
        let l = Config::parse_toml(
            "[ddos]\nenabled = false\n\n[detection]\nwindow_seconds = 120\nscore_attack = 75\n\n[traefik]\naccess_log = \"/tmp/a.log\"\n",
        );
        assert!(!l.config.ddos_enabled);
        assert_eq!(l.config.window_seconds, 120);
        assert_eq!(l.config.score_attack, 75);
        assert_eq!(l.config.access_log, "/tmp/a.log");
        assert!(l.warnings.is_empty());
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let l = Config::parse_toml("# top\n\n[ddos]\n# comment\nenabled = true  # trailing\n");
        assert!(l.config.ddos_enabled);
        assert!(l.warnings.is_empty());
    }

    #[test]
    fn bad_values_warn_and_keep_default() {
        let l = Config::parse_toml("[detection]\nwindow_seconds = banana\n");
        assert_eq!(l.config.window_seconds, Config::default().window_seconds);
        assert_eq!(l.warnings.len(), 1);
    }

    #[test]
    fn out_of_range_is_clamped_not_fatal() {
        let l = Config::parse_toml("[mitigation]\nblock_ttl_secs = 1\nmax_auto_blocks = 0\n");
        assert_eq!(l.config.block_ttl_secs, 30);
        assert_eq!(l.config.max_auto_blocks, 1);
        assert_eq!(l.warnings.len(), 2);
    }

    #[test]
    fn unordered_thresholds_reset() {
        let l = Config::parse_toml("[detection]\nscore_elevated = 90\nscore_critical = 20\n");
        assert_eq!(l.config.score_elevated, 30);
        assert_eq!(l.config.score_critical, 85);
        assert!(l.warnings.iter().any(|w| w.contains("strictly increasing")));
    }

    #[test]
    fn empty_config_equals_defaults() {
        assert_eq!(Config::parse_toml("").config, Config::default());
    }

    #[test]
    fn round_trips_through_toml() {
        let mut c = Config::default();
        c.window_seconds = 90;
        c.mitigation_enabled = false;
        c.access_log = "/var/log/t/a.log".into();
        assert_eq!(Config::parse_toml(&c.to_toml()).config, c);
    }

    #[test]
    fn bands_follow_thresholds() {
        let c = Config::default();
        assert_eq!(c.band(0), Threat::Normal);
        assert_eq!(c.band(29), Threat::Normal);
        assert_eq!(c.band(30), Threat::Elevated);
        assert_eq!(c.band(50), Threat::Suspicious);
        assert_eq!(c.band(70), Threat::Attack);
        assert_eq!(c.band(85), Threat::Critical);
        assert_eq!(c.band(100), Threat::Critical);
    }
}
