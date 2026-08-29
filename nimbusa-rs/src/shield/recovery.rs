//! Recovery state machine.
//!
//! The machine is a pure function of (previous state, current observation), so
//! the whole lifecycle is unit-testable without a firewall, and the engine only
//! has to execute the `Action`s it emits.
//!
//! The property that matters most here is that recovery is *earned*: leaving
//! PROTECTED requires a cooldown to elapse AND several consecutive healthy
//! samples AND the score to have come back down. One quiet sample proves
//! nothing — an attacker pausing for five seconds would otherwise get the
//! defences torn down for free.
use super::detect::AttackType;
use super::mitigate::Level;
use crate::config::{Config, Threat};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum State {
    Normal,
    Anomaly,
    AttackDetected,
    Mitigating,
    Protected,
    Escalated,
    RecoveryPending,
    Recovering,
    HealthVerification,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Normal => "NORMAL",
            State::Anomaly => "ANOMALY",
            State::AttackDetected => "ATTACK_DETECTED",
            State::Mitigating => "MITIGATING",
            State::Protected => "PROTECTED",
            State::Escalated => "ESCALATED",
            State::RecoveryPending => "RECOVERY_PENDING",
            State::Recovering => "RECOVERING",
            State::HealthVerification => "HEALTH_VERIFICATION",
        }
    }
    pub fn under_incident(&self) -> bool {
        !matches!(self, State::Normal | State::Anomaly)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Open a new incident record.
    OpenIncident(AttackType),
    /// Apply (or re-apply) mitigation at this level.
    ApplyLevel(Level),
    /// Enter cooldown; nothing is removed yet.
    BeginCooldown,
    /// Remove every automatic rule.
    Rollback,
    /// Incident is over; write the final record.
    CloseIncident,
}

#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub now: u64,
    pub score: u32,
    pub threat: Threat,
    pub attack: AttackType,
    /// Every protected service answering normally.
    pub health_ok: bool,
    /// At least one protected service is not answering at all.
    pub health_down: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Machine {
    pub state: State,
    pub level: u8,
    /// First moment the score left NORMAL for the current episode.
    pub anomaly_at: u64,
    /// Moment the episode was classified as an attack.
    pub detected_at: u64,
    /// Moment the first mitigation was applied.
    pub mitigated_at: u64,
    pub cooldown_started: u64,
    pub recovery_started: u64,
    pub recovered_at: u64,
    pub healthy_streak: u32,
    pub peak_score: u32,
    pub escalations: u32,
    /// Seconds during which a protected service was unavailable in this episode.
    pub downtime_secs: u64,
    last_tick: u64,
    pub changed_at: u64,
}

impl Default for Machine {
    fn default() -> Self {
        Machine {
            state: State::Normal,
            level: 0,
            anomaly_at: 0,
            detected_at: 0,
            mitigated_at: 0,
            cooldown_started: 0,
            recovery_started: 0,
            recovered_at: 0,
            healthy_streak: 0,
            peak_score: 0,
            escalations: 0,
            downtime_secs: 0,
            last_tick: 0,
            changed_at: 0,
        }
    }
}

/// Mitigation level appropriate to a threat band. Health matters: the same
/// score with a service already failing deserves a heavier response.
pub fn level_for(threat: Threat, health_down: bool) -> Level {
    match threat {
        Threat::Normal => Level::Observe,
        Threat::Elevated => Level::RateLimit,
        Threat::Suspicious => Level::SourceScoring,
        Threat::Attack => {
            if health_down {
                Level::Aggressive
            } else {
                Level::Filtering
            }
        }
        Threat::Critical => Level::Emergency,
    }
}

impl Machine {
    /// Detection time: anomaly first seen -> classified as an attack.
    pub fn detection_secs(&self) -> u64 {
        self.detected_at.saturating_sub(self.anomaly_at)
    }
    /// Mitigation time: attack classified -> first rule in place.
    pub fn mitigation_secs(&self) -> u64 {
        self.mitigated_at.saturating_sub(self.detected_at)
    }
    /// Recovery time: cooldown started -> back to NORMAL.
    pub fn recovery_secs(&self) -> u64 {
        self.recovered_at.saturating_sub(self.cooldown_started)
    }

    pub fn reset_episode(&mut self) {
        let downtime = self.downtime_secs;
        *self = Machine {
            downtime_secs: downtime,
            last_tick: self.last_tick,
            ..Machine::default()
        };
        self.downtime_secs = 0;
    }

    fn go(&mut self, s: State, now: u64) {
        if self.state != s {
            self.state = s;
            self.changed_at = now;
        }
    }

    /// Advance one tick. Returns the side effects the engine must perform.
    pub fn step(&mut self, i: Input, cfg: &Config) -> Vec<Action> {
        let mut acts = Vec::new();
        self.peak_score = self.peak_score.max(i.score);

        // measured downtime: seconds elapsed since the previous tick during
        // which something was actually unreachable
        if self.last_tick > 0 && i.health_down && i.now > self.last_tick {
            self.downtime_secs += (i.now - self.last_tick).min(600);
        }
        self.last_tick = i.now;

        if i.health_ok {
            self.healthy_streak = self.healthy_streak.saturating_add(1);
        } else {
            self.healthy_streak = 0;
        }

        let want = level_for(i.threat, i.health_down);

        match self.state {
            State::Normal => {
                if i.threat >= Threat::Elevated {
                    self.anomaly_at = i.now;
                    self.go(State::Anomaly, i.now);
                }
            }
            State::Anomaly => {
                if i.threat >= Threat::Attack && i.attack.is_attack() {
                    self.detected_at = i.now;
                    self.go(State::AttackDetected, i.now);
                    acts.push(Action::OpenIncident(i.attack));
                    acts.push(Action::ApplyLevel(want));
                } else if i.threat == Threat::Normal {
                    self.reset_episode();
                    self.go(State::Normal, i.now);
                } else if want.as_u8() > self.level {
                    // ELEVATED / SUSPICIOUS: rate limiting only, no incident yet
                    acts.push(Action::ApplyLevel(want));
                    self.level = want.as_u8();
                }
            }
            State::AttackDetected => {
                self.mitigated_at = i.now;
                self.level = want.as_u8();
                self.go(State::Mitigating, i.now);
                acts.push(Action::ApplyLevel(want));
            }
            State::Mitigating => {
                if want.as_u8() > self.level {
                    self.escalations += 1;
                    self.level = want.as_u8();
                    self.go(State::Escalated, i.now);
                    acts.push(Action::ApplyLevel(want));
                } else {
                    self.go(State::Protected, i.now);
                }
            }
            State::Escalated => {
                self.go(State::Mitigating, i.now);
            }
            State::Protected => {
                if want.as_u8() > self.level {
                    self.escalations += 1;
                    self.level = want.as_u8();
                    self.go(State::Escalated, i.now);
                    acts.push(Action::ApplyLevel(want));
                } else if i.threat <= Threat::Elevated {
                    self.cooldown_started = i.now;
                    self.go(State::RecoveryPending, i.now);
                    acts.push(Action::BeginCooldown);
                }
            }
            State::RecoveryPending => {
                if !cfg.recovery_enabled {
                    // manual-only recovery: hold protection until an operator acts
                } else if i.threat >= Threat::Attack {
                    // the attack came back during cooldown — no rollback
                    self.escalations += 1;
                    self.level = want.as_u8().max(self.level);
                    self.go(State::Escalated, i.now);
                    acts.push(Action::ApplyLevel(Level::from_u8(self.level)));
                } else {
                    let cooled = i.now.saturating_sub(self.cooldown_started) >= cfg.cooldown_secs;
                    let quiet = i.threat <= Threat::Elevated;
                    let healthy = self.healthy_streak >= cfg.recovery_healthy_samples;
                    if cooled && quiet && healthy {
                        self.recovery_started = i.now;
                        self.go(State::Recovering, i.now);
                        acts.push(Action::Rollback);
                    }
                }
            }
            State::Recovering => {
                self.level = 0;
                self.go(State::HealthVerification, i.now);
            }
            State::HealthVerification => {
                if i.threat >= Threat::Attack {
                    self.escalations += 1;
                    self.level = want.as_u8();
                    self.go(State::Escalated, i.now);
                    acts.push(Action::ApplyLevel(want));
                } else if self.healthy_streak >= cfg.recovery_healthy_samples
                    && i.threat == Threat::Normal
                {
                    self.recovered_at = i.now;
                    acts.push(Action::CloseIncident);
                    self.go(State::Normal, i.now);
                }
            }
        }
        acts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            cooldown_secs: 30,
            recovery_healthy_samples: 3,
            ..Config::default()
        }
    }

    fn input(now: u64, score: u32, attack: AttackType, health_ok: bool) -> Input {
        let c = Config::default();
        Input {
            now,
            score,
            threat: c.band(score),
            attack,
            health_ok,
            health_down: !health_ok,
        }
    }

    /// Drive the machine through a full attack and recovery, collecting actions.
    fn run(m: &mut Machine, cfg: &Config, ticks: &[(u64, u32, AttackType, bool)]) -> Vec<Action> {
        let mut all = Vec::new();
        for (t, s, a, h) in ticks {
            all.extend(m.step(input(*t, *s, *a, *h), cfg));
        }
        all
    }

    #[test]
    fn quiet_box_stays_normal() {
        let c = cfg();
        let mut m = Machine::default();
        let acts = run(
            &mut m,
            &c,
            &[
                (10, 5, AttackType::None, true),
                (15, 12, AttackType::None, true),
            ],
        );
        assert_eq!(m.state, State::Normal);
        assert!(acts.is_empty());
    }

    #[test]
    fn elevated_alone_does_not_open_an_incident() {
        let c = cfg();
        let mut m = Machine::default();
        let acts = run(
            &mut m,
            &c,
            &[
                (10, 35, AttackType::TrafficSurge, true),
                (15, 38, AttackType::TrafficSurge, true),
            ],
        );
        assert_eq!(m.state, State::Anomaly);
        assert!(!acts.iter().any(|a| matches!(a, Action::OpenIncident(_))));
        assert!(acts.contains(&Action::ApplyLevel(Level::RateLimit)));
    }

    #[test]
    fn a_damped_surge_never_becomes_an_incident() {
        let c = cfg();
        let mut m = Machine::default();
        // score is high but the classifier says TRAFFIC SURGE, not an attack
        let acts = run(
            &mut m,
            &c,
            &[
                (10, 49, AttackType::TrafficSurge, true),
                (15, 49, AttackType::TrafficSurge, true),
                (20, 49, AttackType::TrafficSurge, true),
            ],
        );
        assert!(!acts.iter().any(|a| matches!(a, Action::OpenIncident(_))));
        assert_eq!(m.state, State::Anomaly);
    }

    #[test]
    fn full_lifecycle_reaches_protected_then_returns_to_normal() {
        let c = cfg();
        let mut m = Machine::default();
        // anomaly -> attack -> mitigating -> protected
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::TrafficSurge, true),
                (105, 88, AttackType::DistributedHttpFlood, false),
                (110, 90, AttackType::DistributedHttpFlood, false),
                (115, 90, AttackType::DistributedHttpFlood, false),
            ],
        );
        assert_eq!(m.state, State::Protected);
        assert_eq!(m.detection_secs(), 5);
        assert_eq!(m.mitigation_secs(), 5);

        // attack stops
        let acts = run(&mut m, &c, &[(120, 10, AttackType::None, true)]);
        assert_eq!(m.state, State::RecoveryPending);
        assert!(acts.contains(&Action::BeginCooldown));

        // cooldown not finished yet -> no rollback
        let acts = run(&mut m, &c, &[(130, 5, AttackType::None, true)]);
        assert!(!acts.contains(&Action::Rollback));
        assert_eq!(m.state, State::RecoveryPending);

        // cooldown elapsed and three healthy samples seen
        let acts = run(
            &mut m,
            &c,
            &[
                (155, 5, AttackType::None, true),
                (160, 5, AttackType::None, true),
            ],
        );
        assert!(acts.contains(&Action::Rollback));

        let acts = run(
            &mut m,
            &c,
            &[
                (165, 3, AttackType::None, true),
                (170, 3, AttackType::None, true),
                (175, 3, AttackType::None, true),
            ],
        );
        assert!(acts.contains(&Action::CloseIncident));
        assert_eq!(m.state, State::Normal);
        assert!(m.recovery_secs() > 0);
    }

    #[test]
    fn one_quiet_sample_does_not_trigger_rollback() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, false),
                (105, 90, AttackType::HttpFlood, false),
                (110, 90, AttackType::HttpFlood, false),
                (115, 90, AttackType::HttpFlood, false),
            ],
        );
        assert_eq!(m.state, State::Protected);
        // a single quiet tick, then the flood resumes
        let acts = run(
            &mut m,
            &c,
            &[
                (120, 5, AttackType::None, true),
                (125, 92, AttackType::HttpFlood, false),
            ],
        );
        assert!(
            !acts.contains(&Action::Rollback),
            "must not disarm on one sample"
        );
        assert!(m.state == State::Escalated || m.state == State::Mitigating);
    }

    #[test]
    fn attack_returning_during_cooldown_re_escalates() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, false),
                (105, 90, AttackType::HttpFlood, false),
                (110, 90, AttackType::HttpFlood, false),
                (115, 90, AttackType::HttpFlood, false),
                (120, 10, AttackType::None, true),
            ],
        );
        assert_eq!(m.state, State::RecoveryPending);
        let acts = run(&mut m, &c, &[(125, 95, AttackType::HttpFlood, false)]);
        assert!(acts.iter().any(|a| matches!(a, Action::ApplyLevel(_))));
        assert_eq!(m.state, State::Escalated);
        assert!(m.escalations >= 1);
    }

    #[test]
    fn worsening_attack_escalates_the_level() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, true),
                (105, 72, AttackType::HttpFlood, true), // ATTACK + healthy -> L3
                (110, 72, AttackType::HttpFlood, true),
                (115, 72, AttackType::HttpFlood, true),
            ],
        );
        assert_eq!(m.state, State::Protected);
        assert_eq!(m.level, Level::Filtering.as_u8());
        let acts = run(&mut m, &c, &[(120, 96, AttackType::HttpFlood, false)]);
        assert!(acts.contains(&Action::ApplyLevel(Level::Emergency)));
        assert_eq!(m.level, Level::Emergency.as_u8());
    }

    #[test]
    fn unhealthy_app_raises_the_response_level() {
        assert_eq!(level_for(Threat::Attack, false), Level::Filtering);
        assert_eq!(level_for(Threat::Attack, true), Level::Aggressive);
        assert_eq!(level_for(Threat::Critical, false), Level::Emergency);
        assert_eq!(level_for(Threat::Normal, true), Level::Observe);
    }

    #[test]
    fn downtime_is_measured_not_assumed() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, true),
                (105, 90, AttackType::HttpFlood, false),
                (110, 90, AttackType::HttpFlood, false),
                (115, 90, AttackType::HttpFlood, true),
            ],
        );
        // two 5 s intervals ended with the service down
        assert_eq!(m.downtime_secs, 10);
    }

    #[test]
    fn zero_downtime_when_the_app_never_fails() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, true),
                (105, 90, AttackType::HttpFlood, true),
                (110, 90, AttackType::HttpFlood, true),
            ],
        );
        assert_eq!(m.downtime_secs, 0);
    }

    #[test]
    fn recovery_disabled_holds_protection() {
        let mut c = cfg();
        c.recovery_enabled = false;
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, false),
                (105, 90, AttackType::HttpFlood, false),
                (110, 90, AttackType::HttpFlood, false),
                (115, 90, AttackType::HttpFlood, false),
                (120, 3, AttackType::None, true),
            ],
        );
        let acts = run(
            &mut m,
            &c,
            &[
                (200, 3, AttackType::None, true),
                (205, 3, AttackType::None, true),
                (210, 3, AttackType::None, true),
            ],
        );
        assert!(!acts.contains(&Action::Rollback));
        assert_eq!(m.state, State::RecoveryPending);
    }

    #[test]
    fn health_verification_does_not_close_while_the_app_is_still_hurting() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, false),
                (105, 90, AttackType::HttpFlood, false),
                (110, 90, AttackType::HttpFlood, false),
                (115, 90, AttackType::HttpFlood, false),
                (120, 5, AttackType::None, true),
                (155, 5, AttackType::None, true),
                (160, 5, AttackType::None, true),
                (165, 5, AttackType::None, true), // Rollback
            ],
        );
        assert_eq!(m.state, State::HealthVerification);
        let acts = run(
            &mut m,
            &c,
            &[
                (170, 5, AttackType::None, false),
                (175, 5, AttackType::None, false),
            ],
        );
        assert!(!acts.contains(&Action::CloseIncident));
        assert_eq!(m.state, State::HealthVerification);
    }

    #[test]
    fn peak_score_is_retained_for_the_report() {
        let c = cfg();
        let mut m = Machine::default();
        run(
            &mut m,
            &c,
            &[
                (100, 35, AttackType::HttpFlood, true),
                (105, 97, AttackType::HttpFlood, false),
                (110, 60, AttackType::HttpFlood, true),
            ],
        );
        assert_eq!(m.peak_score, 97);
    }
}
