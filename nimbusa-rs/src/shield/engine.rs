//! The shield engine — one background worker that runs the whole pipeline and
//! publishes an immutable snapshot the TUI/CLI read.
//!
//! Threading model: the engine owns all mutable shield state and runs on its
//! own thread. The rest of the program never locks that state; it reads an
//! `Arc<Mutex<ShieldSnapshot>>` that the engine swaps out once per tick. So the
//! render loop can never block on a firewall call, and the firewall can never
//! be touched from the render loop.
use super::accesslog::Tailer;
use super::audit::{self, Auditor};
use super::baseline::{Baseline, Observation};
use super::detect::{self, Assessment};
use super::health::{self, Report};
use super::incident::{self, Incident, Store};
use super::mitigate::{Level, Mitigator, RuleKind};
use super::recovery::{Action, Input, Machine, State as RState};
use super::simulate::{Scenario, Simulation};
use super::telemetry::{self, RawCounters};
use super::window::{TickAgg, Window};
use crate::config::Config;
use crate::util::{epoch, human_bps};
use std::sync::{Arc, Mutex};

/// The read-only view the UI and CLI consume. Cheap to clone; contains no locks.
#[derive(Clone)]
#[allow(dead_code)] // published UI surface; not every field is read by every consumer
pub struct ShieldSnapshot {
    pub enabled: bool,
    pub capable: bool,
    pub enforcing: bool,
    pub assessment: Assessment,
    pub recovery: Machine,
    pub level: Level,
    pub baseline: Baseline,
    pub baseline_warm: bool,
    pub baseline_pct: u32,
    pub active_rules: usize,
    pub blocked_sources: usize,
    pub has_rate_limit: bool,
    pub has_conn_limit: bool,
    pub has_filtering: bool,
    pub has_docker_guard: bool,
    pub health: Report,
    pub current_incident: Option<Incident>,
    pub recent_incidents: Vec<Incident>,
    pub audit_head: String,
    pub audit_records: u64,
    pub audit_verified: bool,
    pub audit_enabled: bool,
    pub anchor_configured: bool,
    pub anchor_state: String,
    pub simulating: Option<Scenario>,
    pub access_log_present: bool,
    pub access_log_parsed: u64,
    pub last_tick: u64,
    pub sample_series_rps: Vec<u64>,
    pub sample_series_bps: Vec<u64>,
    pub sample_series_conn: Vec<u64>,
    pub sample_series_score: Vec<u64>,
    pub uptime_ticks: u64,
    pub notes: Vec<String>,
}

impl Default for ShieldSnapshot {
    fn default() -> Self {
        ShieldSnapshot {
            enabled: true,
            capable: false,
            enforcing: false,
            assessment: Assessment::default(),
            recovery: Machine::default(),
            level: Level::Observe,
            baseline: Baseline::default(),
            baseline_warm: false,
            baseline_pct: 0,
            active_rules: 0,
            blocked_sources: 0,
            has_rate_limit: false,
            has_conn_limit: false,
            has_filtering: false,
            has_docker_guard: false,
            health: Report::default(),
            current_incident: None,
            recent_incidents: vec![],
            audit_head: audit::GENESIS.into(),
            audit_records: 0,
            audit_verified: true,
            audit_enabled: true,
            anchor_configured: false,
            anchor_state: "local only".into(),
            simulating: None,
            access_log_present: false,
            access_log_parsed: 0,
            last_tick: 0,
            sample_series_rps: vec![],
            sample_series_bps: vec![],
            sample_series_conn: vec![],
            sample_series_score: vec![],
            uptime_ticks: 0,
            notes: vec![],
        }
    }
}

/// Commands the UI/CLI post to the running engine.
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)] // ReloadConfig carries a Config by design; commands are rare
pub enum Command {
    Enable,
    Disable,
    Simulate(Scenario),
    StopSimulation,
    ForceRecover,
    ReloadConfig(Config),
    Shutdown,
}

/// Live inputs the engine needs but does not own: domains and container states
/// come from the main snapshot (docker/traefik), refreshed by the UI.
#[derive(Clone, Default)]
pub struct Context {
    pub domains: Vec<String>,
    pub containers: Vec<(String, String)>,
    pub hour: usize,
}

pub struct Shield {
    pub snapshot: Arc<Mutex<ShieldSnapshot>>,
    pub tx: std::sync::mpsc::Sender<Command>,
    pub ctx: Arc<Mutex<Context>>,
}

impl Shield {
    /// Spawn the background engine. Returns a handle whose snapshot the UI reads.
    pub fn spawn(cfg: Config) -> Shield {
        let snapshot = Arc::new(Mutex::new(ShieldSnapshot {
            enabled: cfg.ddos_enabled,
            audit_enabled: cfg.audit_enabled,
            ..Default::default()
        }));
        let ctx = Arc::new(Mutex::new(Context::default()));
        let (tx, rx) = std::sync::mpsc::channel();
        let snap2 = snapshot.clone();
        let ctx2 = ctx.clone();
        std::thread::Builder::new()
            .name("nimbusa-shield".into())
            .spawn(move || {
                let mut engine = Engine::new(cfg, snap2, ctx2, rx);
                engine.run();
            })
            .expect("spawn shield engine");
        Shield { snapshot, tx, ctx }
    }

    pub fn read(&self) -> ShieldSnapshot {
        self.snapshot.lock().unwrap().clone()
    }
    pub fn set_context(
        &self,
        domains: Vec<String>,
        containers: Vec<(String, String)>,
        hour: usize,
    ) {
        let mut c = self.ctx.lock().unwrap();
        c.domains = domains;
        c.containers = containers;
        c.hour = hour;
    }
    pub fn command(&self, c: Command) {
        let _ = self.tx.send(c);
    }
}

struct Engine {
    cfg: Config,
    snap: Arc<Mutex<ShieldSnapshot>>,
    ctx: Arc<Mutex<Context>>,
    rx: std::sync::mpsc::Receiver<Command>,

    win: Window,
    prev_raw: RawCounters,
    baseline: Baseline,
    mitigator: Mitigator,
    recovery: Machine,
    auditor: Auditor,
    tailer: Tailer,
    store: Store,
    current: Option<Incident>,

    sim: Option<Simulation>,
    tick_n: u64,
    last_health: u64,
    health: Report,
    last_baseline_save: u64,
    ser_rps: Vec<u64>,
    ser_bps: Vec<u64>,
    ser_conn: Vec<u64>,
    ser_score: Vec<u64>,
}

const SERIES_LEN: usize = 120;

impl Engine {
    fn new(
        cfg: Config,
        snap: Arc<Mutex<ShieldSnapshot>>,
        ctx: Arc<Mutex<Context>>,
        rx: std::sync::mpsc::Receiver<Command>,
    ) -> Engine {
        let mut tailer = Tailer::new(&cfg.access_log);
        tailer.seek_to_end();
        let mut mitigator = Mitigator::new();
        // reattach to whatever protection survived a restart, and check it is real
        mitigator.installed = mitigator.enforcing();
        let auditor = Auditor::open(cfg.audit_enabled, &cfg.audit_anchor_cmd);
        Engine {
            win: Window::new(cfg.window_seconds.max(60) * 2),
            prev_raw: telemetry::raw(),
            baseline: Baseline::load(),
            mitigator,
            recovery: Machine::default(),
            auditor,
            tailer,
            store: incident::load(),
            current: None,
            sim: None,
            tick_n: 0,
            last_health: 0,
            health: Report::default(),
            last_baseline_save: 0,
            ser_rps: vec![],
            ser_bps: vec![],
            ser_conn: vec![],
            ser_score: vec![],
            cfg,
            snap,
            ctx,
            rx,
        }
    }

    fn run(&mut self) {
        // an initial publish so the UI has something before the first tick lands
        self.publish(&Assessment::default());
        loop {
            let interval = self.cfg.sample_interval_secs.max(1);
            // drain commands, waiting up to one interval for the next one
            match self
                .rx
                .recv_timeout(std::time::Duration::from_secs(interval))
            {
                Ok(Command::Shutdown) => break,
                Ok(c) => {
                    self.handle(c);
                    // keep draining without blocking
                    while let Ok(c) = self.rx.try_recv() {
                        if matches!(c, Command::Shutdown) {
                            return;
                        }
                        self.handle(c);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
            self.tick();
        }
    }

    fn handle(&mut self, c: Command) {
        match c {
            Command::Enable => {
                self.cfg.ddos_enabled = true;
                let o = self.mitigator.install();
                self.mitigator.installed = self.mitigator.enforcing();
                self.note(format!("shield enabled — {}", summarize(&o)));
            }
            Command::Disable => {
                self.cfg.ddos_enabled = false;
                self.mitigator.rollback();
                self.note("shield disabled — automatic rules released".into());
            }
            Command::Simulate(s) => {
                self.sim = Some(Simulation::new(s));
                self.note(format!("SIMULATION started: {}", s.describe()));
            }
            Command::StopSimulation => {
                self.sim = None;
                self.note("simulation stopped".into());
            }
            Command::ForceRecover => {
                let o = self.mitigator.rollback();
                if let Some(inc) = self.current.as_mut() {
                    inc.note("MANUAL_RECOVER", "operator forced rollback", "");
                }
                self.finalize_incident();
                self.recovery = Machine::default();
                self.note(format!("manual recovery — {}", summarize(&o)));
            }
            Command::ReloadConfig(cfg) => {
                self.cfg = cfg;
                self.note("configuration reloaded".into());
            }
            Command::Shutdown => {}
        }
    }

    fn note(&mut self, s: String) {
        let mut snap = self.snap.lock().unwrap();
        if snap.notes.len() >= 8 {
            snap.notes.remove(0);
        }
        snap.notes.push(s);
    }

    fn tick(&mut self) {
        self.tick_n += 1;
        let ctx = self.ctx.lock().unwrap().clone();

        // ---- COLLECT ------------------------------------------------------
        let (raw, mut sample, census) = telemetry::tick(&self.prev_raw);
        self.prev_raw = raw;
        let mut reqs = self.tailer.read_new();

        // ---- SIMULATION overlay (clearly flagged everywhere downstream) ---
        let base_rps = self.baseline.rps.mean;
        let mut sim_census = std::collections::HashMap::new();
        if let Some(sim) = self.sim.as_mut() {
            let (sreqs, ssample) = sim.tick(&sample, base_rps);
            reqs.extend(sreqs);
            sample = ssample;
            sim_census = sim.conn_census();
            // burst finishes on its own after a handful of ticks
            if sim.ticks > sim.ramp_ticks + 8 && sim.scenario == Scenario::Burst {
                self.sim = None;
            }
        }

        // ---- NORMALIZE into the rolling window ----------------------------
        let agg = TickAgg::from_requests(sample.t, &reqs);
        self.win.push(agg, sample.clone());
        self.win.conn_by_source = if sim_census.is_empty() {
            census.by_source
        } else {
            let mut m = census.by_source;
            m.extend(sim_census);
            m
        };
        self.win.internal_by_source = census.internal_by_source;

        // ---- HEALTH (on its own slower cadence) ---------------------------
        if self.cfg.health_enabled
            && epoch().saturating_sub(self.last_health) >= self.cfg.health_interval_secs
        {
            self.health = health::collect(&ctx.domains, &ctx.containers, &self.cfg);
            self.last_health = epoch();
        }

        // ---- DETECT / CLASSIFY / SCORE / EXPLAIN --------------------------
        let assessment = if self.cfg.ddos_enabled {
            detect::assess(&self.win, &self.baseline, &self.health, &self.cfg, ctx.hour)
        } else {
            Assessment::default()
        };

        // ---- BASELINE (attack-aware; frozen while scoring high) -----------
        let obs = Observation {
            rps: assessment.metrics.rps,
            rx_bps: sample.rx_bps,
            tx_bps: sample.tx_bps,
            pps: sample.rx_pps,
            conn_rate: sample.conn_rate,
            established: sample.established as f64,
            sources: assessment.metrics.sources as f64,
            error_rate: assessment.metrics.error_rate,
            latency_ms: assessment.metrics.latency_ms,
            internal_bps: sample.internal_bps,
            internal_conns: sample.internal_conns as f64,
            hour: ctx.hour,
        };
        self.baseline.update(&obs, assessment.score, &self.cfg);

        // ---- RECOVER / MITIGATE (state machine drives actions) ------------
        if self.cfg.ddos_enabled {
            self.drive(&assessment);
        }
        self.mitigator.prune();

        // ---- series for the UI graphs -------------------------------------
        push_series(&mut self.ser_rps, assessment.metrics.rps as u64);
        push_series(&mut self.ser_bps, (sample.rx_bps / 1000.0) as u64);
        push_series(&mut self.ser_conn, sample.established as u64);
        push_series(&mut self.ser_score, assessment.score as u64);

        // periodic persistence (never every tick — atomic writes cost a rename)
        if epoch().saturating_sub(self.last_baseline_save) >= 30 {
            self.baseline.save();
            self.last_baseline_save = epoch();
        }

        self.publish(&assessment);
    }

    /// Run the recovery state machine and execute whatever actions it emits.
    fn drive(&mut self, a: &Assessment) {
        let input = Input {
            now: a.at.max(epoch()),
            score: a.score,
            threat: a.threat,
            attack: a.attack,
            health_ok: matches!(
                self.health.overall(),
                health::State::Healthy | health::State::Unknown
            ),
            health_down: self.health.unavailable() > 0,
        };
        let actions = self.recovery.step(input, &self.cfg);

        for act in actions {
            match act {
                Action::OpenIncident(_) => self.open_incident(a),
                Action::ApplyLevel(level) => self.apply(level, a),
                Action::BeginCooldown => {
                    if let Some(inc) = self.current.as_mut() {
                        inc.recovery_state = "RECOVERY_PENDING".into();
                    }
                    let id = self.current_id().to_string();
                    let h = self
                        .auditor
                        .record(
                            "COOLDOWN",
                            &id,
                            a.threat.as_str(),
                            "cooldown-start",
                            "attack subsiding — cooldown started before rollback",
                        )
                        .map(|r| r.hash)
                        .unwrap_or_default();
                    if let Some(inc) = self.current.as_mut() {
                        inc.note("COOLDOWN", "attack subsiding — cooldown started", &h);
                    }
                }
                Action::Rollback => {
                    let o = self.mitigator.rollback();
                    let id = self.current_id().to_string();
                    let h = self
                        .auditor
                        .record("ROLLBACK", &id, "RECOVERING", "rollback", &summarize(&o))
                        .map(|r| r.hash)
                        .unwrap_or_default();
                    if let Some(inc) = self.current.as_mut() {
                        inc.recovery_state = "RECOVERING".into();
                        inc.note("ROLLBACK", &summarize(&o), &h);
                    }
                }
                Action::CloseIncident => self.finalize_incident(),
            }
        }

        // absorb the worst-case view and keep the live copy's metrics current
        if let Some(inc) = self.current.as_mut() {
            inc.absorb(a);
            inc.downtime_secs = self.recovery.downtime_secs;
            inc.detection_secs = self.recovery.detection_secs();
            inc.mitigation_secs = self.recovery.mitigation_secs();
            inc.max_level = inc.max_level.max(self.recovery.level);
            inc.escalations = self.recovery.escalations;
            inc.recovery_state = self.recovery.state.as_str().into();
            inc.blocked_sources = self.mitigator.blocked_count() as u32;
        }
    }

    fn open_incident(&mut self, a: &Assessment) {
        let day = incident::today();
        let id = incident::next_id(&mut self.store, &day);
        let simulated = self.sim.is_some();
        let mut inc = Incident::open_new(id.clone(), a, simulated);
        inc.services = self
            .ctx
            .lock()
            .unwrap()
            .containers
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        let detail = format!(
            "{} — score {}/100, {} confidence; {}",
            a.attack.as_str(),
            a.score,
            a.confidence.as_str(),
            a.reasons.first().cloned().unwrap_or_default()
        );
        let h = self
            .auditor
            .record(
                "DETECTION",
                &id,
                a.threat.as_str(),
                "open-incident",
                &detail,
            )
            .map(|r| r.hash)
            .unwrap_or_default();
        inc.audit_hash = h.clone();
        inc.note("DETECTION", &detail, &h);
        self.note(format!(
            "{} {} DETECTED — score {} ({})",
            id,
            a.attack.as_str(),
            a.score,
            a.confidence.as_str()
        ));
        self.current = Some(inc);
    }

    fn apply(&mut self, level: Level, a: &Assessment) {
        if level == Level::Observe {
            return;
        }
        let id = self.current_id().to_string();
        let o = self
            .mitigator
            .apply_level(level, &id, &a.suspects, &self.cfg);
        let summary = summarize(&o);
        let h = self
            .auditor
            .record(
                "MITIGATION",
                &id,
                a.threat.as_str(),
                level.as_str(),
                &summary,
            )
            .map(|r| r.hash)
            .unwrap_or_default();
        if let Some(inc) = self.current.as_mut() {
            for line in &o.applied {
                if !inc.mitigations.contains(line) {
                    inc.mitigations.push(line.clone());
                }
            }
            inc.blocked_sources = self.mitigator.blocked_count() as u32;
            inc.note(
                "MITIGATION",
                &format!("{} — {}", level.as_str(), summary),
                &h,
            );
        }
    }

    fn finalize_incident(&mut self) {
        if let Some(mut inc) = self.current.take() {
            inc.recovery_secs = self.recovery.recovery_secs();
            inc.downtime_secs = self.recovery.downtime_secs;
            inc.peak_score = inc.peak_score.max(self.recovery.peak_score);
            inc.close(epoch());
            let detail = format!(
                "duration {}, downtime {}s, availability {:.3}%, detection {}s, mitigation {}s, recovery {}s",
                crate::util::dur_str(inc.duration_secs),
                inc.downtime_secs,
                inc.availability_pct(),
                inc.detection_secs,
                inc.mitigation_secs,
                inc.recovery_secs
            );
            let h = self
                .auditor
                .record("RECOVERY", &inc.id, "NORMAL", "close-incident", &detail)
                .map(|r| r.hash)
                .unwrap_or_default();
            inc.note("RECOVERY", &detail, &h);
            inc.audit_hash = self.auditor.head().to_string();
            self.note(format!(
                "{} RESOLVED — {} downtime, {:.2}% availability",
                inc.id,
                inc.downtime_secs,
                inc.availability_pct()
            ));
            self.store.incidents.push(inc);
            incident::save(&self.store);
            // downtime accounting resets for the next episode
            self.recovery.downtime_secs = 0;
        }
    }

    fn current_id(&self) -> &str {
        self.current.as_ref().map(|i| i.id.as_str()).unwrap_or("-")
    }

    fn publish(&mut self, a: &Assessment) {
        let v = audit::verify_path(&self.auditor.local.path);
        let anchor_state = match self.auditor.anchor.as_ref() {
            None => "local hash chain only".to_string(),
            Some(an) if an.failures > 0 => {
                format!(
                    "anchored {} · {} failures (protection unaffected)",
                    an.anchored, an.failures
                )
            }
            Some(an) => format!("anchored {} heads", an.anchored),
        };
        let recent: Vec<Incident> = self
            .store
            .incidents
            .iter()
            .rev()
            .take(20)
            .cloned()
            .collect();
        let active = self.mitigator.active();
        let snap = ShieldSnapshot {
            enabled: self.cfg.ddos_enabled,
            capable: self.mitigator.capable,
            enforcing: self.mitigator.enforcing(),
            level: self.mitigator.level(),
            active_rules: active.len(),
            blocked_sources: self.mitigator.blocked_count(),
            has_rate_limit: self.mitigator.has(RuleKind::RateLimit),
            has_conn_limit: self.mitigator.has(RuleKind::ConnLimit),
            has_filtering: self.mitigator.has(RuleKind::BlockIp)
                || self.mitigator.has(RuleKind::BlockNet),
            has_docker_guard: self.mitigator.capable
                && crate::util::run("iptables", &["-S", "DOCKER-USER"]).contains(mitigate_chain()),
            recovery: self.recovery.clone(),
            baseline_warm: self.baseline.warm(&self.cfg),
            baseline_pct: self.baseline.warmup_pct(&self.cfg),
            baseline: self.baseline.clone(),
            health: self.health.clone(),
            current_incident: self.current.clone(),
            recent_incidents: recent,
            audit_head: v.head.clone(),
            audit_records: v.records,
            audit_verified: v.ok,
            audit_enabled: self.cfg.audit_enabled,
            anchor_configured: self
                .auditor
                .anchor
                .as_ref()
                .map(|a| a.configured())
                .unwrap_or(false),
            anchor_state,
            simulating: self.sim.as_ref().map(|s| s.scenario),
            access_log_present: self.tailer.present,
            access_log_parsed: self.tailer.parsed,
            last_tick: a.at.max(epoch()),
            sample_series_rps: self.ser_rps.clone(),
            sample_series_bps: self.ser_bps.clone(),
            sample_series_conn: self.ser_conn.clone(),
            sample_series_score: self.ser_score.clone(),
            uptime_ticks: self.tick_n,
            notes: self.snap.lock().unwrap().notes.clone(),
            assessment: a.clone(),
        };
        *self.snap.lock().unwrap() = snap;
    }
}

fn mitigate_chain() -> &'static str {
    super::mitigate::CHAIN
}

fn push_series(v: &mut Vec<u64>, x: u64) {
    v.push(x);
    if v.len() > SERIES_LEN {
        v.remove(0);
    }
}

fn summarize(o: &super::mitigate::Outcome) -> String {
    let mut parts = Vec::new();
    if !o.applied.is_empty() {
        parts.push(format!("applied: {}", o.applied.join(", ")));
    }
    if !o.skipped.is_empty() {
        let n = o.skipped.len();
        parts.push(format!("{} skipped", n));
    }
    if !o.failed.is_empty() {
        parts.push(format!("failed: {}", o.failed.join(", ")));
    }
    if parts.is_empty() {
        "no change".into()
    } else {
        parts.join("; ")
    }
}

/// One-line human status used by the CLI `ddos status`.
pub fn status_line(s: &ShieldSnapshot) -> String {
    format!(
        "score {}/100 {} · {} · {} req/s (baseline {:.1}) · {} · {}",
        s.assessment.score,
        s.assessment.threat.as_str(),
        s.recovery.state.as_str(),
        s.assessment.metrics.rps as u64,
        s.assessment.metrics.rps_base,
        human_bps(s.assessment.metrics.rx_bps),
        if s.enforcing {
            "ENFORCING"
        } else if s.capable {
            "ready"
        } else {
            "observe-only"
        }
    )
}

/// The dashboard "PROTECTED / NORMAL / …" line.
pub fn posture(s: &ShieldSnapshot) -> (&'static str, &'static str) {
    if !s.enabled {
        return ("DISABLED", "shield is turned off");
    }
    match s.recovery.state {
        RState::Normal | RState::Anomaly => {
            if s.enforcing {
                ("PROTECTED", "monitoring · enforcement path armed")
            } else if s.capable {
                (
                    "READY",
                    "monitoring · run `nimbusa ddos enable` to arm enforcement",
                )
            } else {
                ("OBSERVING", "monitoring · not privileged to enforce")
            }
        }
        RState::RecoveryPending | RState::Recovering | RState::HealthVerification => (
            "RECOVERING",
            "attack subsided · verifying health before rollback",
        ),
        _ => ("UNDER ATTACK", "active mitigation in progress"),
    }
}
