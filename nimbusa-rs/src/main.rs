//! NIMBUSA — Autonomous Cloud DDoS Detection, Mitigation, Recovery & Security
//! Control Center. Entry point: gate/elevate, then CLI or the ratatui TUI.
//!
//! The heavy lifting lives in modules: `system` (host/docker/ssh/users/IP
//! intelligence), `firewall` (permanent ipset/fail2ban), `shield` (the whole
//! DDoS pipeline on its own background thread), `cli`, and the UI files. main.rs
//! owns only the TUI app loop and the base-tab rendering.
mod theme;
mod ui_shield;

use nimbusa::config::Config;
use nimbusa::shield::engine::Command as SC;
use nimbusa::shield::simulate::Scenario;
use nimbusa::shield::Shield;
use nimbusa::system::*;
use nimbusa::util::*;
use nimbusa::{cli, firewall, paths, shield};

use crate::theme::*;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::{self};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::*;

const TABS: [&str; 9] = [
    "Overview", "Shield", "Services", "Domains", "Traffic", "Security", "SSH", "Users", "Settings",
];
// tab indices
const T_OVERVIEW: usize = 0;
const T_SHIELD: usize = 1;
const T_SERVICES: usize = 2;
const T_DOMAINS: usize = 3;
const T_TRAFFIC: usize = 4;
const T_SECURITY: usize = 5;
const T_SSH: usize = 6;
const T_USERS: usize = 7;
const T_SETTINGS: usize = 8;

/// Root-gate + auto-elevation for authorised non-root users (the `nimbusa` group).
fn gate_and_elevate() -> Option<i32> {
    if sh("id -u").trim() == "0" {
        return None;
    }
    let me = sh("id -un");
    if !sh("id -nG")
        .split_whitespace()
        .any(|g| g == paths::ACCESS_GROUP || g == paths::LEGACY_ACCESS_GROUP)
    {
        eprintln!("nimbusa: access is restricted to root and authorised admins.");
        eprintln!(
            "Ask root to grant you access (nimbusa → Settings tab). You ({}) are not authorised.",
            me.trim()
        );
        return Some(1);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bin = if std::path::Path::new(paths::BIN).exists() {
        paths::BIN.to_string()
    } else {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| paths::BIN.to_string())
    };
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(bin).args(&args);
    match cmd.status() {
        Ok(s) => Some(s.code().unwrap_or(0)),
        Err(_) => {
            eprintln!("nimbusa: failed to elevate via sudo — is sudo installed?");
            Some(1)
        }
    }
}

fn main() -> io::Result<()> {
    if let Some(code) = gate_and_elevate() {
        std::process::exit(code);
    }
    // idempotent, non-destructive AVNI -> NIMBUSA migration on every start
    if sh("id -u").trim() == "0" {
        let migrated = paths::migrate_legacy();
        for m in &migrated {
            eprintln!("nimbusa: migrated {}", m);
        }
        // seed a default config the first time
        if !paths::config_file().exists() {
            let _ = write_atomic(&paths::config_file(), &Config::default().to_toml());
        }
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        if args[0] == "__render" {
            render_debug(&args[1..]);
            return Ok(());
        }
        return cli::run(&args);
    }

    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let mut app = App::new();
    let res = run_app(&mut term, &mut app);
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    if let Some(sh) = &app.shield {
        sh.command(SC::Shutdown);
    }
    res
}

// ------------------------------------------------------------------ snapshot
#[derive(Default)]
struct Snapshot {
    ov: Overview,
    svcs: Vec<Svc>,
    doms: Vec<(String, String)>,
    reg: HashMap<String, IpRec>,
    sess: Vec<Sess>,
    users: Vec<UserRow>,
    ssh: SshCfg,
    t_hourly: Vec<(String, u64)>,
    t_daily: Vec<(String, u64)>,
    t_today: String,
    iface: String,
    inventory: Vec<shield::inventory::Service>,
    ban_count: usize,
    bl_count: usize,
    wl_count: usize,
}

fn gather() -> Snapshot {
    let mut s = Snapshot::default();
    std::thread::scope(|sc| {
        let h_ov = sc.spawn(overview);
        let h_dock = sc.spawn(docker_snapshot);
        let h_reg = sc.spawn(reg_update);
        let h_sess = sc.spawn(sessions);
        let h_users = sc.spawn(users_list);
        let h_ssh = sc.spawn(ssh_cfg);
        let h_traf = sc.spawn(|| {
            let i = primary_iface();
            (
                vnstat_full("h", &i),
                vnstat_full("d", &i),
                vnstat_today(),
                i,
            )
        });
        let h_inv = sc.spawn(service_inventory);
        s.ov = h_ov.join().unwrap();
        let (svcs, doms) = h_dock.join().unwrap();
        s.svcs = svcs;
        s.doms = doms;
        s.reg = h_reg.join().unwrap();
        s.sess = h_sess.join().unwrap();
        s.users = h_users.join().unwrap();
        s.ssh = h_ssh.join().unwrap();
        let (th, td, tt, ifc) = h_traf.join().unwrap();
        s.t_hourly = th;
        s.t_daily = td;
        s.t_today = tt;
        s.iface = ifc;
        s.inventory = h_inv.join().unwrap();
    });
    s.ssh.attackers = s.reg.values().filter(|e| e.attempts > 0).count();
    s.ban_count = s.reg.values().filter(|e| e.banned).count();
    s.bl_count = s.reg.values().filter(|e| e.blacklisted).count();
    s.wl_count = s.reg.values().filter(|e| e.whitelisted).count();
    s
}

enum Input {
    None,
    Blacklist,
    Whitelist,
    NewUser,
}

struct App {
    tab: usize,
    sub: usize,
    tw: usize,
    sel: [usize; 9],
    input: Input,
    buf: String,
    status: String,
    ov: Overview,
    svcs: Vec<Svc>,
    doms: Vec<(String, String)>,
    reg: HashMap<String, IpRec>,
    sess: Vec<Sess>,
    users: Vec<UserRow>,
    ssh: SshCfg,
    t_hourly: Vec<(String, u64)>,
    t_daily: Vec<(String, u64)>,
    t_today: String,
    iface: String,
    inventory: Vec<shield::inventory::Service>,
    bl_count: usize,
    ban_count: usize,
    wl_count: usize,
    last: Instant,
    popup: Option<(String, String)>,
    confirm: Option<String>,
    rx: Option<std::sync::mpsc::Receiver<Snapshot>>,
    loading: bool,
    ready: bool,
    boot: Instant,
    shield: Option<Shield>,
    sim_confirm: Option<Scenario>,
}

impl App {
    fn blank() -> Self {
        App {
            tab: 0,
            sub: 0,
            tw: 1,
            sel: [0; 9],
            input: Input::None,
            buf: String::new(),
            status: "NIMBUSA loading… · keys in footer".into(),
            ov: Overview::default(),
            svcs: vec![],
            doms: vec![],
            reg: HashMap::new(),
            sess: vec![],
            users: vec![],
            ssh: SshCfg::default(),
            t_hourly: vec![],
            t_daily: vec![],
            t_today: String::new(),
            iface: String::new(),
            inventory: vec![],
            bl_count: 0,
            ban_count: 0,
            wl_count: 0,
            last: Instant::now() - Duration::from_secs(99),
            popup: None,
            confirm: None,
            rx: None,
            loading: false,
            ready: false,
            boot: Instant::now(),
            shield: None,
            sim_confirm: None,
        }
    }
    fn new() -> Self {
        let mut a = App::blank();
        let cfg = Config::load().config;
        a.shield = Some(Shield::spawn(cfg));
        a.kick();
        a
    }
    fn kick(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(gather());
        });
        self.rx = Some(rx);
        self.loading = true;
    }
    fn poll_data(&mut self) {
        let mut done = false;
        if let Some(rx) = &self.rx {
            if let Ok(s) = rx.try_recv() {
                self.ov = s.ov;
                self.svcs = s.svcs;
                self.doms = s.doms;
                self.reg = s.reg;
                self.sess = s.sess;
                self.users = s.users;
                self.ssh = s.ssh;
                self.t_hourly = s.t_hourly;
                self.t_daily = s.t_daily;
                self.t_today = s.t_today;
                self.iface = s.iface;
                self.inventory = s.inventory;
                self.bl_count = s.bl_count;
                self.ban_count = s.ban_count;
                self.wl_count = s.wl_count;
                self.last = Instant::now();
                done = true;
            }
        }
        if done {
            self.rx = None;
            self.loading = false;
            self.ready = true;
            // feed the shield the latest docker/traefik context
            if let Some(sh) = &self.shield {
                let hour: usize = sh_hour();
                sh.set_context(
                    self.doms.iter().map(|(d, _)| d.clone()).collect(),
                    self.svcs
                        .iter()
                        .map(|s| (s.name.clone(), s.status.clone()))
                        .collect(),
                    hour,
                );
            }
        }
    }
    fn rows_security(&self) -> Vec<(String, IpRec)> {
        if self.sub == 6 {
            let mut v: Vec<_> = self
                .reg
                .iter()
                .map(|(k, r)| (k.clone(), r.clone()))
                .collect();
            v.sort_by_key(|(_, r)| Reverse(r.attempts));
            v
        } else {
            reg_filter(&self.reg, self.sub)
        }
    }
    fn sel_mut(&mut self) -> &mut usize {
        &mut self.sel[self.tab]
    }
    fn set_user<F: Fn(&mut UserRow)>(&mut self, name: &str, f: F) {
        if let Some(r) = self.users.iter_mut().find(|x| x.user == name) {
            f(r);
        }
    }
    fn set_ip<F: Fn(&mut IpRec)>(&mut self, ip: &str, f: F) {
        let e = self.reg.entry(ip.to_string()).or_default();
        f(e);
    }
}

fn sh_hour() -> usize {
    sh("date +%H").parse().unwrap_or(12)
}

fn run_app<B: Backend>(term: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        app.poll_data();
        term.draw(|f| ui(f, app))?;
        // Shield tab wants a live feel; the rest can idle
        let poll_ms = if !app.ready {
            80
        } else if app.tab == T_SHIELD || app.tab == T_TRAFFIC {
            250
        } else {
            300
        };
        if event::poll(Duration::from_millis(poll_ms))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                if app.popup.is_some() {
                    app.popup = None;
                    continue;
                }
                if let Some(sc) = app.sim_confirm {
                    match k.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            if let Some(sh) = &app.shield {
                                sh.command(SC::Simulate(sc));
                            }
                            app.status = format!(
                                "SIMULATION started: {} (synthetic, local-only)",
                                sc.as_str()
                            );
                        }
                        _ => app.status = "simulation cancelled".into(),
                    }
                    app.sim_confirm = None;
                    continue;
                }
                if let Some(user) = app.confirm.clone() {
                    match k.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            app.status = del_user(&user);
                            app.kick();
                        }
                        _ => app.status = "delete cancelled".into(),
                    }
                    app.confirm = None;
                    continue;
                }
                if !matches!(app.input, Input::None) {
                    handle_input(app, k.code);
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Right | KeyCode::Tab => app.tab = (app.tab + 1) % TABS.len(),
                    KeyCode::Left | KeyCode::BackTab => {
                        app.tab = (app.tab + TABS.len() - 1) % TABS.len()
                    }
                    KeyCode::Char(c @ '1'..='9') => {
                        let i = c as usize - '1' as usize;
                        if i < TABS.len() {
                            app.tab = i;
                        }
                    }
                    KeyCode::Char('r') => {
                        app.status = "refreshing…".into();
                        app.kick();
                    }
                    KeyCode::Char('[') if app.tab == T_SECURITY => {
                        app.sub = (app.sub + SUBS.len() - 1) % SUBS.len();
                        app.sel[T_SECURITY] = 0;
                    }
                    KeyCode::Char(']') if app.tab == T_SECURITY => {
                        app.sub = (app.sub + 1) % SUBS.len();
                        app.sel[T_SECURITY] = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.tab == T_TRAFFIC {
                            app.tw = (app.tw + 1) % 3;
                        } else {
                            *app.sel_mut() += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k')
                        if app.tab != T_SECURITY && app.tab != T_SSH =>
                    {
                        if app.tab == T_TRAFFIC {
                            app.tw = (app.tw + 2) % 3;
                        } else {
                            let s = app.sel_mut();
                            if *s > 0 {
                                *s -= 1;
                            }
                        }
                    }
                    KeyCode::Up => {
                        let s = app.sel_mut();
                        if *s > 0 {
                            *s -= 1;
                        }
                    }
                    _ => action(app, k.code, k.modifiers),
                }
                clamp(app);
            }
        }
        if matches!(app.input, Input::None)
            && app.popup.is_none()
            && app.confirm.is_none()
            && app.sim_confirm.is_none()
            && app.rx.is_none()
            && app.last.elapsed() > Duration::from_secs(10)
        {
            app.kick();
        }
    }
}

fn handle_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => {
            if !app.buf.is_empty() {
                let val = app.buf.trim().to_string();
                match app.input {
                    Input::Whitelist => {
                        app.status = firewall::whitelist_add(&val);
                        app.wl_count += 1;
                        if let Some(ip) = valid_ip(&val) {
                            app.set_ip(&ip, |e| {
                                e.whitelisted = true;
                                e.banned = false;
                                e.blacklisted = false;
                            });
                        }
                    }
                    Input::NewUser => app.status = create_user(&val),
                    _ => {
                        app.status = firewall::blacklist_add(&val);
                        app.bl_count += 1;
                        if let Some(ip) = valid_ip(&val) {
                            app.set_ip(&ip, |e| e.blacklisted = true);
                        }
                    }
                }
                app.kick();
            }
            app.input = Input::None;
            app.buf.clear();
        }
        KeyCode::Esc => {
            app.input = Input::None;
            app.buf.clear();
            app.status = "cancelled".into();
        }
        KeyCode::Backspace => {
            app.buf.pop();
        }
        KeyCode::Char(c) if c.is_ascii() && !c.is_control() => app.buf.push(c),
        _ => {}
    }
}

fn clamp(app: &mut App) {
    let n = match app.tab {
        T_SERVICES => app.svcs.len(),
        T_DOMAINS => app.doms.len(),
        T_SECURITY => app.rows_security().len(),
        T_SSH => app.sess.len(),
        T_USERS | T_SETTINGS => app.users.len(),
        _ => 0,
    };
    let s = &mut app.sel[app.tab];
    if n == 0 {
        *s = 0;
    } else if *s >= n {
        *s = n - 1;
    }
}

fn action(app: &mut App, code: KeyCode, _m: KeyModifiers) {
    match app.tab {
        T_SHIELD => shield_action(app, code),
        T_SERVICES => {
            if let Some(s) = app.svcs.get(app.sel[T_SERVICES]).cloned() {
                match code {
                    KeyCode::Char('x') => {
                        run("docker", &["stop", s.name.as_str()]);
                        app.kick();
                        app.status = format!("stopped {}", s.name);
                    }
                    KeyCode::Char('s') => {
                        run("docker", &["start", s.name.as_str()]);
                        app.kick();
                        app.status = format!("started {}", s.name);
                    }
                    KeyCode::Char('R') => {
                        run("docker", &["restart", s.name.as_str()]);
                        app.kick();
                        app.status = format!("restarted {}", s.name);
                    }
                    KeyCode::Char('l') => {
                        app.popup = Some((
                            format!("logs {}", s.name),
                            run("docker", &["logs", "--tail", "60", s.name.as_str()]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        T_DOMAINS => {
            if let Some((d, c)) = app.doms.get(app.sel[T_DOMAINS]).cloned() {
                if let KeyCode::Enter = code {
                    let url = format!("https://{}/", d);
                    let code_s = run(
                        "curl",
                        &["-s", "-m8", "-o", "/dev/null", "-w", "%{http_code}", &url],
                    );
                    let cert = sh(&format!(
                        "echo | timeout 6 openssl s_client -servername {} -connect {}:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null",
                        d, d
                    ));
                    app.popup = Some((
                        format!("domain {}", d),
                        format!("backend  {}\nHTTP     {}\n{}", c, code_s, cert),
                    ));
                }
            }
        }
        T_SECURITY => sec_action(app, code),
        T_SSH => {
            if let Some(s) = app.sess.get(app.sel[T_SSH]).cloned() {
                match code {
                    KeyCode::Char('k') => {
                        app.status = kick_session(&s);
                        app.kick();
                    }
                    KeyCode::Char('K') => {
                        let r = kick_session(&s);
                        let b = firewall::blacklist_add(&s.from);
                        app.status = format!("{} + {}", r, b);
                        app.kick();
                    }
                    _ => {}
                }
            }
        }
        T_USERS => users_action(app, code),
        T_SETTINGS => {
            if let Some(u) = app.users.get(app.sel[T_SETTINGS]).cloned() {
                match code {
                    KeyCode::Char('g') => {
                        app.status = grant_access(&u.user);
                        if !app.status.starts_with("refused") {
                            app.set_user(&u.user, |r| r.access = true);
                        }
                        app.kick();
                    }
                    KeyCode::Char('x') | KeyCode::Char('u') => {
                        app.status = revoke_access(&u.user);
                        if !app.status.starts_with("refused") {
                            app.set_user(&u.user, |r| r.access = false);
                        }
                        app.kick();
                    }
                    KeyCode::Enter => {
                        app.popup =
                            Some((format!("activity · {}", u.user), user_activity(&u.user)));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn shield_action(app: &mut App, code: KeyCode) {
    let sh = match &app.shield {
        Some(s) => s,
        None => return,
    };
    match code {
        KeyCode::Char('e') => {
            sh.command(SC::Enable);
            app.status = "shield: enforcement armed".into();
        }
        KeyCode::Char('d') => {
            sh.command(SC::Disable);
            app.status = "shield: automatic rules released".into();
        }
        KeyCode::Char('R') => {
            sh.command(SC::ForceRecover);
            app.status = "shield: manual recovery — rollback requested".into();
        }
        KeyCode::Char('x') => {
            sh.command(SC::StopSimulation);
            app.status = "simulation stopped".into();
        }
        KeyCode::Char('h') => app.sim_confirm = Some(Scenario::HttpFlood),
        KeyCode::Char('b') => app.sim_confirm = Some(Scenario::Burst),
        KeyCode::Char('D') => app.sim_confirm = Some(Scenario::Distributed),
        KeyCode::Char('c') => app.sim_confirm = Some(Scenario::Connection),
        KeyCode::Char('i') => app.sim_confirm = Some(Scenario::Internal),
        KeyCode::Char('f') => app.sim_confirm = Some(Scenario::Surge),
        KeyCode::Enter => {
            let s = sh.read();
            if let Some(inc) = s
                .current_incident
                .clone()
                .or_else(|| s.recent_incidents.first().cloned())
            {
                app.popup = Some((format!("incident {}", inc.id), incident_report(&inc)));
            } else {
                let a = &s.assessment;
                let mut body = format!(
                    "DDOS RISK SCORE {}/100  ·  {}\nATTACK  {}\nCONFIDENCE  {}\n\nREASONS:\n",
                    a.score,
                    a.threat.as_str(),
                    a.attack.as_str(),
                    a.confidence.as_str()
                );
                for r in &a.reasons {
                    body.push_str(&format!("  + {}\n", r));
                }
                if let Some(d) = &a.damped {
                    body.push_str(&format!("\nFALSE-POSITIVE DAMPING:\n  {}\n", d));
                }
                app.popup = Some(("NIMBUSA SHIELD — current assessment".into(), body));
            }
        }
        _ => {}
    }
}

fn incident_report(i: &shield::incident::Incident) -> String {
    let mut s = format!(
        "attack       {}\nseverity     {} (peak {})\nstarted      {}\nduration     {}\npeak req/s   {:.0}\npeak in      {}\nsources      {} ({} nets)\ntarget       {} {}\nblocked      {} sources\ndetection    {}s\nmitigation   {}s\nrecovery     {}s\ndowntime     {}s\navailability {:.3}%\naudit        {}\n\nWHY DETECTED:\n",
        i.attack.as_str(), i.severity.as_str(), i.peak_score, i.started_time,
        dur_str(i.duration_secs), i.peak_rps, human_bps(i.peak_bps), i.source_count, i.network_count,
        i.target_domain, i.target_endpoint, i.blocked_sources, i.detection_secs, i.mitigation_secs,
        i.recovery_secs, i.downtime_secs, i.availability_pct(), i.audit_hash.chars().take(24).collect::<String>()
    );
    for r in &i.reasons {
        s.push_str(&format!("  + {}\n", r));
    }
    s.push_str("\nMITIGATION:\n");
    for m in &i.mitigations {
        s.push_str(&format!("  ✓ {}\n", m));
    }
    s
}

fn sec_action(app: &mut App, code: KeyCode) {
    let rows = app.rows_security();
    let ip = rows.get(app.sel[T_SECURITY]).map(|(i, _)| i.clone());
    match code {
        KeyCode::Char('[') => {
            app.sub = (app.sub + SUBS.len() - 1) % SUBS.len();
            app.sel[T_SECURITY] = 0;
        }
        KeyCode::Char(']') => {
            app.sub = (app.sub + 1) % SUBS.len();
            app.sel[T_SECURITY] = 0;
        }
        KeyCode::Char('a') => {
            app.input = Input::Blacklist;
            app.buf.clear();
            app.status = "BLACKLIST: type IP/CIDR/domain then Enter (Esc cancels)".into();
        }
        KeyCode::Char('A') => {
            app.input = Input::Whitelist;
            app.buf.clear();
            app.status = "WHITELIST: type IP/CIDR/domain then Enter (Esc cancels)".into();
        }
        KeyCode::Char('b') => {
            if let Some(ip) = ip {
                app.status = firewall::ban(&ip);
                app.set_ip(&ip, |e| e.banned = true);
                app.ban_count += 1;
                app.kick();
            }
        }
        KeyCode::Char('B') => {
            if let Some(ip) = ip {
                app.status = firewall::blacklist_add(&ip);
                app.set_ip(&ip, |e| e.blacklisted = true);
                app.bl_count += 1;
                app.kick();
            }
        }
        KeyCode::Char('W') => {
            if let Some(ip) = ip {
                app.status = firewall::whitelist_add(&ip);
                app.set_ip(&ip, |e| {
                    e.whitelisted = true;
                    e.banned = false;
                    e.blacklisted = false;
                });
                app.wl_count += 1;
                app.kick();
            }
        }
        KeyCode::Char('u') => {
            if let Some(ip) = ip {
                if app.reg.get(&ip).map(|e| e.whitelisted).unwrap_or(false) {
                    app.status = firewall::whitelist_del(&ip);
                    app.set_ip(&ip, |e| e.whitelisted = false);
                    app.wl_count = app.wl_count.saturating_sub(1);
                } else {
                    app.status = firewall::unban(&ip);
                    app.set_ip(&ip, |e| {
                        e.banned = false;
                        e.blacklisted = false;
                    });
                    app.ban_count = app.ban_count.saturating_sub(1);
                }
                app.kick();
            }
        }
        KeyCode::Char('w') => {
            if let Some(ip) = ip {
                app.popup = Some((format!("whois {}", ip), firewall::whois_ip(&ip)));
            }
        }
        KeyCode::Char('k') => {
            let s = app.sel_mut();
            if *s > 0 {
                *s -= 1;
            }
        }
        KeyCode::Enter => {
            if let Some(ip) = ip {
                if let Some(e) = app.reg.get(&ip).cloned() {
                    let d = ist_delta_min();
                    app.popup = Some((
                        format!("IP intel {}", ip),
                        format!(
                            "country     {}\nattempts    {}   logins {}\nfirst seen  {}\nlast seen   {}\nbanned {}   blacklisted {}   whitelisted {}\nlast user   {}\norg         {}",
                            e.country, e.attempts, e.logins, with_ist(&e.first, d), with_ist(&e.last, d),
                            e.banned, e.blacklisted, e.whitelisted, e.last_user,
                            firewall::whois_ip(&ip).replace('\n', " · ")
                        ),
                    ));
                }
            }
        }
        KeyCode::Char('g') => {
            app.popup = Some((
                "Permanent blacklist".into(),
                firewall::blacklist_list()
                    .iter()
                    .map(|x| format!("{}  {}", x, geo(x.split('/').next().unwrap_or(x))))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
        }
        _ => {}
    }
}

fn users_action(app: &mut App, code: KeyCode) {
    if let KeyCode::Char('N') = code {
        app.input = Input::NewUser;
        app.buf.clear();
        app.status = "NEW USER: type  username  (or  username password)  then Enter".into();
        return;
    }
    if let Some(u) = app.users.get(app.sel[T_USERS]).cloned() {
        let is_root = u.uid == "0" || u.user == "root";
        match code {
            KeyCode::Char('L') => {
                if is_root {
                    app.status = "refused: cannot lock root".into();
                } else {
                    run("usermod", &["-L", u.user.as_str()]);
                    app.set_user(&u.user, |r| r.locked = true);
                    app.status = format!("locked {}", u.user);
                    app.kick();
                }
            }
            KeyCode::Char('U') => {
                run("usermod", &["-U", u.user.as_str()]);
                app.set_user(&u.user, |r| r.locked = false);
                app.status = format!("unlocked {}", u.user);
                app.kick();
            }
            KeyCode::Char('G') => {
                app.status = grant_sudo(&u.user);
                app.set_user(&u.user, |r| r.sudo = true);
                app.kick();
            }
            KeyCode::Char('g') => {
                if is_root {
                    app.status = "refused: cannot revoke root's sudo".into();
                } else {
                    app.status = revoke_sudo(&u.user);
                    app.set_user(&u.user, |r| {
                        r.sudo = false;
                        r.access = false;
                    });
                    app.kick();
                }
            }
            KeyCode::Char('D') => {
                if is_root {
                    app.status = "refused: cannot delete root".into();
                } else {
                    app.confirm = Some(u.user.clone());
                }
            }
            KeyCode::Enter => {
                app.popup = Some((format!("activity · {}", u.user), user_activity(&u.user)));
            }
            _ => {}
        }
    }
}

// ------------------------------------------------------------------ UI
fn ui(f: &mut Frame, app: &mut App) {
    let area = f.size();
    if !app.ready {
        splash(f, area, app);
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);
    let titles: Vec<Line> = TABS
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!(" {}.{} ", i + 1, t)))
        .collect();
    // shield threat colour bleeds into the title bar so posture is glanceable
    let title_txt = shield_title(app);
    let tabs = Tabs::new(titles)
        .select(app.tab)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    title_txt,
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ))
                .border_style(Style::default().fg(CREAM)),
        )
        .highlight_style(
            Style::default()
                .fg(INK)
                .bg(CREAM)
                .add_modifier(Modifier::BOLD),
        )
        .divider("·");
    f.render_widget(tabs, chunks[0]);
    match app.tab {
        T_OVERVIEW => ov_tab(f, chunks[1], app),
        T_SHIELD => {
            if let Some(sh) = &app.shield {
                ui_shield::render(f, chunks[1], &sh.read());
            }
        }
        T_SERVICES => svc_tab(f, chunks[1], app),
        T_DOMAINS => dom_tab(f, chunks[1], app),
        T_TRAFFIC => traffic_tab(f, chunks[1], app),
        T_SECURITY => sec_tab(f, chunks[1], app),
        T_SSH => ssh_tab(f, chunks[1], app),
        T_USERS => users_tab(f, chunks[1], app),
        T_SETTINGS => settings_tab(f, chunks[1], app),
        _ => {}
    }
    let status_line = Line::from(vec![Span::styled(
        format!(" {} ", app.status),
        Style::default()
            .fg(INK)
            .bg(CREAM)
            .add_modifier(Modifier::BOLD),
    )]);
    f.render_widget(Paragraph::new(status_line), chunks[2]);
    let mut keys: Vec<(&str, &str)> = match app.tab {
        T_OVERVIEW => vec![],
        T_SHIELD => vec![
            ("↵", "detail"),
            ("e", "enable"),
            ("d", "disable"),
            ("R", "recover"),
            ("h/b/D/c/i/f", "simulate"),
            ("x", "stop sim"),
        ],
        T_SERVICES => vec![
            ("s", "start"),
            ("x", "stop"),
            ("R", "restart"),
            ("l", "logs"),
        ],
        T_DOMAINS => vec![("↵", "detail")],
        T_TRAFFIC => vec![("↑↓", "window")],
        T_SECURITY => vec![
            ("[ ]", "sub-tab"),
            ("a", "+blacklist"),
            ("A", "+whitelist"),
            ("b", "ban"),
            ("B", "blacklist"),
            ("W", "whitelist"),
            ("u", "un-do"),
            ("w", "whois"),
            ("↵", "detail"),
        ],
        T_SSH => vec![("k", "kick"), ("K", "kick+block")],
        T_USERS => vec![
            ("↵", "activity"),
            ("N", "new"),
            ("G", "+sudo"),
            ("g", "-sudo"),
            ("L", "lock"),
            ("U", "unlock"),
            ("D", "delete"),
        ],
        T_SETTINGS => vec![("g", "grant"), ("x", "revoke"), ("↵", "activity")],
        _ => vec![],
    };
    keys.extend_from_slice(&[
        ("1-9/⇄", "tabs"),
        ("↑↓", "move"),
        ("r", "refresh"),
        ("q", "quit"),
    ]);
    let mut spans: Vec<Span> = vec![Span::raw(" ")];
    for (k, label) in keys {
        spans.push(Span::styled(
            format!(" {} ", k),
            Style::default()
                .fg(INK)
                .bg(CREAM)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {}", label),
            Style::default().fg(CREAM),
        ));
        spans.push(Span::styled("  ", Style::default()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[3]);

    modals(f, app, area);
}

fn shield_title(app: &App) -> String {
    if let Some(sh) = &app.shield {
        let s = sh.read();
        let (posture, _) = shield::engine::posture(&s);
        format!(
            " NIMBUSA · SHIELD {} · score {}/100 {} ",
            posture,
            s.assessment.score,
            s.assessment.threat.as_str()
        )
    } else {
        " NIMBUSA · Cloud Security Control Center ".into()
    }
}

fn modals(f: &mut Frame, app: &App, area: Rect) {
    if !matches!(app.input, Input::None) {
        let (title, accent, note, example) = match app.input {
            Input::Whitelist => (
                " ADD TO WHITELIST ",
                Color::Green,
                "Whitelisted IPs can NEVER be banned, blacklisted, or auto-blocked by the shield.",
                "    e.g.  45.148.10.183   ·   10.0.0.0/24   ·   trusted.host.com",
            ),
            Input::NewUser => (
                " CREATE NEW USER ",
                Color::Cyan,
                "Creates a Linux account with its own /home and a bash shell.",
                "    e.g.  alice          ·   alice S3cret-pw   (username [password])",
            ),
            _ => (
                " ADD TO BLACKLIST ",
                Color::Red,
                "Blacklisted IPs are dropped at the firewall (host + Docker), permanently.",
                "    e.g.  45.148.10.183   ·   10.0.0.0/24   ·   badhost.com",
            ),
        };
        let r = centered_abs(66, 8, area);
        f.render_widget(Clear, r);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                title,
                Style::default()
                    .fg(INK)
                    .bg(accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(accent));
        let inner = block.inner(r);
        f.render_widget(block, r);
        let lines = vec![
            Line::from(Span::styled(note, Style::default().fg(Color::Gray))),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  ❯ ",
                    Style::default().fg(accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    app.buf.clone(),
                    Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
                ),
                Span::styled("▌", Style::default().fg(accent)),
            ]),
            Line::from(Span::styled(example, Style::default().fg(Color::DarkGray))),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    " Enter ",
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" confirm    ", Style::default().fg(CREAM)),
                Span::styled(
                    " Esc ",
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" cancel", Style::default().fg(CREAM)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines), inner);
    }
    if let Some(sc) = app.sim_confirm {
        let r = centered_abs(66, 9, area);
        f.render_widget(Clear, r);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " START LOCAL SIMULATION ",
                Style::default()
                    .fg(INK)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::Magenta));
        let inner = block.inner(r);
        f.render_widget(block, r);
        let lines = vec![
            Line::from(vec![
                Span::styled("  scenario: ", Style::default().fg(CREAM)),
                Span::styled(
                    sc.as_str(),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                format!("  {}", sc.describe()),
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Injects SYNTHETIC telemetry into the local detector only.",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                "  No traffic is sent to anyone. Watch the score climb, then recover.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  y ",
                    Style::default()
                        .fg(INK)
                        .bg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" start     ", Style::default().fg(CREAM)),
                Span::styled(
                    " any other key ",
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" cancel", Style::default().fg(CREAM)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines), inner);
    }
    if let Some(user) = app.confirm.clone() {
        let r = centered_abs(60, 9, area);
        f.render_widget(Clear, r);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                " DELETE USER ",
                Style::default()
                    .fg(INK)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(Style::default().fg(Color::Red));
        let inner = block.inner(r);
        f.render_widget(block, r);
        let lines = vec![
            Line::from(vec![
                Span::styled("  Delete account ", Style::default().fg(CREAM)),
                Span::styled(
                    user.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" ?", Style::default().fg(CREAM)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  The /home directory and files are KEPT (account only).",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  y ",
                    Style::default()
                        .fg(INK)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" yes, delete     ", Style::default().fg(CREAM)),
                Span::styled(
                    " any other key ",
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" cancel", Style::default().fg(CREAM)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines), inner);
    }
    if let Some((title, body)) = app.popup.clone() {
        let h = (body.lines().count() as u16 + 4)
            .min(area.height.saturating_sub(2))
            .max(6);
        let r = centered_abs(82, h, area);
        f.render_widget(Clear, r);
        f.render_widget(
            Paragraph::new(body).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        format!(" {} ", title),
                        Style::default()
                            .fg(INK)
                            .bg(CREAM)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .title(
                        block::Title::from(Span::styled(
                            " any key to close ",
                            Style::default().fg(Color::Gray),
                        ))
                        .position(block::Position::Bottom)
                        .alignment(Alignment::Right),
                    )
                    .border_style(Style::default().fg(CREAM)),
            ),
            r,
        );
    }
}

fn gauge(f: &mut Frame, area: Rect, label: &str, ratio: f64, text: String) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(9), Constraint::Min(10)])
        .split(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            label,
            Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
        )),
        cols[0],
    );
    let col = if ratio < 0.7 {
        Color::Green
    } else if ratio < 0.9 {
        Color::Yellow
    } else {
        Color::Red
    };
    let g = LineGauge::default()
        .gauge_style(Style::default().fg(col).bg(Color::DarkGray))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(text);
    f.render_widget(g, cols[1]);
}

fn ov_tab(f: &mut Frame, area: Rect, app: &App) {
    let o = &app.ov;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);
    let info = format!(
        "Host    {}   {}\nOS      {} · {}\nUptime  {}\nTime    {}   ·   {} (your time)\nLoad    {:.2} {:.2} {:.2}   ·   {} cpus",
        o.host, o.ip, o.os, o.kernel, o.uptime, o.time, o.ist, o.load[0], o.load[1], o.load[2], o.ncpu
    );
    f.render_widget(
        Paragraph::new(info).style(Style::default().fg(Color::White)),
        rows[0],
    );
    gauge(
        f,
        rows[1],
        "Load ",
        o.load[0] / o.ncpu.max(1.0),
        format!("{:.2}/{}", o.load[0], o.ncpu),
    );
    gauge(
        f,
        rows[2],
        "Memory",
        o.mem_used as f64 / o.mem_total.max(1) as f64,
        format!("{}/{} MB", o.mem_used, o.mem_total),
    );
    gauge(
        f,
        rows[3],
        "Disk ",
        o.disk_pct as f64 / 100.0,
        format!("{}% ({}/{})", o.disk_pct, o.disk_used, o.disk_size),
    );
    let up = app
        .svcs
        .iter()
        .filter(|s| s.status.starts_with("Up"))
        .count();
    let line = format!(
        "Services {}/{} up   Domains {}   Banned {}   Blacklist {}   Tracked IPs {}",
        up,
        app.svcs.len(),
        app.doms.len(),
        app.ban_count,
        app.bl_count,
        app.reg.len()
    );
    f.render_widget(
        Paragraph::new(line).style(Style::default().fg(CREAM)),
        rows[4],
    );
    // shield one-liner on the overview so the SOC posture is visible immediately
    if let Some(sh) = &app.shield {
        let s = sh.read();
        let (posture, note) = shield::engine::posture(&s);
        let tcol = match s.assessment.threat.as_str() {
            "CRITICAL" | "ATTACK" => Color::Red,
            "SUSPICIOUS" | "ELEVATED" => Color::Yellow,
            _ => Color::Green,
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " NIMBUSA SHIELD ",
                    Style::default()
                        .fg(INK)
                        .bg(CREAM)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {} ", posture),
                    Style::default()
                        .fg(INK)
                        .bg(tcol)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {}", shield::engine::status_line(&s)),
                    Style::default().fg(CREAM),
                ),
                Span::styled(format!("   ({})", note), Style::default().fg(Color::Gray)),
            ])),
            rows[5],
        );
    }
    let mut att: Vec<u64> = app
        .reg
        .values()
        .filter(|e| e.attempts > 0)
        .map(|e| e.attempts)
        .collect();
    att.sort_by(|a, b| b.cmp(a));
    att.truncate(40);
    let spk = Sparkline::default()
        .block(Block::default().title(Span::styled(
            "SSH attack pressure (top source IPs)",
            Style::default().fg(Color::Red),
        )))
        .data(&att)
        .style(Style::default().fg(Color::Red));
    f.render_widget(spk, rows[6]);
}

fn table_widget<'a>(
    header: Vec<&'a str>,
    rows: Vec<Row<'a>>,
    widths: Vec<Constraint>,
    sel: usize,
    title: String,
) -> (Table<'a>, TableState) {
    let mut st = TableState::default();
    st.select(Some(sel));
    let t = Table::new(rows, widths)
        .header(Row::new(header).style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(CREAM)),
        )
        .highlight_style(Style::default().fg(INK).bg(CREAM))
        .highlight_symbol("» ");
    (t, st)
}

fn svc_tab(f: &mut Frame, area: Rect, app: &mut App) {
    let rows: Vec<Row> = app
        .svcs
        .iter()
        .map(|s| {
            let dot = if s.status.starts_with("Up") && !s.status.contains("unhealthy") {
                Span::styled("●", Style::default().fg(Color::Green))
            } else if s.status.contains("unhealthy") {
                Span::styled("●", Style::default().fg(Color::Yellow))
            } else {
                Span::styled("○", Style::default().fg(Color::Red))
            };
            Row::new(vec![
                Cell::from(dot),
                Cell::from(s.name.clone()),
                Cell::from(s.status.clone()),
                Cell::from(s.domain.clone()),
            ])
        })
        .collect();
    let (t, mut st) = table_widget(
        vec!["", "NAME", "STATUS", "DOMAIN"],
        rows,
        vec![
            Constraint::Length(1),
            Constraint::Length(34),
            Constraint::Length(26),
            Constraint::Min(10),
        ],
        app.sel[T_SERVICES],
        format!(" Services ({}) ", app.svcs.len()),
    );
    f.render_stateful_widget(t, area, &mut st);
}

fn dom_tab(f: &mut Frame, area: Rect, app: &mut App) {
    // Unified "Domains & Services": every real listening socket, enriched with
    // docker/traefik metadata where available. Not DNS-only any more.
    if app.inventory.is_empty() {
        let msg = if app.ready {
            "No listening services discovered.\n\nNeeds `ss` (iproute2) or read access to /proc/net/tcp. \
Docker/Traefik metadata is attached when those are present."
        } else {
            "discovering services…"
        };
        f.render_widget(
            Paragraph::new(msg).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Domains & Services ")
                    .border_style(Style::default().fg(CREAM)),
            ),
            area,
        );
        return;
    }
    let rows: Vec<Row> = app
        .inventory
        .iter()
        .map(|s| {
            let domain = if s.domain.is_empty() {
                Span::styled("(no domain)", Style::default().fg(Color::DarkGray))
            } else {
                Span::styled(s.domain.clone(), Style::default().fg(Color::Cyan))
            };
            let service = if !s.container.is_empty() {
                s.container.clone()
            } else if !s.process.is_empty() {
                s.process.clone()
            } else {
                "—".into()
            };
            let proto = if s.app_proto.is_empty() {
                s.proto.clone()
            } else {
                s.app_proto.clone()
            };
            let scope = s.scope();
            let scope_col = if scope == "PUBLIC" {
                Color::Yellow
            } else {
                Color::DarkGray
            };
            let src = match s.source.as_str() {
                "traefik" => Span::styled("TRAEFIK", Style::default().fg(Color::Magenta)),
                "docker" => Span::styled("DOCKER", Style::default().fg(Color::Blue)),
                _ => Span::styled("SOCKET", Style::default().fg(Color::Gray)),
            };
            Row::new(vec![
                Cell::from(domain),
                Cell::from(service),
                Cell::from(s.bind.clone()),
                Cell::from(format!("{}", s.port)),
                Cell::from(proto),
                Cell::from(Span::styled(scope, Style::default().fg(scope_col))),
                Cell::from(src),
            ])
        })
        .collect();
    let (t, mut st) = table_widget(
        vec![
            "DOMAIN", "SERVICE", "ADDRESS", "PORT", "PROTO", "SCOPE", "SOURCE",
        ],
        rows,
        vec![
            Constraint::Min(18),
            Constraint::Length(20),
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
        app.sel[T_DOMAINS],
        format!(" Domains & Services ({}) ", app.inventory.len()),
    );
    f.render_stateful_widget(t, area, &mut st);
}

fn traffic_tab(f: &mut Frame, area: Rect, app: &mut App) {
    // Live, native, vnstat-free: /proc/net/dev per-interface rates straight from
    // the shield engine. Historical (vnstat) is optional and shown below.
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(7), Constraint::Length(12)])
        .split(area);
    live_traffic(f, outer[0], app);
    historical_traffic(f, outer[1], app);
}

fn live_traffic(f: &mut Frame, area: Rect, app: &App) {
    let snap = app.shield.as_ref().map(|s| s.read());
    let ifaces = snap.as_ref().map(|s| s.ifaces.clone()).unwrap_or_default();
    let (rx_tot, tx_tot, pps_tot) = snap
        .as_ref()
        .map(|s| (s.live_rx_bps, s.live_tx_bps, s.live_rx_pps + s.live_tx_pps))
        .unwrap_or((0.0, 0.0, 0.0));
    if ifaces.is_empty() {
        f.render_widget(
            Paragraph::new("live telemetry warming up… (needs one shield tick)").block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" LIVE TRAFFIC (native /proc/net/dev — no vnstat needed) ")
                    .border_style(Style::default().fg(CREAM)),
            ),
            area,
        );
        return;
    }
    let trows: Vec<Row> = ifaces
        .iter()
        .map(|i| {
            let (stat, scol) = if i.up {
                ("ACTIVE", Color::Green)
            } else {
                ("DOWN", Color::DarkGray)
            };
            Row::new(vec![
                Cell::from(i.name.clone()),
                Cell::from(human(i.rx_bytes as f64)),
                Cell::from(human(i.tx_bytes as f64)),
                Cell::from(human_bps(i.rx_bps)),
                Cell::from(human_bps(i.tx_bps)),
                Cell::from(format!("{:.0}/s", i.rx_pps + i.tx_pps)),
                Cell::from(Span::styled(stat, Style::default().fg(scol))),
            ])
        })
        .collect();
    let title = format!(
        " LIVE TRAFFIC — total ↓{} ↑{} · {:.0} pkt/s (native, no vnstat) ",
        human_bps(rx_tot),
        human_bps(tx_tot),
        pps_tot
    );
    let t = Table::new(
        trows,
        vec![
            Constraint::Length(12),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Min(7),
        ],
    )
    .header(
        Row::new(vec![
            "IFACE", "RX", "TX", "RX RATE", "TX RATE", "PKT/S", "STATUS",
        ])
        .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(CREAM)),
    );
    f.render_widget(t, area);
}

fn historical_traffic(f: &mut Frame, area: Rect, app: &App) {
    let win = ["24h", "7d", "30d"][app.tw];
    let vnstat_missing = app.t_today.contains("vnstat not installed") || app.t_hourly.is_empty();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(6)])
        .split(area);
    if vnstat_missing {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("HISTORICAL  ", Style::default().fg(CREAM)),
                Span::styled(
                    "vnstat unavailable — using NIMBUSA live telemetry above",
                    Style::default().fg(Color::Yellow),
                ),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" HISTORICAL BANDWIDTH ")
                    .border_style(Style::default().fg(CREAM)),
            ),
            area,
        );
        return;
    }
    let picker: Vec<Span> = ["24h", "7d", "30d"]
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let st = if i == app.tw {
                Style::default()
                    .fg(INK)
                    .bg(CREAM)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Span::styled(format!(" {} ", w), st)
        })
        .flat_map(|s| vec![s, Span::raw(" ")])
        .collect();
    let mut head = vec![Span::styled(
        "↑↓ ",
        Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
    )];
    head.extend(picker);
    head.push(Span::styled(
        format!(
            "   iface {}   {}",
            if app.iface.is_empty() {
                "…"
            } else {
                &app.iface
            },
            app.t_today
        ),
        Style::default().fg(CREAM),
    ));
    f.render_widget(Paragraph::new(Line::from(head)), rows[0]);
    let full = if app.tw == 0 {
        &app.t_hourly
    } else {
        &app.t_daily
    };
    let take = [24usize, 7, 30][app.tw];
    let start = full.len().saturating_sub(take);
    let slice = &full[start..];
    let bw: u16 = if app.tw == 0 {
        3
    } else if app.tw == 1 {
        9
    } else {
        2
    };
    let bars: Vec<Bar> = slice
        .iter()
        .map(|(l, v)| {
            Bar::default()
                .value(*v)
                .label(Line::from(l.as_str()))
                .text_value(if *v == 0 {
                    "·".into()
                } else {
                    human(*v as f64)
                })
                .style(Style::default().fg(Color::Cyan))
                .value_style(Style::default().fg(INK).bg(Color::Cyan))
        })
        .collect();
    let title = if slice.iter().all(|(_, v)| *v == 0) {
        format!(
            " bandwidth / {} — no data yet (vnstat still collecting) ",
            win
        )
    } else {
        format!(
            " bandwidth / {} (rx+tx per {}) ",
            win,
            if app.tw == 0 { "hour" } else { "day" }
        )
    };
    let bc = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(CREAM)),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(bw)
        .bar_gap(1);
    f.render_widget(bc, rows[1]);
}

fn sec_tab(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);
    let mut subspans: Vec<Span> = vec![Span::styled(
        "[ ] ",
        Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
    )];
    for (i, s) in SUBS.iter().enumerate() {
        let st = if i == app.sub {
            Style::default()
                .fg(INK)
                .bg(CREAM)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        subspans.push(Span::styled(format!(" {} ", s), st));
        subspans.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(subspans)), rows[0]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" banned {} ", app.ban_count),
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!(" blacklist {} ", app.bl_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" whitelist {} ", app.wl_count),
                Style::default().fg(Color::Green),
            ),
            Span::styled(
                format!(" tracked {} ", app.reg.len()),
                Style::default().fg(CREAM),
            ),
        ])),
        rows[1],
    );
    // Live SHIELD firewall / rate-limit / DDoS-ipset state — the real enforcement
    // mechanism, not the SSH registry. Every value comes from the engine.
    let tag = |on: bool| -> Span<'static> {
        if on {
            Span::styled(" ACTIVE ", Style::default().fg(INK).bg(Color::Green))
        } else {
            Span::styled(" READY ", Style::default().fg(INK).bg(Color::DarkGray))
        }
    };
    let sec_line = match app.shield.as_ref().map(|s| s.read()) {
        Some(s) => Line::from(vec![
            Span::styled(
                "SHIELD ",
                Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if s.enforcing {
                    "ENFORCING "
                } else if s.capable {
                    "READY "
                } else {
                    "OBSERVE "
                },
                Style::default().fg(if s.enforcing {
                    Color::Green
                } else {
                    Color::Gray
                }),
            ),
            Span::styled("· DDoS blocked ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} ", s.blocked_sources),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("· rate-limit", Style::default().fg(Color::Gray)),
            tag(s.has_rate_limit),
            Span::styled("· filtering", Style::default().fg(Color::Gray)),
            tag(s.has_filtering),
            Span::styled(
                format!("· {} active rules", s.active_rules),
                Style::default().fg(Color::Gray),
            ),
        ]),
        None => Line::from(Span::styled(
            "SHIELD engine not attached",
            Style::default().fg(Color::DarkGray),
        )),
    };
    f.render_widget(Paragraph::new(sec_line), rows[2]);
    let data = app.rows_security();
    let max = data.first().map(|(_, e)| e.attempts.max(1)).unwrap_or(1);
    let trows: Vec<Row> = data
        .iter()
        .map(|(ip, e)| {
            let stat = status_of(e);
            let col = if e.whitelisted {
                Color::Green
            } else if e.blacklisted || e.banned {
                Color::Red
            } else if e.logins > 0 {
                Color::Cyan
            } else {
                Color::White
            };
            let bw = (24.0 * e.attempts as f64 / max as f64) as usize;
            Row::new(vec![
                Cell::from(ip.clone()),
                Cell::from(e.country.clone()),
                Cell::from(format!("{}", e.attempts)),
                Cell::from(format!("{}", e.logins)),
                Cell::from(Span::styled(
                    stat,
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    "█".repeat(bw),
                    Style::default().fg(Color::Red),
                )),
            ])
        })
        .collect();
    let mut ts = TableState::default();
    ts.select(Some(app.sel[T_SECURITY]));
    let t = Table::new(
        trows,
        vec![
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["IP", "COUNTRY", "ATT", "LOGIN", "STATUS", "ATTEMPTS"])
            .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ({}) ", SUBS[app.sub], data.len()))
            .border_style(Style::default().fg(CREAM)),
    )
    .highlight_style(Style::default().fg(INK).bg(CREAM))
    .highlight_symbol("» ");
    f.render_stateful_widget(t, rows[3], &mut ts);
}

fn ssh_tab(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    let warn = app.ssh.pass == "yes";
    let hdr = format!(
        "PermitRootLogin {}   PasswordAuth {}   Pubkey {}   Port {}\nattacker IPs in logs: {}",
        app.ssh.root, app.ssh.pass, app.ssh.pubkey, app.ssh.port, app.ssh.attackers
    );
    f.render_widget(
        Paragraph::new(hdr)
            .style(Style::default().fg(if warn { Color::Red } else { Color::Green }))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" SSH policy ")
                    .border_style(Style::default().fg(CREAM)),
            ),
        rows[0],
    );
    let trows: Vec<Row> = app
        .sess
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(format!("{}{}", s.user, if s.me { " (you)" } else { "" })),
                Cell::from(s.tty.clone()),
                Cell::from(s.from.clone()),
                Cell::from(s.country.clone()),
                Cell::from(s.since.clone()),
            ])
        })
        .collect();
    let mut ts = TableState::default();
    ts.select(Some(app.sel[T_SSH]));
    let t = Table::new(
        trows,
        vec![
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(16),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["USER", "TTY", "FROM", "COUNTRY", "SINCE"])
            .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " live sessions ({}) — k kick · K kick+blacklist ",
                app.sess.len()
            ))
            .border_style(Style::default().fg(CREAM)),
    )
    .highlight_style(Style::default().fg(INK).bg(CREAM))
    .highlight_symbol("» ");
    f.render_stateful_widget(t, rows[1], &mut ts);
}

fn users_tab(f: &mut Frame, area: Rect, app: &mut App) {
    let trows: Vec<Row> = app
        .users
        .iter()
        .map(|u| {
            let col = if u.locked { Color::Red } else { Color::White };
            Row::new(vec![
                Cell::from(Span::styled(u.user.clone(), Style::default().fg(col))),
                Cell::from(u.uid.clone()),
                Cell::from(if u.sudo { "yes" } else { "-" }),
                Cell::from(format!("{}", u.live)),
                Cell::from(if u.locked { "LOCKED" } else { "-" }),
                Cell::from(if u.key { "yes" } else { "no" }),
                Cell::from(u.last.clone()),
            ])
        })
        .collect();
    let mut ts = TableState::default();
    ts.select(Some(app.sel[T_USERS]));
    let t = Table::new(
        trows,
        vec![
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(4),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec![
            "USER",
            "UID",
            "SUDO",
            "LIVE",
            "LOCK",
            "KEY",
            "LASTLOGIN",
        ])
        .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Users ({}) — N new · G/g sudo · L/U lock · D delete ",
                app.users.len()
            ))
            .border_style(Style::default().fg(CREAM)),
    )
    .highlight_style(Style::default().fg(INK).bg(CREAM))
    .highlight_symbol("» ");
    f.render_stateful_widget(t, area, &mut ts);
}

fn settings_tab(f: &mut Frame, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);
    let granted = app
        .users
        .iter()
        .filter(|u| u.access && u.uid != "0")
        .count();
    let info = Paragraph::new(vec![
        Line::from(Span::styled("  nimbusa — access control", Style::default().fg(CREAM).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  This tool is restricted to root + members of the 'nimbusa' group. Granted users run `nimbusa` and it auto-elevates via sudo.", Style::default().fg(Color::Gray))),
        Line::from(Span::styled("  RULE: a user must be an admin (sudo) FIRST — make them sudo in the Users tab (G), then grant here.", Style::default().fg(Color::Yellow))),
        Line::from(Span::styled(format!("  currently granted (besides root): {}", granted), Style::default().fg(Color::Green))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Settings · who can use nimbusa ").border_style(Style::default().fg(CREAM)));
    f.render_widget(info, rows[0]);
    let trows: Vec<Row> = app
        .users
        .iter()
        .map(|u| {
            let is_root = u.uid == "0";
            let access = if u.access {
                Span::styled(
                    "GRANTED",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("-", Style::default().fg(Color::DarkGray))
            };
            let elig = if is_root {
                Span::styled("root", Style::default().fg(CREAM))
            } else if u.sudo {
                Span::styled("admin — can grant", Style::default().fg(Color::Cyan))
            } else {
                Span::styled("not admin — sudo first", Style::default().fg(Color::Yellow))
            };
            Row::new(vec![
                Cell::from(u.user.clone()),
                Cell::from(u.uid.clone()),
                Cell::from(if u.sudo { "yes" } else { "-" }),
                Cell::from(access),
                Cell::from(elig),
            ])
        })
        .collect();
    let mut ts = TableState::default();
    ts.select(Some(app.sel[T_SETTINGS]));
    let t = Table::new(
        trows,
        vec![
            Constraint::Length(14),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["USER", "UID", "SUDO", "NIMBUSA", "ELIGIBILITY"])
            .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" g grant nimbusa · x revoke · ↵ activity ")
            .border_style(Style::default().fg(CREAM)),
    )
    .highlight_style(Style::default().fg(INK).bg(CREAM))
    .highlight_symbol("» ");
    f.render_stateful_widget(t, rows[1], &mut ts);
}

fn centered_abs(w: u16, h: u16, area: Rect) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn splash(f: &mut Frame, area: Rect, app: &App) {
    f.render_widget(Block::default().style(Style::default().bg(INK)), area);
    let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let ms = app.boot.elapsed().as_millis();
    let sp = frames[(ms / 90) as usize % frames.len()];
    let dots = ".".repeat((ms / 400) as usize % 4);
    let lines = vec![
        Line::from(Span::styled(
            "N I M B U S A",
            Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "CLOUD SECURITY CONTROL CENTER",
            Style::default().fg(CREAM),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "NIMBUSA SHIELD — Autonomous DDoS Detection & Mitigation",
            Style::default().fg(Color::Gray),
        ))
        .alignment(Alignment::Center),
        Line::from(""),
        Line::from(Span::styled(
            format!("{}  arming shield{}", sp, dots),
            Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center),
        Line::from(Span::styled(
            "telemetry · baseline · detection · mitigation · recovery · audit",
            Style::default().fg(Color::DarkGray),
        ))
        .alignment(Alignment::Center),
    ];
    let h = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(h) / 2;
    f.render_widget(
        Paragraph::new(lines),
        Rect {
            x: area.x,
            y,
            width: area.width,
            height: h.min(area.height),
        },
    );
}

/// Headless render for verification without a tty.
/// nimbusa __render <tab 0-8> [modal] [sub 0-6]
fn render_debug(args: &[String]) {
    use ratatui::backend::TestBackend;
    let tab: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let modal = args.get(1).cloned().unwrap_or_default();
    let sub: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut app = App::blank();
    let s = gather();
    app.ov = s.ov;
    app.svcs = s.svcs;
    app.doms = s.doms;
    app.reg = s.reg;
    app.sess = s.sess;
    app.users = s.users;
    app.ssh = s.ssh;
    app.t_hourly = s.t_hourly;
    app.t_daily = s.t_daily;
    app.t_today = s.t_today;
    app.iface = s.iface;
    app.inventory = s.inventory;
    app.bl_count = s.bl_count;
    app.ban_count = s.ban_count;
    app.wl_count = s.wl_count;
    app.ready = true;
    app.tab = tab;
    app.sub = sub;
    app.status = "render-test".into();
    app.shield = Some(Shield::spawn(Config::load().config));
    std::thread::sleep(Duration::from_millis(200));
    match modal.as_str() {
        "blacklist" => {
            app.input = Input::Blacklist;
            app.buf = "45.148.10.183".into();
        }
        "whitelist" => {
            app.input = Input::Whitelist;
            app.buf = "203.0.113.9".into();
        }
        "newuser" => {
            app.input = Input::NewUser;
            app.buf = "alice".into();
        }
        "confirm" => app.confirm = Some("johnny".into()),
        "sim" => app.sim_confirm = Some(Scenario::Distributed),
        "popup" => {
            app.popup = Some((
                "IP intel 1.2.3.4".into(),
                "country India\nattempts 42".into(),
            ))
        }
        "splash" => app.ready = false,
        _ => {}
    }
    let backend = TestBackend::new(120, 40);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| ui(f, &mut app)).unwrap();
    let buf = term.backend().buffer().clone();
    for y in 0..buf.area.height {
        let mut line = String::new();
        for x in 0..buf.area.width {
            line.push_str(buf.get(x, y).symbol());
        }
        println!("{}", line.trim_end());
    }
    if let Some(sh) = &app.shield {
        sh.command(SC::Shutdown);
    }
}
