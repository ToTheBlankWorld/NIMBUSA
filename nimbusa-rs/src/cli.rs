//! Scriptable CLI. Every DDoS command reads a live snapshot from a
//! short-lived shield engine, so `nimbusa ddos status` reflects the real
//! detector, not a re-implementation. `--json` is available where a machine is
//! likely to consume the output.
use crate::config::Config;
use crate::firewall;
use crate::shield::engine::{self, Command as SC};
use crate::shield::simulate::Scenario;
use crate::shield::{audit, Shield};
use crate::system::*;
use crate::util::*;
use crate::{config, paths};
use std::io;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn help() {
    println!(
        "NIMBUSA {} — Autonomous Cloud DDoS Detection, Mitigation, Recovery & Security Control Center\n\
\n\
  (no args)                 launch the NIMBUSA SHIELD command center (TUI)\n\
\n\
CONTROL CENTER\n\
  status                    host + service + security summary\n\
  services                  containers, status, domains\n\
  ssh                       sshd policy + live sessions\n\
  users                     system users\n\
  ips [filter]              IP intelligence (attackers|banned|whitelist|new|logins|all)\n\
  attackers [N]             top SSH brute-force sources\n\
  ban|unban <ip>            fail2ban ban/unban\n\
  blacklist [add|del <x>]   permanent firewall blacklist\n\
  whitelist [add|del <x>]   protected whitelist (never auto-blocked)\n\
  geo <ip>                  country of an IP\n\
  health                    application/service health probe\n\
\n\
NIMBUSA SHIELD (ddos)\n\
  ddos status [--json]      live risk score, threat, posture\n\
  ddos score                just the number\n\
  ddos top [--json]         top sources / endpoints / networks now\n\
  ddos why                  full explainable breakdown of the current score\n\
  ddos incidents [--json]   recorded incidents\n\
  ddos incident <id>        one incident report\n\
  ddos baseline             learned normal traffic\n\
  ddos policy               detection thresholds + mitigation policy\n\
  ddos mitigation           active automatic firewall rules\n\
  ddos recover              force rollback of automatic rules now\n\
  ddos enable | disable     arm / disarm the enforcement path\n\
  ddos daemon               run the headless SHIELD engine (used by systemd)\n\
  ddos simulate <kind> [--confirm-local-test] [--duration N]\n\
                            local-only synthetic attack (http-flood|distributed|\n\
                            burst|connection|internal|surge)\n\
  ddos export [file]        export incidents + audit as JSON\n\
\n\
AUDIT\n\
  audit verify              verify the tamper-evident incident chain\n\
  audit head                current chain head hash\n\
  audit log [N]             last N audit records\n\
\n\
CONFIG\n\
  config validate           check /etc/nimbusa/config.toml\n\
  config show               print the effective configuration\n\
  config init               write a default config if none exists\n\
\n\
USER MANAGEMENT\n\
  adduser <u> [pw] · sudo <u> · unsudo <u> · deluser <u> · activity <u>\n\
  access · grant <u> · revoke <u>\n\
\n\
  --help · --version",
        VERSION
    );
}

/// Run one shield tick synchronously and read the result. Used by the CLI so it
/// reflects the real engine without needing the daemon to already run.
fn quick_snapshot(cfg: &Config) -> engine::ShieldSnapshot {
    let shield = Shield::spawn(cfg.clone());
    let (svcs, doms) = docker_snapshot();
    let hour: usize = sh("date +%H").parse().unwrap_or(12);
    shield.set_context(
        doms.iter().map(|(d, _)| d.clone()).collect(),
        svcs.iter()
            .map(|s| (s.name.clone(), s.status.clone()))
            .collect(),
        hour,
    );
    // give the engine two ticks so a sample delta exists
    std::thread::sleep(std::time::Duration::from_millis(400));
    let s = shield.read();
    shield.command(SC::Shutdown);
    s
}

pub fn run(args: &[String]) -> io::Result<()> {
    let loaded = Config::load();
    let cfg = loaded.config;
    match args[0].as_str() {
        "--help" | "-h" | "help" => help(),
        "--version" | "-V" | "version" => println!("NIMBUSA {}", VERSION),

        "status" => {
            let o = overview();
            let s = services();
            let up = s.iter().filter(|x| x.status.starts_with("Up")).count();
            let snap = quick_snapshot(&cfg);
            println!("NIMBUSA {} — {} ({})", VERSION, o.host, o.ip);
            println!(
                "  load {:.2} {:.2} {:.2} · ram {}/{}MB · disk {}%",
                o.load[0], o.load[1], o.load[2], o.mem_used, o.mem_total, o.disk_pct
            );
            println!(
                "  services {}/{} · domains {} · banned {} · blacklist {}",
                up,
                s.len(),
                domains().len(),
                firewall::f2b_count(),
                firewall::blacklist_list().len()
            );
            let (posture, _) = engine::posture(&snap);
            println!("  SHIELD {} · {}", posture, engine::status_line(&snap));
        }
        "services" => {
            for s in services() {
                println!(
                    "  {} {:<34}{:<26}{}",
                    if s.status.starts_with("Up") {
                        "●"
                    } else {
                        "○"
                    },
                    s.name,
                    s.status,
                    s.domain
                );
            }
        }
        "ips" => {
            let last = SUBS.len() - 1;
            let which = args
                .get(1)
                .map(|s| {
                    SUBS.iter()
                        .position(|x| x.eq_ignore_ascii_case(s))
                        .unwrap_or(last)
                })
                .unwrap_or(last);
            let reg = reg_update();
            let rows = if which == last {
                let mut v: Vec<_> = reg.iter().map(|(k, r)| (k.clone(), r.clone())).collect();
                v.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
                v
            } else {
                reg_filter(&reg, which)
            };
            println!(
                "  {} : {} IPs (tracked {})",
                SUBS[which],
                rows.len(),
                reg.len()
            );
            for (ip, e) in rows.iter().take(40) {
                println!(
                    "  {:<16}{:<14}{:>8}{:>6}  {:<10}{}",
                    ip,
                    e.country,
                    e.attempts,
                    e.logins,
                    status_of(e),
                    e.last
                );
            }
        }
        "attackers" => {
            let reg = reg_update();
            let mut v: Vec<_> = reg.iter().filter(|(_, e)| e.attempts > 0).collect();
            v.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
            for (ip, e) in v
                .iter()
                .take(args.get(1).and_then(|n| n.parse().ok()).unwrap_or(15))
            {
                println!("  {:>7} {:<16}{}", e.attempts, ip, e.country);
            }
        }
        "ban" if args.len() > 1 => println!("{}", firewall::ban(&args[1])),
        "unban" if args.len() > 1 => println!("{}", firewall::unban(&args[1])),
        "blacklist" => {
            if args.len() > 2 && args[1] == "add" {
                println!("{}", firewall::blacklist_add(&args[2]));
            } else if args.len() > 2 && args[1] == "del" {
                println!("{}", firewall::blacklist_del(&args[2]));
            } else {
                for x in firewall::blacklist_list() {
                    println!("  {}  {}", x, geo(x.split('/').next().unwrap_or(&x)));
                }
            }
        }
        "whitelist" => {
            if args.len() > 2 && args[1] == "add" {
                println!("{}", firewall::whitelist_add(&args[2]));
            } else if args.len() > 2 && args[1] == "del" {
                println!("{}", firewall::whitelist_del(&args[2]));
            } else {
                for x in firewall::whitelist_list() {
                    println!("  {}  {}", x, geo(x.split('/').next().unwrap_or(&x)));
                }
            }
        }
        "geo" if args.len() > 1 => println!("{}", geo(&args[1])),
        "ssh" => {
            let c = ssh_cfg();
            println!(
                "  root={} pass={} pubkey={} port={}",
                c.root, c.pass, c.pubkey, c.port
            );
            for s in sessions() {
                println!("  {}@{:<8}{:<16}({})", s.user, s.tty, s.from, s.country);
            }
        }
        "users" => {
            for u in users_list() {
                println!(
                    "  {:<12}{:<6} sudo={} live={} lock={} key={} {}",
                    u.user, u.uid, u.sudo, u.live, u.locked, u.key, u.last
                );
            }
        }
        "health" => {
            let (svcs, doms) = docker_snapshot();
            let r = crate::shield::health::collect(
                &doms.iter().map(|(d, _)| d.clone()).collect::<Vec<_>>(),
                &svcs
                    .iter()
                    .map(|s| (s.name.clone(), s.status.clone()))
                    .collect::<Vec<_>>(),
                &cfg,
            );
            println!("  overall: {}", r.overall().as_str());
            for c in &r.checks {
                println!("  {:<28} {:<12} {}", c.name, c.state.as_str(), c.detail);
            }
        }

        "ddos" => return ddos(&args[1..], &cfg),
        "audit" => return audit_cmd(&args[1..]),
        "config" => return config_cmd(&args[1..], &loaded.warnings),

        "adduser" if args.len() > 1 => println!("{}", create_user(&args[1..].join(" "))),
        "sudo" if args.len() > 1 => println!("{}", grant_sudo(&args[1])),
        "unsudo" if args.len() > 1 => println!("{}", revoke_sudo(&args[1])),
        "deluser" if args.len() > 1 => println!("{}", del_user(&args[1])),
        "activity" if args.len() > 1 => println!("{}", user_activity(&args[1])),
        "access" => {
            println!(
                "root\n{}",
                sh(&format!("getent group {}", paths::ACCESS_GROUP))
                    .rsplit(':')
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .filter(|u| !u.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        "grant" if args.len() > 1 => println!("{}", grant_access(&args[1])),
        "revoke" if args.len() > 1 => println!("{}", revoke_access(&args[1])),

        other => {
            println!("nimbusa: unknown command '{}'. Try: nimbusa --help", other);
        }
    }
    Ok(())
}

fn has_flag(args: &[String], f: &str) -> bool {
    args.iter().any(|a| a == f)
}

fn ddos(args: &[String], cfg: &Config) -> io::Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    let json = has_flag(args, "--json");
    match sub {
        "status" => {
            let s = quick_snapshot(cfg);
            if json {
                println!("{}", status_json(&s));
            } else {
                let (posture, note) = engine::posture(&s);
                println!("NIMBUSA SHIELD — {} ({})", posture, note);
                println!("  {}", engine::status_line(&s));
                println!(
                    "  attack: {}   confidence: {}",
                    s.assessment.attack.as_str(),
                    s.assessment.confidence.as_str()
                );
                if !s.baseline_warm {
                    println!("  baseline: learning ({}%)", s.baseline_pct);
                }
                println!(
                    "  mitigation: {} active rule(s), {} sources blocked, level {}",
                    s.active_rules,
                    s.blocked_sources,
                    s.level.as_str()
                );
                if let Some(sc) = s.simulating {
                    println!("  ⚠ SIMULATION ACTIVE: {}", sc.as_str());
                }
            }
        }
        "score" => println!("{}", quick_snapshot(cfg).assessment.score),
        "why" => {
            let s = quick_snapshot(cfg);
            let a = &s.assessment;
            println!(
                "NIMBUSA SHIELD\n\nDDOS RISK SCORE: {}/100\nTHREAT: {}\nATTACK: {}\nCONFIDENCE: {}\n",
                a.score,
                a.threat.as_str(),
                a.attack.as_str(),
                a.confidence.as_str()
            );
            println!("REASONS:");
            for r in &a.reasons {
                println!("  + {}", r);
            }
            if let Some(d) = &a.damped {
                println!("\nFALSE-POSITIVE DAMPING:\n  {}", d);
            }
        }
        "top" => {
            let s = quick_snapshot(cfg);
            let a = &s.assessment;
            if json {
                println!("{}", top_json(a));
            } else {
                println!("TOP SOURCES");
                for (ip, n) in &a.top_sources {
                    println!("  {:<18} {:>8} req   {}", ip, n, geo(ip));
                }
                println!("TOP ENDPOINTS");
                for (ep, n) in &a.top_endpoints {
                    println!("  {:<40} {:>8} req", ep, n);
                }
                println!("TOP NETWORKS");
                for (net, n) in &a.top_networks {
                    println!("  {:<20} {:>8} req", net, n);
                }
            }
        }
        "incidents" => {
            let store = crate::shield::incident::load();
            if json {
                println!("{}", serde_json::to_string_pretty(&store.incidents).unwrap_or_default());
            } else if store.incidents.is_empty() {
                println!("no incidents recorded");
            } else {
                for i in store.incidents.iter().rev().take(30) {
                    println!(
                        "  {}  {:<24} score {:>3} {:<9} {}s down, {:.2}% avail  {}",
                        i.id,
                        i.attack.as_str(),
                        i.peak_score,
                        i.severity.as_str(),
                        i.downtime_secs,
                        i.availability_pct(),
                        if i.simulated { "[SIM]" } else { "" }
                    );
                }
            }
        }
        "incident" if args.len() > 1 => {
            let store = crate::shield::incident::load();
            match store.incidents.iter().find(|i| i.id == args[1]) {
                Some(i) => print_incident(i),
                None => println!("no such incident: {}", args[1]),
            }
        }
        "baseline" => {
            let b = crate::shield::baseline::Baseline::load();
            println!("NIMBUSA SHIELD baseline (samples: {})", b.samples);
            println!("  request rate   {:.2} req/s  ± {:.2}", b.rps.mean, b.rps.sd());
            println!(
                "  inbound        {} ± {}",
                human_bps(b.rx_bps.mean),
                human_bps(b.rx_bps.sd())
            );
            println!("  packets        {:.0}/s ± {:.0}", b.pps.mean, b.pps.sd());
            println!("  conn rate      {:.2}/s ± {:.2}", b.conn_rate.mean, b.conn_rate.sd());
            println!("  established    {:.0} ± {:.0}", b.established.mean, b.established.sd());
            println!("  sources        {:.0} ± {:.0}", b.sources.mean, b.sources.sd());
            println!("  error rate     {:.1}%", b.error_rate.mean * 100.0);
            println!("  latency        {:.0} ms", b.latency_ms.mean);
            println!("  frozen ticks   {} (samples ignored during attacks)", b.frozen_ticks);
        }
        "policy" => {
            println!("NIMBUSA SHIELD policy");
            println!("  detection window     {} s", cfg.window_seconds);
            println!(
                "  score bands          ELEVATED {} · SUSPICIOUS {} · ATTACK {} · CRITICAL {}",
                cfg.score_elevated, cfg.score_suspicious, cfg.score_attack, cfg.score_critical
            );
            println!("  baseline warmup      {} samples, freeze at score {}", cfg.baseline_warmup_samples, cfg.baseline_freeze_score);
            println!("  mitigation           {}", if cfg.mitigation_enabled { "ENABLED" } else { "disabled" });
            println!("  block TTL            {} s", cfg.block_ttl_secs);
            println!("  max auto-blocks      {}", cfg.max_auto_blocks);
            println!("  conn limit           {} per source", cfg.connlimit);
            println!("  recovery             {} healthy samples, {} s cooldown", cfg.recovery_healthy_samples, cfg.cooldown_secs);
            println!("  audit                {}", if cfg.audit_enabled { "ENABLED (hash chain)" } else { "disabled" });
        }
        "mitigation" => {
            let store = crate::shield::mitigate::load_store();
            let now = epoch();
            let active: Vec<_> = store.rules.iter().filter(|r| !r.expired(now)).collect();
            if active.is_empty() {
                println!("no active automatic mitigation");
            } else {
                println!("active NIMBUSA automatic rules (level {}):", store.level);
                for r in active {
                    println!(
                        "  {:<12} {:<20} L{} ttl {:>4}s  {}  [{}]",
                        r.kind.as_str(),
                        r.target,
                        r.level,
                        r.ttl_left(now),
                        r.reason,
                        r.incident_id
                    );
                }
            }
        }
        "recover" => {
            let shield = Shield::spawn(cfg.clone());
            shield.command(SC::ForceRecover);
            std::thread::sleep(std::time::Duration::from_millis(300));
            shield.command(SC::Shutdown);
            println!("forced rollback of automatic rules — permanent rules untouched");
        }
        "enable" => {
            let mut m = crate::shield::mitigate::Mitigator::new();
            let o = m.install();
            println!("shield enforcement: {:?} applied, {:?} failed", o.applied, o.failed);
            // persist enabled=true is a config concern; report capability
            if !m.capable {
                println!("note: not privileged or ipset/iptables missing — observe-only");
            }
        }
        "disable" => {
            let mut m = crate::shield::mitigate::Mitigator::new();
            m.rollback();
            println!("shield automatic rules released (permanent firewall untouched)");
        }
        "daemon" => return daemon(cfg),
        "simulate" if args.len() > 1 => return simulate(&args[1..], cfg),
        "export" => {
            let store = crate::shield::incident::load();
            let v = audit::verify();
            let out = serde_json::json!({
                "product": "NIMBUSA",
                "version": VERSION,
                "exported_at": now_str(),
                "audit": { "verified": v.ok, "records": v.records, "head": v.head },
                "incidents": store.incidents,
            });
            let text = serde_json::to_string_pretty(&out).unwrap_or_default();
            match args.get(1).filter(|a| !a.starts_with("--")) {
                Some(path) => {
                    std::fs::write(path, &text)?;
                    println!("exported to {}", path);
                }
                None => println!("{}", text),
            }
        }
        _ => println!("nimbusa ddos: try status|score|why|top|incidents|incident <id>|baseline|policy|mitigation|recover|enable|disable|simulate <kind>|export"),
    }
    Ok(())
}

/// Headless engine (systemd `nimbusa-shield.service`). Runs the full pipeline
/// forever, refreshing the docker/traefik context every few seconds. It shares
/// /var/lib/nimbusa state with the interactive tool, so `nimbusa ddos status`
/// reflects this process. Never exits on its own; never disables the firewall.
fn daemon(cfg: &Config) -> io::Result<()> {
    println!("NIMBUSA SHIELD daemon starting — {}", now_str());
    let shield = Shield::spawn(cfg.clone());
    let mut last_ctx = 0u64;
    loop {
        let now = epoch();
        // refresh docker/traefik context at most every 15 s (it forks docker)
        if now.saturating_sub(last_ctx) >= 15 {
            let (svcs, doms) = docker_snapshot();
            let hour: usize = sh("date +%H").parse().unwrap_or(12);
            shield.set_context(
                doms.iter().map(|(d, _)| d.clone()).collect(),
                svcs.iter()
                    .map(|s| (s.name.clone(), s.status.clone()))
                    .collect(),
                hour,
            );
            last_ctx = now;
        }
        std::thread::sleep(std::time::Duration::from_secs(
            cfg.sample_interval_secs.max(1),
        ));
    }
}

fn simulate(args: &[String], cfg: &Config) -> io::Result<()> {
    if args[0] == "stop" {
        println!("no persistent simulation to stop from the CLI (use the TUI Shield tab for live control)");
        return Ok(());
    }
    let scenario = match Scenario::parse(&args[0]) {
        Some(s) => s,
        None => {
            println!("unknown scenario '{}'. try: http-flood|distributed|burst|connection|internal|surge", args[0]);
            return Ok(());
        }
    };
    if scenario.needs_confirm() && !has_flag(args, "--confirm-local-test") {
        println!(
            "'{}' is a higher-volume synthetic test. Re-run with --confirm-local-test to proceed.\n(This never sends traffic to anyone — it injects synthetic telemetry into the local detector.)",
            scenario.as_str()
        );
        return Ok(());
    }
    let duration: u64 = args
        .iter()
        .position(|a| a == "--duration")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);

    println!("NIMBUSA SHIELD — LOCAL SIMULATION (synthetic telemetry only)");
    println!("scenario: {}  ({})", scenario.as_str(), scenario.describe());
    println!(
        "running ~{}s — watch the score climb and mitigation engage:\n",
        duration
    );

    let shield = Shield::spawn(cfg.clone());
    let (svcs, doms) = docker_snapshot();
    let hour: usize = sh("date +%H").parse().unwrap_or(12);
    shield.set_context(
        doms.iter().map(|(d, _)| d.clone()).collect(),
        svcs.iter()
            .map(|s| (s.name.clone(), s.status.clone()))
            .collect(),
        hour,
    );
    shield.command(SC::Simulate(scenario));
    let interval = cfg.sample_interval_secs.max(1);
    let steps = (duration / interval).max(6);
    for i in 0..steps {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        let s = shield.read();
        let (posture, _) = engine::posture(&s);
        println!(
            "  t+{:>3}s  score {:>3}/100  {:<10} {:<16} {:<12} rps {:>5}  blocked {}",
            (i + 1) * interval,
            s.assessment.score,
            s.assessment.threat.as_str(),
            s.assessment.attack.as_str(),
            posture,
            s.assessment.metrics.rps as u64,
            s.blocked_sources
        );
        // stop the attack ~2/3 through so recovery is visible
        if i == steps * 2 / 3 {
            shield.command(SC::StopSimulation);
            println!("  --- attack stopped, observing recovery ---");
        }
    }
    let s = shield.read();
    println!("\nfinal posture: {}", engine::posture(&s).0);
    if let Some(inc) = s.recent_incidents.first() {
        println!(
            "incident recorded: {} (nimbusa ddos incident {})",
            inc.id, inc.id
        );
    }
    shield.command(SC::Shutdown);
    Ok(())
}

fn print_incident(i: &crate::shield::incident::Incident) {
    println!(
        "═══ {} ═══{}",
        i.id,
        if i.simulated { "  [SIMULATION]" } else { "" }
    );
    println!("attack        {}", i.attack.as_str());
    println!(
        "severity      {} (peak score {})",
        i.severity.as_str(),
        i.peak_score
    );
    println!("confidence    {}", i.confidence);
    println!("started       {}", i.started_time);
    if !i.ended_time.is_empty() {
        println!("ended         {}", i.ended_time);
    }
    println!("duration      {}", dur_str(i.duration_secs));
    println!("peak req/s    {:.0}", i.peak_rps);
    println!("peak inbound  {}", human_bps(i.peak_bps));
    println!(
        "sources       {}  ({} networks)",
        i.source_count, i.network_count
    );
    println!("target        {} {}", i.target_domain, i.target_endpoint);
    println!("blocked       {} sources", i.blocked_sources);
    println!("detection     {}s", i.detection_secs);
    println!("mitigation    {}s", i.mitigation_secs);
    println!("recovery      {}s", i.recovery_secs);
    println!("downtime      {}s", i.downtime_secs);
    println!("availability  {:.3}%", i.availability_pct());
    println!("recovery      {}", i.recovery_state);
    println!("audit hash    {}", i.audit_hash);
    println!("\nWHY DETECTED:");
    for r in &i.reasons {
        println!("  + {}", r);
    }
    println!("\nMITIGATION:");
    for m in &i.mitigations {
        println!("  ✓ {}", m);
    }
    println!("\nTIMELINE:");
    for e in &i.timeline {
        println!("  {}  {:<12} {}", e.time, e.kind, e.detail);
    }
}

fn audit_cmd(args: &[String]) -> io::Result<()> {
    match args.first().map(|s| s.as_str()).unwrap_or("verify") {
        "verify" => {
            let v = audit::verify();
            if v.ok {
                println!("✓ audit chain VERIFIED — {} records intact", v.records);
                println!("  head: {}", v.head);
            } else {
                println!("✗ audit chain TAMPERED");
                println!("  {}", v.reason);
                if let Some(seq) = v.broken_at {
                    println!("  first broken record: seq {}", seq);
                }
                std::process::exit(2);
            }
        }
        "head" => println!("{}", audit::verify().head),
        "log" => {
            let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            let path = audit::LocalHashChainSink::default_path();
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
                    for l in lines.iter().rev().take(n).rev() {
                        if let Ok(r) = serde_json::from_str::<audit::Record>(l) {
                            println!(
                                "  #{:<4} {}  {:<11} {:<26} {:<9} {}",
                                r.seq, r.time, r.event_type, r.incident_id, r.severity, r.action
                            );
                        }
                    }
                }
                Err(_) => println!("no audit chain yet"),
            }
        }
        _ => println!("nimbusa audit: verify | head | log [N]"),
    }
    Ok(())
}

fn config_cmd(args: &[String], warnings: &[String]) -> io::Result<()> {
    match args.first().map(|s| s.as_str()).unwrap_or("validate") {
        "validate" => {
            let path = paths::config_file();
            if !path.exists() {
                println!(
                    "no config file at {} — defaults in use (all valid)",
                    path.display()
                );
                return Ok(());
            }
            if warnings.is_empty() {
                println!("✓ {} is valid", path.display());
            } else {
                println!("⚠ {} loaded with corrections:", path.display());
                for w in warnings {
                    println!("  - {}", w);
                }
            }
        }
        "show" => print!("{}", config::Config::load().config.to_toml()),
        "init" => {
            let path = paths::config_file();
            if path.exists() {
                println!(
                    "config already exists at {} (not overwritten)",
                    path.display()
                );
            } else {
                let _ = write_atomic(&path, &Config::default().to_toml());
                println!("wrote default config to {}", path.display());
            }
        }
        _ => println!("nimbusa config: validate | show | init"),
    }
    Ok(())
}

// ------------------------------------------------------------------ json out
fn status_json(s: &engine::ShieldSnapshot) -> String {
    let a = &s.assessment;
    serde_json::json!({
        "score": a.score,
        "threat": a.threat.as_str(),
        "attack": a.attack.as_str(),
        "confidence": a.confidence.as_str(),
        "posture": engine::posture(s).0,
        "recovery_state": s.recovery.state.as_str(),
        "enforcing": s.enforcing,
        "capable": s.capable,
        "baseline_warm": s.baseline_warm,
        "baseline_pct": s.baseline_pct,
        "metrics": {
            "rps": a.metrics.rps,
            "rps_baseline": a.metrics.rps_base,
            "rx_bps": a.metrics.rx_bps,
            "sources": a.metrics.sources,
            "networks": a.metrics.networks,
            "established": a.metrics.established,
            "top_endpoint": a.metrics.top_endpoint,
            "top_endpoint_share": a.metrics.top_endpoint_share,
            "error_rate": a.metrics.error_rate,
            "health": a.metrics.health_state,
        },
        "mitigation": {
            "level": s.level.as_str(),
            "active_rules": s.active_rules,
            "blocked_sources": s.blocked_sources,
        },
        "reasons": a.reasons,
        "simulating": s.simulating.map(|x| x.as_str()),
        "audit": { "verified": s.audit_verified, "records": s.audit_records, "head": s.audit_head },
    })
    .to_string()
}

fn top_json(a: &crate::shield::detect::Assessment) -> String {
    serde_json::json!({
        "sources": a.top_sources,
        "endpoints": a.top_endpoints,
        "networks": a.top_networks,
        "user_agents": a.top_uas,
        "suspects": a.suspects,
    })
    .to_string()
}
