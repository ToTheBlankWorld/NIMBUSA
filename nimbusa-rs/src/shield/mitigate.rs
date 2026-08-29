//! Mitigation engine — the part that actually touches the firewall.
//!
//! Two rules govern everything here.
//!
//! 1. **Temporary state is isolated.** Every automatic rule lives in the
//!    `NIMBUSA-DDOS` chain and the `nimbusa_ddos*` ipsets, which nothing else
//!    writes to. Rolling back is a flush of structures NIMBUSA owns, so a
//!    failed or half-applied mitigation can never damage the permanent
//!    blacklist, the whitelist, fail2ban's chains, or Docker's own rules.
//!
//! 2. **Nothing is applied that cannot expire.** Every ipset entry carries a
//!    kernel-side `timeout`, so even if the process is killed mid-incident the
//!    blocks drain by themselves. The recorded rule carries the incident id,
//!    the reason, the level and the expiry so the audit trail explains itself.
use super::detect::Suspect;
use crate::config::Config;
use crate::firewall;
use crate::paths;
use crate::util::{epoch, have, run_status, valid_ip, valid_ip_or_cidr, write_atomic};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// ipset holding individually blocked source addresses (kernel-timed).
pub const DDOS_SET: &str = "nimbusa_ddos";
/// ipset holding blocked networks when a flood is spread across a /24.
pub const DDOS_NET_SET: &str = "nimbusa_ddos_net";
/// The chain that holds every automatic rule. Nothing else writes to it.
pub const CHAIN: &str = "NIMBUSA-DDOS";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum Level {
    Observe = 0,
    RateLimit = 1,
    SourceScoring = 2,
    Filtering = 3,
    Aggressive = 4,
    Emergency = 5,
}

impl Level {
    pub fn from_u8(n: u8) -> Level {
        match n {
            1 => Level::RateLimit,
            2 => Level::SourceScoring,
            3 => Level::Filtering,
            4 => Level::Aggressive,
            5 => Level::Emergency,
            _ => Level::Observe,
        }
    }
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Observe => "L0 OBSERVE",
            Level::RateLimit => "L1 ADAPTIVE RATE LIMIT",
            Level::SourceScoring => "L2 SOURCE SCORING",
            Level::Filtering => "L3 TEMPORARY FILTERING",
            Level::Aggressive => "L4 AGGRESSIVE PROTECTION",
            Level::Emergency => "L5 EMERGENCY PROTECTION",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RuleKind {
    RateLimit,
    ConnLimit,
    SynProtect,
    BlockIp,
    BlockNet,
    DockerGuard,
}

impl RuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleKind::RateLimit => "rate-limit",
            RuleKind::ConnLimit => "conn-limit",
            RuleKind::SynProtect => "syn-protect",
            RuleKind::BlockIp => "block-ip",
            RuleKind::BlockNet => "block-net",
            RuleKind::DockerGuard => "docker-guard",
        }
    }
}

/// One automatic rule, as recorded on disk. Requirement: every automated rule
/// carries incident_id, reason, timestamp, expiration and mitigation level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub incident_id: String,
    pub kind: RuleKind,
    /// IP, CIDR, or "-" for chain-wide rules.
    pub target: String,
    pub reason: String,
    pub level: u8,
    pub created: u64,
    pub expires: u64,
    /// False when the rule was recorded but the firewall refused it (or the
    /// process is not privileged). The UI shows this instead of claiming
    /// protection that does not exist.
    pub applied: bool,
}

impl Rule {
    pub fn expired(&self, now: u64) -> bool {
        self.expires != 0 && now >= self.expires
    }
    pub fn ttl_left(&self, now: u64) -> u64 {
        self.expires.saturating_sub(now)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleStore {
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub level: u8,
    #[serde(default)]
    pub updated: u64,
}

/// Result of one mitigation pass — what changed, and what was refused.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub applied: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
}

#[allow(dead_code)]
impl Outcome {
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty() && self.skipped.is_empty() && self.failed.is_empty()
    }
}

fn is_root() -> bool {
    static R: OnceLock<bool> = OnceLock::new();
    *R.get_or_init(|| crate::util::sh("id -u").trim() == "0")
}

/// Can mitigation actually be enforced on this box right now?
pub fn capable() -> bool {
    is_root() && have("ipset") && have("iptables")
}

fn ipt(args: &[&str]) -> (bool, String) {
    run_status("iptables", args)
}

/// Addresses that must never be auto-blocked, whatever the score says.
/// The operator's own SSH source is in here for the same reason the whitelist
/// is: a DDoS response that locks the operator out of the box has made the
/// incident worse.
pub fn protected_addresses() -> Vec<String> {
    let mut v = firewall::whitelist_list();
    if let Ok(c) = std::env::var("SSH_CLIENT") {
        if let Some(ip) = c.split_whitespace().next().and_then(valid_ip) {
            v.push(ip);
        }
    }
    if let Ok(c) = std::env::var("SSH_CONNECTION") {
        if let Some(ip) = c.split_whitespace().next().and_then(valid_ip) {
            v.push(ip);
        }
    }
    v.push("127.0.0.1".into());
    v.sort();
    v.dedup();
    v
}

/// Whitelist / self-protection check. Returns Some(reason) when the address
/// must be left alone.
pub fn refuse_reason(ip: &str, protected: &[String]) -> Option<String> {
    if !valid_ip_or_cidr(ip) {
        return Some(format!("MITIGATION_SKIPPED_INVALID target '{}'", ip));
    }
    if protected.iter().any(|w| w == ip) {
        return Some(format!("MITIGATION_SKIPPED_WHITELIST {}", ip));
    }
    // a whitelisted /24 protects its members
    if protected
        .iter()
        .any(|w| w.ends_with("/24") && crate::util::slash24(ip) == *w)
    {
        return Some(format!("MITIGATION_SKIPPED_WHITELIST {} (network)", ip));
    }
    if crate::util::is_private(ip) {
        return Some(format!("MITIGATION_SKIPPED_PRIVATE {}", ip));
    }
    None
}

pub struct Mitigator {
    pub store: RuleStore,
    pub capable: bool,
    /// Set once the chain and ipsets exist.
    pub installed: bool,
}

impl Default for Mitigator {
    fn default() -> Self {
        Self::new()
    }
}

impl Mitigator {
    pub fn new() -> Self {
        Mitigator {
            store: load_store(),
            capable: capable(),
            installed: false,
        }
    }

    pub fn level(&self) -> Level {
        Level::from_u8(self.store.level)
    }

    /// Create the ipsets and the chain, and hook the chain into INPUT and
    /// DOCKER-USER. Idempotent — safe to call on every start.
    pub fn install(&mut self) -> Outcome {
        let mut o = Outcome::default();
        if !self.capable {
            o.skipped.push(
                "not privileged or ipset/iptables missing — shield runs in observe-only mode"
                    .into(),
            );
            return o;
        }
        for (set, kind) in [(DDOS_SET, "hash:ip"), (DDOS_NET_SET, "hash:net")] {
            let (ok, err) = run_status(
                "ipset",
                &[
                    "create", set, kind, "family", "inet", "timeout", "300", "hashsize", "4096",
                    "maxelem", "65536", "-exist",
                ],
            );
            if !ok {
                o.failed.push(format!("ipset create {}: {}", set, err));
            }
        }
        // dedicated chain, so rollback never touches anyone else's rules
        let _ = ipt(&["-N", CHAIN]);
        let (_, _) = ipt(&["-F", CHAIN]);
        for parent in ["INPUT", "DOCKER-USER"] {
            if !ipt(&["-L", parent, "-n"]).0 {
                continue; // DOCKER-USER only exists when docker is installed
            }
            if !ipt(&["-C", parent, "-j", CHAIN]).0 {
                let (ok, err) = ipt(&["-I", parent, "1", "-j", CHAIN]);
                if ok {
                    o.applied.push(format!("{} -> {}", parent, CHAIN));
                } else {
                    o.failed.push(format!("hook {}: {}", parent, err));
                }
            }
        }
        // the two drop rules are the permanent floor of the chain; per-entry
        // TTL lives in the ipsets, so these never need to be removed
        for set in [DDOS_SET, DDOS_NET_SET] {
            let (ok, err) = ipt(&[
                "-A",
                CHAIN,
                "-m",
                "set",
                "--match-set",
                set,
                "src",
                "-j",
                "DROP",
            ]);
            if !ok {
                o.failed.push(format!("drop rule for {}: {}", set, err));
            }
        }
        self.installed = o.failed.is_empty();
        if self.installed {
            o.applied
                .push(format!("{} + {} ready", DDOS_SET, DDOS_NET_SET));
        }
        o
    }

    /// Is the enforcement path present right now (not just recorded)?
    pub fn enforcing(&self) -> bool {
        if !self.capable {
            return false;
        }
        crate::util::run("ipset", &["list", "-n"])
            .lines()
            .any(|l| l.trim() == DDOS_SET)
            && crate::util::run("iptables", &["-S", CHAIN]).contains(DDOS_SET)
    }

    fn record(&mut self, r: Rule) {
        self.store
            .rules
            .retain(|x| !(x.kind == r.kind && x.target == r.target));
        self.store.rules.push(r);
    }

    /// Block one source for `ttl` seconds. Returns Err(reason) when refused.
    pub fn block_ip(
        &mut self,
        ip: &str,
        incident: &str,
        reason: &str,
        level: Level,
        ttl: u64,
        protected: &[String],
    ) -> Result<(), String> {
        if let Some(r) = refuse_reason(ip, protected) {
            return Err(r);
        }
        if self
            .store
            .rules
            .iter()
            .filter(|r| r.kind == RuleKind::BlockIp && !r.expired(epoch()))
            .count()
            >= 65_536
        {
            return Err("MITIGATION_SKIPPED_CAP block set full".into());
        }
        let now = epoch();
        let mut applied = false;
        if self.capable {
            let ttl_s = ttl.to_string();
            let (ok, err) =
                run_status("ipset", &["add", DDOS_SET, ip, "timeout", &ttl_s, "-exist"]);
            if !ok {
                return Err(format!("ipset add {}: {}", ip, err));
            }
            applied = true;
        }
        self.record(Rule {
            incident_id: incident.into(),
            kind: RuleKind::BlockIp,
            target: ip.into(),
            reason: reason.into(),
            level: level.as_u8(),
            created: now,
            expires: now + ttl,
            applied,
        });
        Ok(())
    }

    pub fn block_net(
        &mut self,
        net: &str,
        incident: &str,
        reason: &str,
        level: Level,
        ttl: u64,
        protected: &[String],
    ) -> Result<(), String> {
        if !valid_ip_or_cidr(net) {
            return Err(format!("MITIGATION_SKIPPED_INVALID network '{}'", net));
        }
        // never take out a network that contains a protected address
        for p in protected {
            let base = p.split('/').next().unwrap_or(p);
            if crate::util::slash24(base) == net {
                return Err(format!(
                    "MITIGATION_SKIPPED_WHITELIST {} contains protected {}",
                    net, p
                ));
            }
        }
        let now = epoch();
        let mut applied = false;
        if self.capable {
            let ttl_s = ttl.to_string();
            let (ok, err) = run_status(
                "ipset",
                &["add", DDOS_NET_SET, net, "timeout", &ttl_s, "-exist"],
            );
            if !ok {
                return Err(format!("ipset add {}: {}", net, err));
            }
            applied = true;
        }
        self.record(Rule {
            incident_id: incident.into(),
            kind: RuleKind::BlockNet,
            target: net.into(),
            reason: reason.into(),
            level: level.as_u8(),
            created: now,
            expires: now + ttl,
            applied,
        });
        Ok(())
    }

    /// Adaptive per-source rate limiting on the web ports. Tighter at higher
    /// levels; always leaves a burst allowance so ordinary browsing survives.
    pub fn rate_limit(&mut self, incident: &str, level: Level, cfg: &Config) -> Result<(), String> {
        let (rate, burst) = match level {
            Level::Emergency => ("15/second", "30"),
            Level::Aggressive => ("30/second", "60"),
            _ => ("60/second", "120"),
        };
        let now = epoch();
        let mut applied = false;
        if self.capable {
            self.clear_kind_rules(RuleKind::RateLimit);
            for port in ["80", "443"] {
                let name = format!("nimbusa{}", port);
                let (ok, err) = ipt(&[
                    "-I",
                    CHAIN,
                    "1",
                    "-p",
                    "tcp",
                    "--dport",
                    port,
                    "-m",
                    "hashlimit",
                    "--hashlimit-above",
                    rate,
                    "--hashlimit-burst",
                    burst,
                    "--hashlimit-mode",
                    "srcip",
                    "--hashlimit-name",
                    &name,
                    "--hashlimit-htable-expire",
                    "60000",
                    "-j",
                    "DROP",
                ]);
                if !ok {
                    return Err(format!("hashlimit :{}: {}", port, err));
                }
                applied = true;
            }
        }
        self.record(Rule {
            incident_id: incident.into(),
            kind: RuleKind::RateLimit,
            target: "-".into(),
            reason: format!("per-source HTTP(S) rate limit {} burst {}", rate, burst),
            level: level.as_u8(),
            created: now,
            expires: now + cfg.block_ttl_secs.max(120),
            applied,
        });
        Ok(())
    }

    /// Cap simultaneous connections per source address.
    pub fn conn_limit(&mut self, incident: &str, level: Level, cfg: &Config) -> Result<(), String> {
        let n = if level >= Level::Emergency {
            (cfg.connlimit / 2).max(5)
        } else {
            cfg.connlimit
        };
        let now = epoch();
        let mut applied = false;
        if self.capable {
            self.clear_kind_rules(RuleKind::ConnLimit);
            let ns = n.to_string();
            for port in ["80", "443"] {
                let (ok, err) = ipt(&[
                    "-I",
                    CHAIN,
                    "1",
                    "-p",
                    "tcp",
                    "--syn",
                    "--dport",
                    port,
                    "-m",
                    "connlimit",
                    "--connlimit-above",
                    &ns,
                    "--connlimit-mask",
                    "32",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ]);
                if !ok {
                    return Err(format!("connlimit :{}: {}", port, err));
                }
                applied = true;
            }
        }
        self.record(Rule {
            incident_id: incident.into(),
            kind: RuleKind::ConnLimit,
            target: "-".into(),
            reason: format!("max {} simultaneous connections per source", n),
            level: level.as_u8(),
            created: now,
            expires: now + cfg.block_ttl_secs.max(120),
            applied,
        });
        Ok(())
    }

    /// Half-open connection protection for SYN floods.
    pub fn syn_protect(
        &mut self,
        incident: &str,
        level: Level,
        cfg: &Config,
    ) -> Result<(), String> {
        let now = epoch();
        let mut applied = false;
        if self.capable {
            self.clear_kind_rules(RuleKind::SynProtect);
            let (ok, err) = ipt(&[
                "-I",
                CHAIN,
                "1",
                "-p",
                "tcp",
                "--syn",
                "-m",
                "limit",
                "--limit",
                "200/second",
                "--limit-burst",
                "400",
                "-j",
                "RETURN",
            ]);
            if !ok {
                return Err(format!("syn limit: {}", err));
            }
            let (ok2, err2) = ipt(&["-I", CHAIN, "2", "-p", "tcp", "--syn", "-j", "DROP"]);
            if !ok2 {
                let _ = ipt(&[
                    "-D",
                    CHAIN,
                    "-p",
                    "tcp",
                    "--syn",
                    "-m",
                    "limit",
                    "--limit",
                    "200/second",
                    "--limit-burst",
                    "400",
                    "-j",
                    "RETURN",
                ]);
                return Err(format!("syn drop: {}", err2));
            }
            applied = true;
        }
        self.record(Rule {
            incident_id: incident.into(),
            kind: RuleKind::SynProtect,
            target: "-".into(),
            reason: "SYN rate ceiling 200/s (burst 400)".into(),
            level: level.as_u8(),
            created: now,
            expires: now + cfg.block_ttl_secs.max(120),
            applied,
        });
        Ok(())
    }

    /// Remove the iptables rules of one kind from our chain (ipset entries are
    /// left to their kernel TTL).
    fn clear_kind_rules(&mut self, kind: RuleKind) {
        if !self.capable {
            return;
        }
        let spec = crate::util::run("iptables", &["-S", CHAIN]);
        let needle = match kind {
            RuleKind::RateLimit => "hashlimit",
            RuleKind::ConnLimit => "connlimit",
            RuleKind::SynProtect => "--syn",
            _ => return,
        };
        for line in spec.lines() {
            if !line.starts_with("-A ") || !line.contains(needle) {
                continue;
            }
            let args: Vec<String> = line
                .split_whitespace()
                .skip(1)
                .map(|s| s.to_string())
                .collect();
            let mut argv: Vec<&str> = vec!["-D"];
            argv.extend(args.iter().skip(1).map(|s| s.as_str()));
            // `-A CHAIN ...` -> `-D CHAIN ...`
            let mut full: Vec<&str> = vec!["-D", CHAIN];
            full.extend(argv.iter().skip(2).copied());
            let _ = ipt(&full);
        }
        self.store.rules.retain(|r| r.kind != kind);
    }

    /// Drop everything NIMBUSA added. Permanent rules, the blacklist ipset,
    /// fail2ban and Docker's own chains are untouched by construction.
    pub fn rollback(&mut self) -> Outcome {
        let mut o = Outcome::default();
        if self.capable {
            let (ok, err) = ipt(&["-F", CHAIN]);
            if ok {
                o.applied.push(format!("flushed {}", CHAIN));
            } else {
                o.failed.push(format!("flush {}: {}", CHAIN, err));
            }
            // re-add the ipset drop floor so the chain stays wired for next time
            for set in [DDOS_SET, DDOS_NET_SET] {
                let _ = ipt(&[
                    "-A",
                    CHAIN,
                    "-m",
                    "set",
                    "--match-set",
                    set,
                    "src",
                    "-j",
                    "DROP",
                ]);
                let (fok, ferr) = run_status("ipset", &["flush", set]);
                if fok {
                    o.applied.push(format!("cleared {}", set));
                } else {
                    o.failed.push(format!("flush {}: {}", set, ferr));
                }
            }
        } else {
            o.skipped
                .push("not privileged — nothing to roll back".into());
        }
        let n = self.store.rules.len();
        self.store.rules.clear();
        self.store.level = 0;
        self.save();
        o.applied.push(format!("released {} automatic rules", n));
        o
    }

    /// Drop rules whose TTL has passed. The kernel already expired the ipset
    /// entries; this keeps the recorded state honest.
    pub fn prune(&mut self) -> usize {
        let now = epoch();
        let before = self.store.rules.len();
        let expired: Vec<Rule> = self
            .store
            .rules
            .iter()
            .filter(|r| r.expired(now))
            .cloned()
            .collect();
        for r in &expired {
            if !self.capable {
                continue;
            }
            match r.kind {
                RuleKind::BlockIp => {
                    let _ = run_status("ipset", &["del", DDOS_SET, &r.target]);
                }
                RuleKind::BlockNet => {
                    let _ = run_status("ipset", &["del", DDOS_NET_SET, &r.target]);
                }
                _ => {}
            }
        }
        self.store.rules.retain(|r| !r.expired(now));
        if self.store.rules.len() != before {
            self.save();
        }
        before - self.store.rules.len()
    }

    pub fn active(&self) -> Vec<&Rule> {
        let now = epoch();
        self.store
            .rules
            .iter()
            .filter(|r| !r.expired(now))
            .collect()
    }

    pub fn blocked_count(&self) -> usize {
        self.active()
            .iter()
            .filter(|r| matches!(r.kind, RuleKind::BlockIp | RuleKind::BlockNet))
            .count()
    }

    pub fn has(&self, kind: RuleKind) -> bool {
        self.active().iter().any(|r| r.kind == kind)
    }

    pub fn save(&mut self) {
        self.store.updated = epoch();
        if let Ok(s) = serde_json::to_string_pretty(&self.store) {
            let _ = write_atomic(&paths::ddos("active_rules.json"), &s);
        }
    }

    /// Apply the mitigation appropriate to `target` level. Escalation is
    /// cumulative: level 4 keeps the level 1-3 protections in place.
    pub fn apply_level(
        &mut self,
        target: Level,
        incident: &str,
        suspects: &[Suspect],
        cfg: &Config,
    ) -> Outcome {
        let mut o = Outcome::default();
        if !cfg.mitigation_enabled {
            o.skipped.push("mitigation disabled in config".into());
            return o;
        }
        if target > Level::Observe && !self.installed && self.capable {
            let inst = self.install();
            o.failed.extend(inst.failed.clone());
            o.applied.extend(inst.applied.clone());
        }
        let protected = protected_addresses();

        if target >= Level::RateLimit {
            match self.rate_limit(incident, target, cfg) {
                Ok(_) => o.applied.push("adaptive rate limiting".into()),
                Err(e) => o.failed.push(e),
            }
        }
        if target >= Level::Filtering {
            // Only sources that scored high enough on their own evidence.
            let cut = if target >= Level::Emergency { 30 } else { 45 };
            let mut blocked = 0usize;
            for s in suspects.iter().filter(|s| s.score >= cut) {
                if blocked >= cfg.max_auto_blocks {
                    o.skipped.push(format!(
                        "block cap {} reached — remaining sources left to rate limiting",
                        cfg.max_auto_blocks
                    ));
                    break;
                }
                match self.block_ip(
                    &s.ip,
                    incident,
                    &s.reason,
                    target,
                    cfg.block_ttl_secs,
                    &protected,
                ) {
                    Ok(_) => blocked += 1,
                    Err(e) => o.skipped.push(e),
                }
            }
            if blocked > 0 {
                o.applied.push(format!(
                    "temporary filtering: {} sources ({}s TTL)",
                    blocked, cfg.block_ttl_secs
                ));
            }
        }
        if target >= Level::Aggressive {
            match self.conn_limit(incident, target, cfg) {
                Ok(_) => o.applied.push("connection limiting".into()),
                Err(e) => o.failed.push(e),
            }
            // a flood spread thinly across a /24 is cheaper to stop at the network
            for (net, members, _) in super::detect::network_suspects(suspects, 12) {
                match self.block_net(
                    &net,
                    incident,
                    &format!("{} distinct sources from this network", members),
                    target,
                    cfg.block_ttl_secs,
                    &protected,
                ) {
                    Ok(_) => o.applied.push(format!("network block {}", net)),
                    Err(e) => o.skipped.push(e),
                }
            }
        }
        if target >= Level::Emergency {
            match self.syn_protect(incident, target, cfg) {
                Ok(_) => o.applied.push("SYN flood protection".into()),
                Err(e) => o.failed.push(e),
            }
        }
        self.store.level = target.as_u8();
        self.save();
        o
    }
}

pub fn load_store() -> RuleStore {
    match std::fs::read_to_string(paths::ddos("active_rules.json")) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => RuleStore::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suspect(ip: &str, score: u32) -> Suspect {
        Suspect {
            ip: ip.into(),
            requests: 900,
            rpm: 1800.0,
            connections: 40,
            score,
            reason: "test".into(),
        }
    }

    /// A mitigator with no privileges: it records intent but claims nothing.
    fn offline() -> Mitigator {
        Mitigator {
            store: RuleStore::default(),
            capable: false,
            installed: false,
        }
    }

    #[test]
    fn whitelisted_source_is_never_blocked() {
        let mut m = offline();
        let protected = vec!["203.0.113.5".to_string()];
        let err = m
            .block_ip(
                "203.0.113.5",
                "INC-1",
                "flood",
                Level::Filtering,
                300,
                &protected,
            )
            .unwrap_err();
        assert!(err.starts_with("MITIGATION_SKIPPED_WHITELIST"));
        assert!(m.store.rules.is_empty(), "no rule may be recorded either");
    }

    #[test]
    fn whitelisted_network_protects_its_members() {
        let mut m = offline();
        let protected = vec!["203.0.113.0/24".to_string()];
        assert!(m
            .block_ip(
                "203.0.113.99",
                "INC-1",
                "flood",
                Level::Filtering,
                300,
                &protected
            )
            .is_err());
    }

    #[test]
    fn network_block_refuses_to_swallow_a_protected_address() {
        let mut m = offline();
        let protected = vec!["45.66.77.10".to_string()];
        let err = m
            .block_net(
                "45.66.77.0/24",
                "INC-1",
                "flood",
                Level::Aggressive,
                300,
                &protected,
            )
            .unwrap_err();
        assert!(err.contains("contains protected"));
    }

    #[test]
    fn private_and_invalid_targets_are_refused() {
        let p: Vec<String> = vec![];
        assert!(refuse_reason("10.1.2.3", &p).unwrap().contains("PRIVATE"));
        assert!(refuse_reason("not-an-ip", &p).unwrap().contains("INVALID"));
        assert!(refuse_reason("1.2.3.4; reboot", &p)
            .unwrap()
            .contains("INVALID"));
        assert!(refuse_reason("8.8.8.8", &p).is_none());
    }

    #[test]
    fn recorded_rules_carry_the_full_audit_fields() {
        let mut m = offline();
        m.block_ip(
            "8.8.4.4",
            "NIMBUSA-DDOS-20260829-0001",
            "1800 req/min",
            Level::Filtering,
            300,
            &[],
        )
        .unwrap();
        let r = &m.store.rules[0];
        assert_eq!(r.incident_id, "NIMBUSA-DDOS-20260829-0001");
        assert_eq!(r.reason, "1800 req/min");
        assert_eq!(r.level, 3);
        assert!(r.created > 0);
        assert_eq!(r.expires, r.created + 300);
        assert!(!r.applied, "unprivileged run must not claim enforcement");
    }

    #[test]
    fn every_automatic_rule_has_a_ttl() {
        let mut m = offline();
        let cfg = Config::default();
        m.apply_level(Level::Emergency, "INC-9", &[suspect("9.9.9.9", 90)], &cfg);
        assert!(!m.store.rules.is_empty());
        for r in &m.store.rules {
            assert!(r.expires > r.created, "{:?} has no expiry", r.kind);
        }
    }

    #[test]
    fn expired_rules_are_pruned() {
        let mut m = offline();
        let now = epoch();
        m.store.rules.push(Rule {
            incident_id: "INC-1".into(),
            kind: RuleKind::BlockIp,
            target: "8.8.8.8".into(),
            reason: "old".into(),
            level: 3,
            created: now - 1000,
            expires: now - 1,
            applied: false,
        });
        m.store.rules.push(Rule {
            incident_id: "INC-1".into(),
            kind: RuleKind::BlockIp,
            target: "8.8.4.4".into(),
            reason: "fresh".into(),
            level: 3,
            created: now,
            expires: now + 600,
            applied: false,
        });
        assert_eq!(m.prune(), 1);
        assert_eq!(m.active().len(), 1);
        assert_eq!(m.active()[0].target, "8.8.4.4");
    }

    #[test]
    fn escalation_is_cumulative() {
        let cfg = Config::default();
        let mut m = offline();
        m.apply_level(Level::RateLimit, "INC-2", &[], &cfg);
        assert!(m.has(RuleKind::RateLimit));
        assert!(!m.has(RuleKind::ConnLimit));

        m.apply_level(Level::Aggressive, "INC-2", &[suspect("9.9.9.9", 90)], &cfg);
        assert!(m.has(RuleKind::RateLimit), "lower levels stay in place");
        assert!(m.has(RuleKind::ConnLimit));
        assert!(m.has(RuleKind::BlockIp));
    }

    #[test]
    fn low_scoring_sources_are_not_blocked() {
        let cfg = Config::default();
        let mut m = offline();
        m.apply_level(
            Level::Filtering,
            "INC-3",
            &[suspect("9.9.9.9", 22), suspect("8.8.8.8", 80)],
            &cfg,
        );
        let blocked: Vec<&str> = m
            .active()
            .iter()
            .filter(|r| r.kind == RuleKind::BlockIp)
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(blocked, vec!["8.8.8.8"]);
    }

    #[test]
    fn block_cap_is_respected() {
        let mut cfg = Config::default();
        cfg.max_auto_blocks = 3;
        let mut m = offline();
        let suspects: Vec<Suspect> = (0..50)
            .map(|i| suspect(&format!("45.0.0.{}", i + 1), 90))
            .collect();
        let o = m.apply_level(Level::Filtering, "INC-4", &suspects, &cfg);
        assert_eq!(
            m.active()
                .iter()
                .filter(|r| r.kind == RuleKind::BlockIp)
                .count(),
            3
        );
        assert!(o.skipped.iter().any(|s| s.contains("block cap")));
    }

    #[test]
    fn rollback_clears_recorded_state() {
        let cfg = Config::default();
        let mut m = offline();
        m.apply_level(Level::Aggressive, "INC-5", &[suspect("9.9.9.9", 90)], &cfg);
        assert!(!m.store.rules.is_empty());
        m.rollback();
        assert!(m.store.rules.is_empty());
        assert_eq!(m.store.level, 0);
    }

    #[test]
    fn disabled_mitigation_applies_nothing() {
        let mut cfg = Config::default();
        cfg.mitigation_enabled = false;
        let mut m = offline();
        let o = m.apply_level(Level::Emergency, "INC-6", &[suspect("9.9.9.9", 99)], &cfg);
        assert!(m.store.rules.is_empty());
        assert!(o.skipped.iter().any(|s| s.contains("disabled")));
    }

    #[test]
    fn levels_round_trip() {
        for n in 0..=5u8 {
            assert_eq!(Level::from_u8(n).as_u8(), n);
        }
        assert_eq!(Level::from_u8(99), Level::Observe);
    }
}
