//! Host, docker/traefik, SSH, user and IP-intelligence monitoring.
//!
//! This is the preserved AVNI control-center functionality, moved intact into
//! NIMBUSA and rewired onto the shared `util`/`firewall`/`paths` modules. The
//! background-gather design is unchanged: every expensive fetch runs off the
//! render thread, and the IP registry is still parsed incrementally by file
//! offset.
use crate::firewall;
use crate::paths;
use crate::util::*;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

#[cfg(unix)]
fn inode_of(m: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.ino()
}
#[cfg(not(unix))]
fn inode_of(_m: &std::fs::Metadata) -> u64 {
    0
}

pub const AUTH_LOGS: [&str; 2] = ["/var/log/auth.log", "/var/log/auth.log.1"];

#[derive(Default, Clone)]
pub struct Overview {
    pub host: String,
    pub ip: String,
    pub os: String,
    pub kernel: String,
    pub uptime: String,
    pub load: [f64; 3],
    pub ncpu: f64,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_pct: u64,
    pub disk_used: String,
    pub disk_size: String,
    pub time: String,
    pub ist: String,
}
#[derive(Default, Clone)]
pub struct Svc {
    pub name: String,
    pub status: String,
    pub domain: String,
}
#[derive(Default, Clone)]
pub struct Sess {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub country: String,
    pub since: String,
    pub me: bool,
}
#[derive(Default, Clone)]
#[allow(dead_code)]
pub struct UserRow {
    pub user: String,
    pub uid: String,
    pub sudo: bool,
    pub live: u32,
    pub locked: bool,
    pub key: bool,
    pub last: String,
    pub groups: String,
    pub access: bool,
}
#[derive(Default, Clone)]
pub struct SshCfg {
    pub root: String,
    pub pass: String,
    pub pubkey: String,
    pub port: String,
    pub attackers: usize,
}
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct IpRec {
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub attempts: u64,
    #[serde(default)]
    pub logins: u64,
    #[serde(default)]
    pub first: String,
    #[serde(default)]
    pub last: String,
    #[serde(default)]
    pub banned: bool,
    #[serde(default)]
    pub blacklisted: bool,
    #[serde(default)]
    pub last_user: String,
    #[serde(default)]
    pub whitelisted: bool,
}

pub fn overview() -> Overview {
    let mut o = Overview {
        host: sh("hostname"),
        ip: public_ip(),
        os: sh(". /etc/os-release; echo $PRETTY_NAME"),
        kernel: sh("uname -r"),
        uptime: sh("uptime -p"),
        time: sh("date '+%Y-%m-%d %H:%M:%S %Z'"),
        ist: sh("TZ=Asia/Kolkata date '+%H:%M %Z'"),
        ..Default::default()
    };
    let la = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let lp: Vec<f64> = la
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect();
    if lp.len() == 3 {
        o.load = [lp[0], lp[1], lp[2]];
    }
    o.ncpu = sh("nproc").parse().unwrap_or(1.0);
    for l in sh("free -m").lines() {
        if l.to_lowercase().starts_with("mem") {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() >= 3 {
                o.mem_total = p[1].parse().unwrap_or(0);
                o.mem_used = p[2].parse().unwrap_or(0);
            }
        }
    }
    let d = sh("df -h /");
    let dl: Vec<&str> = d.lines().nth(1).unwrap_or("").split_whitespace().collect();
    if dl.len() >= 5 {
        o.disk_used = dl[2].into();
        o.disk_size = dl[1].into();
        o.disk_pct = dl[4].trim_end_matches('%').parse().unwrap_or(0);
    }
    o
}

pub fn public_ip() -> String {
    use std::sync::OnceLock;
    static C: OnceLock<String> = OnceLock::new();
    C.get_or_init(|| {
        let local = sh("ip route get 1.1.1.1 2>/dev/null")
            .split_whitespace()
            .skip_while(|t| *t != "src")
            .nth(1)
            .unwrap_or("")
            .to_string();
        if valid_ip(&local).is_some() && !is_private(&local) {
            return local;
        }
        let i = if have("curl") {
            run("curl", &["-s", "-m2", "https://api.ipify.org"])
        } else {
            String::new()
        };
        if valid_ip(&i).is_some() {
            i
        } else {
            local
        }
    })
    .clone()
}

/// One docker call for names + status + traefik Host() rules.
pub fn docker_snapshot() -> (Vec<Svc>, Vec<(String, String)>) {
    if !have("docker") {
        return (vec![], vec![]);
    }
    let out = run(
        "docker",
        &[
            "ps",
            "-a",
            "--no-trunc",
            "--format",
            "{{.Names}}\t{{.Status}}\t{{.Labels}}",
        ],
    );
    let mut svcs = Vec::new();
    let mut doms: Vec<(String, String)> = Vec::new();
    for l in out.lines() {
        let p: Vec<&str> = l.splitn(3, '\t').collect();
        if p.len() < 2 {
            continue;
        }
        let (name, status) = (p[0].to_string(), p[1].to_string());
        let mut hosts: Vec<String> = Vec::new();
        let mut rest = p.get(2).copied().unwrap_or("");
        while let Some(i) = rest.find("Host(`") {
            let after = &rest[i + 6..];
            if let Some(j) = after.find('`') {
                hosts.push(after[..j].to_string());
                rest = &after[j + 1..];
            } else {
                break;
            }
        }
        hosts.sort();
        hosts.dedup();
        for h in &hosts {
            doms.push((h.clone(), name.clone()));
        }
        svcs.push(Svc {
            name,
            status,
            domain: hosts.join(","),
        });
    }
    doms.sort();
    doms.dedup();
    (svcs, doms)
}
pub fn services() -> Vec<Svc> {
    docker_snapshot().0
}
pub fn domains() -> Vec<(String, String)> {
    docker_snapshot().1
}

pub fn primary_iface() -> String {
    crate::shield::telemetry::primary_iface()
}

pub fn vnstat_full(flag: &str, iface: &str) -> Vec<(String, u64)> {
    if !have("vnstat") {
        return vec![];
    }
    let out = run("vnstat", &["-i", iface, "--json", flag]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or(serde_json::Value::Null);
    let key = if flag == "h" { "hour" } else { "day" };
    let mut res = vec![];
    if let Some(arr) = v["interfaces"][0]["traffic"]
        .get(key)
        .and_then(|x| x.as_array())
    {
        for e in arr {
            let rx = e["rx"].as_u64().unwrap_or(0);
            let tx = e["tx"].as_u64().unwrap_or(0);
            let d = &e["date"];
            let lab = if flag == "h" {
                format!("{:02}h", d["hour"].as_u64().unwrap_or(0))
            } else {
                format!(
                    "{}/{}",
                    d["month"].as_u64().unwrap_or(0),
                    d["day"].as_u64().unwrap_or(0)
                )
            };
            res.push((lab, rx + tx));
        }
    }
    res
}
pub fn vnstat_today() -> String {
    if !have("vnstat") {
        return "vnstat not installed".into();
    }
    let p: Vec<String> = run("vnstat", &["--oneline"])
        .split(';')
        .map(|s| s.to_string())
        .collect();
    if p.len() >= 7 {
        format!("today {} (rx {} / tx {})  rate {}", p[5], p[3], p[4], p[6])
    } else {
        "today: (vnstat collecting)".into()
    }
}

// ------------------------------------------------------------------ registry
#[allow(clippy::type_complexity)]
pub fn reg_load_map() -> (HashMap<String, IpRec>, HashMap<String, u64>) {
    let mut map = HashMap::new();
    let mut off = HashMap::new();
    if let Ok(s) = fs::read_to_string(paths::registry_file()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(obj) = v.as_object() {
                for (k, val) in obj {
                    if k == "_meta" {
                        if let Some(o) = val.get("offsets").and_then(|o| o.as_object()) {
                            for (i, p) in o {
                                off.insert(i.clone(), p.as_u64().unwrap_or(0));
                            }
                        }
                    } else if !k.starts_with('_') {
                        if let Ok(r) = serde_json::from_value::<IpRec>(val.clone()) {
                            map.insert(k.clone(), r);
                        }
                    }
                }
            }
        }
    }
    (map, off)
}
pub fn reg_save_map(map: &HashMap<String, IpRec>, off: &HashMap<String, u64>) {
    let mut obj = serde_json::Map::new();
    for (k, r) in map {
        obj.insert(k.clone(), serde_json::to_value(r).unwrap());
    }
    let mut offo = serde_json::Map::new();
    for (i, p) in off {
        offo.insert(i.clone(), serde_json::json!(p));
    }
    let mut meta = serde_json::Map::new();
    meta.insert("offsets".into(), serde_json::Value::Object(offo));
    obj.insert("_meta".into(), serde_json::Value::Object(meta));
    let _ = write_atomic(
        &paths::registry_file(),
        &serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default(),
    );
}

pub fn reg_update() -> HashMap<String, IpRec> {
    let (mut map, mut off) = reg_load_map();
    let first_run = off.is_empty() && !map.is_empty();
    #[allow(clippy::type_complexity)]
    let (mut att, mut fsm, mut lsm, mut users): (
        HashMap<String, u64>,
        HashMap<String, String>,
        HashMap<String, String>,
        HashMap<String, String>,
    ) = Default::default();
    for f in AUTH_LOGS {
        if let Ok(meta) = fs::metadata(f) {
            let ino = inode_of(&meta).to_string();
            let size = meta.len();
            if first_run {
                off.insert(ino, size);
                continue;
            }
            let mut start = *off.get(&ino).unwrap_or(&0);
            if start > size {
                start = 0;
            }
            if let Ok(mut file) = fs::File::open(f) {
                let _ = file.seek(SeekFrom::Start(start));
                let mut pos = start;
                for line in BufReader::new(file).lines().map_while(Result::ok) {
                    pos += line.len() as u64 + 1;
                    if line.contains("Failed password")
                        || line.contains("Invalid user")
                        || line.contains("authenticating")
                        || line.contains("closed by")
                        || line.contains("Disconnect")
                    {
                        if let Some(ip) = find_ip(&line) {
                            *att.entry(ip.clone()).or_insert(0) += 1;
                            let t = ts_of(&line);
                            fsm.entry(ip.clone())
                                .and_modify(|e| {
                                    if t < *e {
                                        *e = t.clone();
                                    }
                                })
                                .or_insert(t.clone());
                            lsm.entry(ip.clone())
                                .and_modify(|e| {
                                    if t > *e {
                                        *e = t.clone();
                                    }
                                })
                                .or_insert(t.clone());
                            if let Some(u) = user_of(&line) {
                                users.insert(ip.clone(), u);
                            }
                        }
                    }
                }
                off.insert(ino, pos);
            }
        }
    }
    let mut logins: HashMap<String, u64> = HashMap::new();
    for line in sh("last -i -n 300").lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 3 {
            if let Some(ip) = valid_ip(p[2]) {
                *logins.entry(ip).or_insert(0) += 1;
            }
        }
    }
    let banned = firewall::f2b_banned();
    let bl: HashSet<String> = firewall::blacklist_list().into_iter().collect();
    let wl: HashSet<String> = firewall::whitelist_list().into_iter().collect();
    let mut keys: HashSet<String> = map.keys().cloned().collect();
    keys.extend(att.keys().cloned());
    keys.extend(logins.keys().cloned());
    keys.extend(banned.iter().cloned());
    keys.extend(bl.iter().cloned());
    keys.extend(wl.iter().cloned());
    let now = now_str();
    for ip in keys {
        let e = map.entry(ip.clone()).or_default();
        if e.country.is_empty() {
            e.country = geo(&ip);
        }
        e.attempts += *att.get(&ip).unwrap_or(&0);
        if let Some(t) = fsm.get(&ip) {
            if e.first.is_empty() || *t < e.first {
                e.first = t.clone();
            }
        }
        if let Some(t) = lsm.get(&ip) {
            if *t > e.last {
                e.last = t.clone();
            }
        }
        let lg = *logins.get(&ip).unwrap_or(&0);
        if lg > e.logins {
            e.logins = lg;
        }
        e.banned = banned.contains(&ip);
        e.blacklisted = bl.contains(&ip);
        e.whitelisted = wl.contains(&ip);
        if let Some(u) = users.get(&ip) {
            e.last_user = u.clone();
        }
        if e.first.is_empty() {
            e.first = now.clone();
        }
        if e.last.is_empty() {
            e.last = now.clone();
        }
    }
    reg_save_map(&map, &off);
    map
}

pub const SUBS: [&str; 7] = [
    "Attackers",
    "Banned",
    "Whitelist",
    "Unbanned",
    "New",
    "Logins",
    "All",
];

pub fn reg_filter(reg: &HashMap<String, IpRec>, which: usize) -> Vec<(String, IpRec)> {
    let mut v: Vec<(String, IpRec)> = reg.iter().map(|(k, r)| (k.clone(), r.clone())).collect();
    let cutoff = if which == 4 {
        sh("date -d '-24 hours' '+%Y-%m-%d %H:%M:%S'")
    } else {
        String::new()
    };
    match which {
        0 => v.retain(|(_, e)| {
            e.attempts > 0 && !e.whitelisted && (e.banned || e.blacklisted || e.logins == 0)
        }),
        1 => v.retain(|(_, e)| e.banned || e.blacklisted),
        2 => v.retain(|(_, e)| e.whitelisted),
        3 => v.retain(|(_, e)| e.attempts > 0 && !e.banned && !e.blacklisted && !e.whitelisted),
        4 => v.retain(|(_, e)| !e.first.is_empty() && e.first.as_str() >= cutoff.as_str()),
        5 => v.retain(|(_, e)| e.logins > 0),
        _ => {}
    }
    if which == 5 {
        v.sort_by_key(|(_, e)| Reverse(e.logins));
    } else {
        v.sort_by_key(|(_, e)| Reverse(e.attempts));
    }
    v
}

pub fn status_of(e: &IpRec) -> &'static str {
    if e.whitelisted {
        "WHITELIST"
    } else if e.blacklisted {
        "BLACKLIST"
    } else if e.banned {
        "BANNED"
    } else if e.logins > 0 {
        "login"
    } else {
        "seen"
    }
}

pub fn sessions() -> Vec<Sess> {
    let me_tty = sh("tty").replace("/dev/", "");
    let me_ip = std::env::var("SSH_CLIENT")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|x| x.to_string()))
        .unwrap_or_default();
    let delta = ist_delta_min();
    sh("who")
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() >= 5 {
                let from = p[p.len() - 1]
                    .trim_matches(|c| c == '(' || c == ')')
                    .to_string();
                let country = if valid_ip(&from).is_some() {
                    geo(&from)
                } else {
                    "local".into()
                };
                Some(Sess {
                    user: p[0].into(),
                    tty: p[1].into(),
                    me: p[1] == me_tty || from == me_ip,
                    from,
                    country,
                    since: with_ist(&format!("{} {}", p[2], p[3]), delta),
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn ssh_cfg() -> SshCfg {
    let t = sh("sshd -T 2>/dev/null");
    let g = |k: &str| {
        t.lines()
            .find(|l| l.to_lowercase().starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("?")
            .to_string()
    };
    SshCfg {
        root: g("permitrootlogin"),
        pass: g("passwordauthentication"),
        pubkey: g("pubkeyauthentication"),
        port: g("port"),
        attackers: 0,
    }
}

pub fn users_list() -> Vec<UserRow> {
    let mut sudoers = HashSet::new();
    for grp in ["sudo", "admin", "wheel"] {
        let m = sh(&format!("getent group {}", grp));
        if let Some(list) = m.rsplit(':').next() {
            for u in list.split(',') {
                if !u.is_empty() {
                    sudoers.insert(u.to_string());
                }
            }
        }
    }
    let access_grp: HashSet<String> = sh(&format!("getent group {}", paths::ACCESS_GROUP))
        .rsplit(':')
        .next()
        .unwrap_or("")
        .split(',')
        .filter(|u| !u.is_empty())
        .map(|u| u.to_string())
        .collect();
    let delta = ist_delta_min();
    let mut live: HashMap<String, u32> = HashMap::new();
    for l in sh("who").lines() {
        if let Some(u) = l.split_whitespace().next() {
            *live.entry(u.into()).or_insert(0) += 1;
        }
    }
    let mut rows = vec![];
    for l in sh("getent passwd").lines() {
        let p: Vec<&str> = l.split(':').collect();
        if p.len() < 7 {
            continue;
        }
        let uid: i64 = p[2].parse().unwrap_or(-1);
        if !(uid == 0 || uid >= 1000)
            || p[0] == "nobody"
            || p[6].ends_with("nologin")
            || p[6].ends_with("false")
        {
            continue;
        }
        let ll = sh(&format!("lastlog -u {}", p[0]));
        let last = ll
            .lines()
            .nth(1)
            .map(|l| {
                if l.contains("Never") {
                    return "Never".into();
                }
                let t: Vec<&str> = l.split_whitespace().collect();
                match t.iter().position(|x| {
                    x.matches(':').count() == 2
                        && x.split(':')
                            .next()
                            .map(|h| h.len() <= 2 && h.parse::<u8>().is_ok())
                            .unwrap_or(false)
                }) {
                    Some(i) if i >= 2 => {
                        with_ist(&format!("{} {} {}", t[i - 2], t[i - 1], t[i]), delta)
                    }
                    _ => String::new(),
                }
            })
            .unwrap_or_default();
        let locked = sh(&format!("passwd -S {}", p[0]))
            .split_whitespace()
            .nth(1)
            .map(|s| s.starts_with('L'))
            .unwrap_or(false);
        rows.push(UserRow {
            user: p[0].into(),
            uid: p[2].into(),
            sudo: sudoers.contains(p[0]) || uid == 0,
            live: *live.get(p[0]).unwrap_or(&0),
            locked,
            key: std::path::Path::new(&format!("{}/.ssh/authorized_keys", p[5])).exists(),
            last,
            groups: sh(&format!("id -nG {}", p[0])),
            access: uid == 0 || access_grp.contains(p[0]),
        });
    }
    rows
}

// ----------------------------- user management (root protected everywhere)
pub fn kick_session(s: &Sess) -> String {
    if s.me {
        return "refused: that is YOUR session".into();
    }
    if s.tty.is_empty() || !s.tty.chars().all(|c| c.is_ascii_alphanumeric() || c == '/') {
        return "refused: invalid tty".into();
    }
    run("pkill", &["-KILL", "-t", &s.tty]);
    format!("kicked {}", s.tty)
}
pub fn grant_sudo(user: &str) -> String {
    if !valid_username(user) {
        return "refused: invalid username".into();
    }
    run("usermod", &["-aG", "sudo", user]);
    format!("granted sudo to {}", user)
}
pub fn revoke_sudo(user: &str) -> String {
    if user == "root" {
        return "refused: cannot revoke root's sudo".into();
    }
    if !valid_username(user) {
        return "refused: invalid username".into();
    }
    for g in ["sudo", "admin", "wheel"] {
        run("gpasswd", &["-d", user, g]);
    }
    format!("revoked sudo from {}", user)
}
pub fn del_user(user: &str) -> String {
    if user == "root" {
        return "refused: cannot delete root".into();
    }
    if !valid_username(user) {
        return "refused: invalid username".into();
    }
    let (ok, out) = run_status("userdel", &[user]);
    if ok {
        format!("deleted {} (home kept)", user)
    } else {
        format!("userdel: {}", out.trim())
    }
}
pub fn safe_pw(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '\'' | '"' | '`' | '\\' | '$'))
}
pub fn create_user(input: &str) -> String {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return "no username given".into();
    }
    let user = parts[0];
    if !valid_username(user) {
        return format!(
            "invalid username '{}' (lowercase letter, then a-z 0-9 _ -)",
            user
        );
    }
    if !sh(&format!("id -u '{}' 2>/dev/null", user))
        .trim()
        .is_empty()
    {
        return format!("user {} already exists", user);
    }
    let pw = parts.get(1).copied();
    if let Some(p) = pw {
        if !safe_pw(p) {
            return "password has unsupported characters — create without one, then set via passwd"
                .into();
        }
    }
    let (ok, out) = run_status("useradd", &["-m", "-s", "/bin/bash", user]);
    if !ok {
        return format!("useradd: {}", out.trim());
    }
    match pw {
        Some(p) => {
            let (ok2, _) = run_status(
                "sh",
                &[
                    "-c",
                    &format!("printf '%s:%s' '{}' '{}' | chpasswd", user, p),
                ],
            );
            if ok2 {
                format!("created {} with password (/home/{})", user, user)
            } else {
                format!("created {} but password set failed — use passwd", user)
            }
        }
        None => format!(
            "created {} — no password set yet (locked; set with passwd)",
            user
        ),
    }
}
pub fn is_sudoer(user: &str) -> bool {
    if user == "root" {
        return true;
    }
    sh(&format!("id -nG '{}' 2>/dev/null", user))
        .split_whitespace()
        .any(|g| g == "sudo" || g == "admin" || g == "wheel")
}
pub fn user_activity(user: &str) -> String {
    if !valid_username(user) {
        return "invalid username".into();
    }
    let delta = ist_delta_min();
    let ist_lines = |s: &str| {
        s.lines()
            .map(|l| with_ist(l, delta))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let shell = sh(&format!("getent passwd '{}' | cut -d: -f7", user));
    let home = sh(&format!("getent passwd '{}' | cut -d: -f6", user));
    let pwstat = sh(&format!("passwd -S '{}' 2>/dev/null", user));
    let groups = sh(&format!("id -nG '{}' 2>/dev/null", user));
    let mut out = format!(
        "now       {}  ·  {} IST\nuid/gid   {}\nshell     {}\nhome      {}\ngroups    {}\npasswd    {}\nadmin     {}   nimbusa-access {}",
        sh("date '+%Y-%m-%d %H:%M:%S %Z'"),
        sh("TZ=Asia/Kolkata date '+%H:%M'"),
        sh(&format!("id -u '{}' 2>/dev/null", user)),
        shell, home, groups, pwstat, is_sudoer(user),
        sh(&format!("getent group {}", paths::ACCESS_GROUP))
            .rsplit(':').next().unwrap_or("").split(',').any(|u| u == user)
            || sh(&format!("id -u '{}'", user)).trim() == "0"
    );
    let live = sh(&format!("who | grep -c '^{} '", user));
    out.push_str(&format!(
        "\n\n— live sessions ({}) · times show IST —",
        live.trim()
    ));
    let who = sh(&format!("who | awk '$1==\"{}\"'", user));
    out.push_str(&format!(
        "\n{}",
        if who.trim().is_empty() {
            "  (not logged in now)".into()
        } else {
            ist_lines(&who)
        }
    ));
    out.push_str("\n\n— recent logins (last) —\n");
    let last = sh(&format!("last -i -n 8 '{}' | head -n 8", user));
    out.push_str(
        if last.trim().is_empty() {
            "  (none recorded)".into()
        } else {
            ist_lines(last.trim_end())
        }
        .as_str(),
    );
    let sudo = sh(&format!(
        "grep -h ' sudo:.*{} :' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | grep -o 'COMMAND=.*' | tail -n 8",
        user
    ));
    out.push_str("\n\n— recent sudo commands —\n");
    out.push_str(if sudo.trim().is_empty() {
        "  (none)"
    } else {
        sudo.trim_end()
    });
    let nproc = sh(&format!(
        "ps -u '{}' --no-headers 2>/dev/null | wc -l",
        user
    ));
    let ps = sh(&format!(
        "ps -u '{}' -o pid,pcpu,pmem,etime,comm --sort=-pcpu --no-headers 2>/dev/null | head -n 6",
        user
    ));
    out.push_str(&format!("\n\n— running processes ({}) —\n", nproc.trim()));
    out.push_str(if ps.trim().is_empty() {
        "  (none)"
    } else {
        ps.trim_end()
    });
    out
}
pub fn grant_access(user: &str) -> String {
    if user == "root" {
        return "root already has access".into();
    }
    if !valid_username(user) {
        return "refused: invalid username".into();
    }
    if !is_sudoer(user) {
        return format!(
            "refused: make {} an admin first (Users tab → G grant sudo)",
            user
        );
    }
    run("groupadd", &["-f", paths::ACCESS_GROUP]);
    run("usermod", &["-aG", paths::ACCESS_GROUP, user]);
    format!(
        "granted nimbusa access to {} — they can now run: nimbusa",
        user
    )
}
pub fn revoke_access(user: &str) -> String {
    if user == "root" {
        return "refused: root always has access".into();
    }
    if !valid_username(user) {
        return "refused: invalid username".into();
    }
    run("gpasswd", &["-d", user, paths::ACCESS_GROUP]);
    format!("revoked nimbusa access from {}", user)
}
