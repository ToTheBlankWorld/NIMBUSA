//! Product-owned filesystem layout + one-time, idempotent migration from the
//! legacy AVNI layout. NOTHING is ever deleted: migration copies forward and
//! leaves a `.migrated` breadcrumb next to the old data.
use std::fs;
use std::path::{Path, PathBuf};

pub const ETC: &str = "/etc/nimbusa";
pub const VAR: &str = "/var/lib/nimbusa";
pub const LOG: &str = "/var/log/nimbusa";
pub const RUN: &str = "/run/nimbusa";
pub const BIN: &str = "/usr/local/bin/nimbusa";

pub const LEGACY_ETC: &str = "/etc/avni";
pub const LEGACY_VAR: &str = "/var/lib/avni";

/// Unix group whose members may run the tool (root always can).
pub const ACCESS_GROUP: &str = "nimbusa";
pub const LEGACY_ACCESS_GROUP: &str = "avni";

pub fn etc(f: &str) -> PathBuf {
    Path::new(ETC).join(f)
}
pub fn var(f: &str) -> PathBuf {
    Path::new(VAR).join(f)
}
pub fn ddos(f: &str) -> PathBuf {
    Path::new(VAR).join("ddos").join(f)
}

pub fn config_file() -> PathBuf {
    etc("config.toml")
}
pub fn registry_file() -> PathBuf {
    var("ips.json")
}
#[allow(dead_code)]
pub fn whitelist_file() -> PathBuf {
    etc("whitelist.txt")
}

/// The firewall helper script. Installed copy first, then the in-repo path.
pub fn firewall_script() -> String {
    for c in [
        "/usr/local/lib/nimbusa/nimbusa-firewall.sh",
        "/root/nimbusa/scripts/nimbusa-firewall.sh",
        "/root/avni-cloud-tui/scripts/nimbusa-firewall.sh",
    ] {
        if Path::new(c).exists() {
            return c.to_string();
        }
    }
    "/usr/local/lib/nimbusa/nimbusa-firewall.sh".to_string()
}

fn ensure_dirs() {
    for d in [ETC, VAR, LOG, RUN] {
        let _ = fs::create_dir_all(d);
    }
    let _ = fs::create_dir_all(Path::new(VAR).join("ddos"));
    let _ = fs::create_dir_all(Path::new(VAR).join("audit"));
}

/// Copy `from` -> `to` only when `to` does not exist yet. Returns true if copied.
fn adopt(from: &Path, to: &Path) -> bool {
    if to.exists() || !from.exists() {
        return false;
    }
    if let Some(p) = to.parent() {
        let _ = fs::create_dir_all(p);
    }
    match fs::copy(from, to) {
        Ok(_) => {
            let _ = fs::write(
                from.with_extension("migrated"),
                format!("copied to {} by NIMBUSA migration\n", to.display()),
            );
            true
        }
        Err(_) => false,
    }
}

/// Idempotent AVNI -> NIMBUSA data migration. Safe to call on every start.
/// Returns the list of things that were adopted (empty on a clean/already-done box).
pub fn migrate_legacy() -> Vec<String> {
    ensure_dirs();
    let mut done = Vec::new();
    let pairs: [(&str, &str, &str); 4] = [
        (LEGACY_VAR, "ips.json", "IP intelligence registry"),
        (LEGACY_ETC, "whitelist.txt", "firewall whitelist"),
        (
            LEGACY_ETC,
            "blacklist.save",
            "firewall blacklist (ipset save)",
        ),
        (LEGACY_ETC, "config.toml", "configuration"),
    ];
    for (root, file, label) in pairs {
        let from = Path::new(root).join(file);
        let to = if root == LEGACY_VAR {
            var(file)
        } else {
            etc(file)
        };
        if adopt(&from, &to) {
            done.push(format!(
                "{} ({} -> {})",
                label,
                from.display(),
                to.display()
            ));
        }
    }
    done
}
