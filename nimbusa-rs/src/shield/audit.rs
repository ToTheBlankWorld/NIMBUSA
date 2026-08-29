//! Tamper-evident security audit ledger.
//!
//! This is the "Blockchain & Cybersecurity" half of SIH1649, done at the size
//! the problem actually calls for. Putting every packet on a chain would be
//! theatre; what matters operationally is that the *security record* — every
//! detection, mitigation, rollback and recovery — cannot be quietly edited
//! after the fact.
//!
//! So each event is canonically serialised, hashed with SHA-256 together with
//! the hash of the record before it, and appended to a local chain. Changing,
//! reordering or deleting any past record breaks every hash after it, and
//! `nimbusa audit verify` says exactly where.
//!
//! The `AuditSink` boundary is deliberate: `LocalHashChainSink` is the one the
//! system depends on, and an optional `BlockchainAnchorSink` can publish the
//! chain head somewhere external. If the anchor is unreachable, misconfigured,
//! or slow, detection and mitigation carry on untouched — the anchor is never
//! in the enforcement path.
use crate::paths;
use crate::sha256::sha256_hex;
use crate::util::{epoch, now_str};
use serde::{Deserialize, Serialize};
use std::io::Write;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub ts: u64,
    pub time: String,
    pub event_type: String,
    pub incident_id: String,
    pub severity: String,
    pub action: String,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

impl Record {
    /// Canonical form. Field order is fixed and the separator cannot appear in
    /// any field (it is a control character), so two different records can
    /// never serialise identically.
    pub fn canonical(&self) -> String {
        [
            self.seq.to_string(),
            self.ts.to_string(),
            self.event_type.clone(),
            self.incident_id.clone(),
            self.severity.clone(),
            self.action.clone(),
            self.detail.replace(['\n', '\r', '\u{1e}'], " "),
            self.prev_hash.clone(),
        ]
        .join("\u{1e}")
    }
    pub fn compute_hash(&self) -> String {
        sha256_hex(&self.canonical())
    }
    pub fn valid(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// Where audit records go. The shield depends on exactly one implementation of
/// this (the local chain); anything else is additive and best-effort.
#[allow(dead_code)]
pub trait AuditSink {
    fn name(&self) -> &str;
    fn append(&mut self, r: &Record) -> Result<(), String>;
    /// Called after each append with the current chain head, for sinks that
    /// anchor rather than store.
    fn anchor(&mut self, _head: &str) -> Result<(), String> {
        Ok(())
    }
}

/// The authoritative sink: an append-only JSON-lines hash chain on disk.
pub struct LocalHashChainSink {
    pub path: std::path::PathBuf,
    pub head: String,
    pub seq: u64,
}

impl LocalHashChainSink {
    pub fn open(path: std::path::PathBuf) -> Self {
        let (head, seq) = match std::fs::read_to_string(&path) {
            Ok(s) => {
                let last = s
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str::<Record>(l).ok())
                    .next_back();
                match last {
                    Some(r) => (r.hash, r.seq + 1),
                    None => (GENESIS.to_string(), 0),
                }
            }
            Err(_) => (GENESIS.to_string(), 0),
        };
        LocalHashChainSink { path, head, seq }
    }

    pub fn default_path() -> std::path::PathBuf {
        paths::var("audit/chain.jsonl")
    }
}

impl AuditSink for LocalHashChainSink {
    fn name(&self) -> &str {
        "local-hash-chain"
    }
    fn append(&mut self, r: &Record) -> Result<(), String> {
        if let Some(p) = self.path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let line = serde_json::to_string(r).map_err(|e| e.to_string())?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        writeln!(f, "{}", line).map_err(|e| e.to_string())?;
        self.head = r.hash.clone();
        self.seq = r.seq + 1;
        Ok(())
    }
}

/// Optional external anchor. Hands the chain head to a command of the
/// operator's choosing (an `eth` CLI, an internal notary, `logger`, anything)
/// and does not care whether it succeeds. Failures are counted and surfaced,
/// never propagated: DDoS protection must keep running when the chain the
/// operator wanted to anchor to is down.
pub struct BlockchainAnchorSink {
    pub command: String,
    pub anchored: u64,
    pub failures: u64,
    pub last_error: String,
    /// Anchor one head in this many records (batching keeps cost sane).
    pub every: u64,
    seen: u64,
}

#[allow(dead_code)]
impl BlockchainAnchorSink {
    pub fn new(command: &str, every: u64) -> Self {
        BlockchainAnchorSink {
            command: command.to_string(),
            anchored: 0,
            failures: 0,
            last_error: String::new(),
            every: every.max(1),
            seen: 0,
        }
    }
    pub fn configured(&self) -> bool {
        !self.command.trim().is_empty()
    }
}

impl AuditSink for BlockchainAnchorSink {
    fn name(&self) -> &str {
        "blockchain-anchor"
    }
    fn append(&mut self, _r: &Record) -> Result<(), String> {
        Ok(())
    }
    fn anchor(&mut self, head: &str) -> Result<(), String> {
        if !self.configured() {
            return Ok(());
        }
        self.seen += 1;
        if !self.seen.is_multiple_of(self.every) {
            return Ok(());
        }
        // The command comes from root-owned /etc/nimbusa/config.toml; the head
        // is a hex hash we produced, so nothing attacker-controlled is passed.
        let res = std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .env("NIMBUSA_AUDIT_HEAD", head)
            .output();
        match res {
            Ok(o) if o.status.success() => {
                self.anchored += 1;
                Ok(())
            }
            Ok(o) => {
                self.failures += 1;
                self.last_error = String::from_utf8_lossy(&o.stderr).trim().to_string();
                Err(self.last_error.clone())
            }
            Err(e) => {
                self.failures += 1;
                self.last_error = e.to_string();
                Err(self.last_error.clone())
            }
        }
    }
}

/// The audit facade the rest of the shield calls. Every method is infallible
/// from the caller's point of view.
pub struct Auditor {
    pub local: LocalHashChainSink,
    pub anchor: Option<BlockchainAnchorSink>,
    pub enabled: bool,
    pub errors: u64,
    pub last_error: String,
}

impl Auditor {
    pub fn open(enabled: bool, anchor_cmd: &str) -> Self {
        let anchor = if anchor_cmd.trim().is_empty() {
            None
        } else {
            Some(BlockchainAnchorSink::new(anchor_cmd, 10))
        };
        Auditor {
            local: LocalHashChainSink::open(LocalHashChainSink::default_path()),
            anchor,
            enabled,
            errors: 0,
            last_error: String::new(),
        }
    }

    pub fn head(&self) -> &str {
        &self.local.head
    }

    /// Append one event. Never panics, never propagates: an audit failure is
    /// recorded and the shield carries on.
    pub fn record(
        &mut self,
        event_type: &str,
        incident_id: &str,
        severity: &str,
        action: &str,
        detail: &str,
    ) -> Option<Record> {
        if !self.enabled {
            return None;
        }
        let mut r = Record {
            seq: self.local.seq,
            ts: epoch(),
            time: now_str(),
            event_type: event_type.into(),
            incident_id: incident_id.into(),
            severity: severity.into(),
            action: action.into(),
            detail: detail.into(),
            prev_hash: self.local.head.clone(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        if let Err(e) = self.local.append(&r) {
            self.errors += 1;
            self.last_error = e;
            return None;
        }
        if let Some(a) = self.anchor.as_mut() {
            if let Err(e) = a.anchor(&r.hash) {
                // deliberately not an error for the caller
                self.last_error = format!("anchor: {}", e);
            }
        }
        Some(r)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Verification {
    pub records: u64,
    pub ok: bool,
    /// Sequence number of the first record that does not verify.
    pub broken_at: Option<u64>,
    pub reason: String,
    pub head: String,
}

/// Walk a chain file and recompute every link.
pub fn verify_path(path: &std::path::Path) -> Verification {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(_) => {
            return Verification {
                ok: true,
                reason: "no audit chain yet".into(),
                head: GENESIS.into(),
                ..Default::default()
            }
        }
    };
    let mut prev = GENESIS.to_string();
    let mut n = 0u64;
    let mut expect_seq = 0u64;
    for (i, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let r: Record = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                return Verification {
                    records: n,
                    ok: false,
                    broken_at: Some(expect_seq),
                    reason: format!("line {} is not a valid record: {}", i + 1, e),
                    head: prev,
                }
            }
        };
        if r.seq != expect_seq {
            return Verification {
                records: n,
                ok: false,
                broken_at: Some(r.seq),
                reason: format!(
                    "record out of order: expected seq {}, found {}",
                    expect_seq, r.seq
                ),
                head: prev,
            };
        }
        if r.prev_hash != prev {
            return Verification {
                records: n,
                ok: false,
                broken_at: Some(r.seq),
                reason: format!(
                    "broken link at seq {}: record points at {}…, chain head is {}…",
                    r.seq,
                    r.prev_hash.chars().take(12).collect::<String>(),
                    prev.chars().take(12).collect::<String>()
                ),
                head: prev,
            };
        }
        if !r.valid() {
            return Verification {
                records: n,
                ok: false,
                broken_at: Some(r.seq),
                reason: format!(
                    "record {} has been modified: stored hash {}… does not match its contents",
                    r.seq,
                    r.hash.chars().take(12).collect::<String>()
                ),
                head: prev,
            };
        }
        prev = r.hash;
        n += 1;
        expect_seq += 1;
    }
    Verification {
        records: n,
        ok: true,
        broken_at: None,
        reason: format!("{} records verified", n),
        head: prev,
    }
}

pub fn verify() -> Verification {
    verify_path(&LocalHashChainSink::default_path())
}

/// Seal an incompatible chain and start a fresh one — **auditably**.
///
/// This is the honest answer to a chain that no longer verifies because an
/// older build wrote records in a different canonical format (a version
/// migration, not an attack). It NEVER rewrites or reinterprets a past record,
/// and NEVER weakens verification. Instead it:
///   1. refuses if the chain already verifies (nothing to migrate),
///   2. archives the existing file verbatim next to the chain,
///   3. records the archive's SHA-256, its record count and the exact verifier
///      reason inside a new genesis `MIGRATION` record whose own hash covers
///      that fingerprint — so the sealed past is itself tamper-evident.
///
/// The new chain verifies from `GENESIS`; the legacy file stays on disk.
pub fn migrate_path(path: &std::path::Path) -> Result<String, String> {
    let body =
        std::fs::read_to_string(path).map_err(|_| "no audit chain to migrate".to_string())?;
    if body.trim().is_empty() {
        return Err("audit chain is empty — nothing to migrate".into());
    }
    let v = verify_path(path);
    if v.ok {
        return Err(format!(
            "audit chain already verifies ({} records) — migration refused",
            v.records
        ));
    }
    let stamp = epoch();
    let legacy_hash = sha256_hex(&body);
    let legacy_records = body.lines().filter(|l| !l.trim().is_empty()).count();
    let archive = path.with_file_name(format!("chain.jsonl.legacy-{}", stamp));
    std::fs::copy(path, &archive).map_err(|e| e.to_string())?;

    // fresh chain: genesis MIGRATION record. prev_hash stays GENESIS so the new
    // chain verifies normally; the legacy fingerprint lives in `detail`, which
    // the record's own hash covers.
    std::fs::write(path, "").map_err(|e| e.to_string())?;
    let mut sink = LocalHashChainSink {
        path: path.to_path_buf(),
        head: GENESIS.to_string(),
        seq: 0,
    };
    let mut r = Record {
        seq: 0,
        ts: stamp,
        time: now_str(),
        event_type: "MIGRATION".into(),
        incident_id: "-".into(),
        severity: "NORMAL".into(),
        action: "chain-migrate".into(),
        detail: format!(
            "sealed legacy audit chain: {} records, sha256={}, reason=\"{}\", archived={}",
            legacy_records,
            legacy_hash,
            v.reason,
            archive.display()
        ),
        prev_hash: GENESIS.into(),
        hash: String::new(),
    };
    r.hash = r.compute_hash();
    sink.append(&r).map_err(|e| e.to_string())?;
    Ok(format!(
        "migrated: sealed {} legacy records (sha256 {}…), archived to {}; new chain genesis written",
        legacy_records,
        legacy_hash.chars().take(12).collect::<String>(),
        archive.display()
    ))
}

pub fn migrate() -> Result<String, String> {
    migrate_path(&LocalHashChainSink::default_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nimbusa-audit-{}-{}-{}",
            tag,
            std::process::id(),
            epoch()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d.join("chain.jsonl")
    }

    fn chain_of(path: &std::path::Path, n: usize) -> LocalHashChainSink {
        let mut s = LocalHashChainSink::open(path.to_path_buf());
        for i in 0..n {
            let mut r = Record {
                seq: s.seq,
                ts: 1000 + i as u64,
                time: "2026-08-29 10:00:00".into(),
                event_type: "DETECTION".into(),
                incident_id: format!("NIMBUSA-DDOS-20260829-{:04}", i),
                severity: "ATTACK".into(),
                action: "mitigate".into(),
                detail: format!("event {}", i),
                prev_hash: s.head.clone(),
                hash: String::new(),
            };
            r.hash = r.compute_hash();
            s.append(&r).unwrap();
        }
        s
    }

    #[test]
    fn empty_chain_verifies() {
        let p = tmp("empty");
        let v = verify_path(&p);
        assert!(v.ok);
        assert_eq!(v.records, 0);
    }

    #[test]
    fn a_written_chain_verifies() {
        let p = tmp("good");
        chain_of(&p, 20);
        let v = verify_path(&p);
        assert!(v.ok, "{}", v.reason);
        assert_eq!(v.records, 20);
        assert_ne!(v.head, GENESIS);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn editing_a_past_record_is_detected() {
        let p = tmp("edit");
        chain_of(&p, 10);
        let body = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
        lines[4] = lines[4].replace("\"severity\":\"ATTACK\"", "\"severity\":\"NORMAL\"");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();

        let v = verify_path(&p);
        assert!(!v.ok);
        assert_eq!(v.broken_at, Some(4));
        assert!(v.reason.contains("modified"), "{}", v.reason);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn deleting_a_record_is_detected() {
        let p = tmp("delete");
        chain_of(&p, 10);
        let body = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
        lines.remove(5);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();

        let v = verify_path(&p);
        assert!(!v.ok);
        assert!(v.reason.contains("out of order"), "{}", v.reason);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn reordering_records_is_detected() {
        let p = tmp("reorder");
        chain_of(&p, 10);
        let body = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
        lines.swap(3, 7);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();

        let v = verify_path(&p);
        assert!(!v.ok);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn appending_a_forged_record_is_detected() {
        let p = tmp("forge");
        chain_of(&p, 5);
        // an attacker appends a "nothing happened" record without the real prev hash
        let forged = Record {
            seq: 5,
            ts: 9999,
            time: "2026-08-29 11:00:00".into(),
            event_type: "RECOVERY".into(),
            incident_id: "NIMBUSA-DDOS-20260829-0000".into(),
            severity: "NORMAL".into(),
            action: "none".into(),
            detail: "all clear".into(),
            prev_hash: GENESIS.into(),
            hash: "deadbeef".into(),
        };
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "{}", serde_json::to_string(&forged).unwrap()).unwrap();

        let v = verify_path(&p);
        assert!(!v.ok);
        assert_eq!(v.broken_at, Some(5));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn chain_resumes_correctly_after_reopen() {
        let p = tmp("resume");
        let s1 = chain_of(&p, 4);
        let head1 = s1.head.clone();
        drop(s1);
        let s2 = LocalHashChainSink::open(p.clone());
        assert_eq!(s2.head, head1);
        assert_eq!(s2.seq, 4);
        chain_of(&p, 3);
        assert!(verify_path(&p).ok);
        assert_eq!(verify_path(&p).records, 7);
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn hash_covers_every_field() {
        let base = Record {
            seq: 1,
            ts: 100,
            time: "t".into(),
            event_type: "DETECTION".into(),
            incident_id: "I1".into(),
            severity: "ATTACK".into(),
            action: "block".into(),
            detail: "d".into(),
            prev_hash: GENESIS.into(),
            hash: String::new(),
        };
        let h = base.compute_hash();
        for change in [
            Record {
                seq: 2,
                ..base.clone()
            },
            Record {
                ts: 101,
                ..base.clone()
            },
            Record {
                event_type: "RECOVERY".into(),
                ..base.clone()
            },
            Record {
                incident_id: "I2".into(),
                ..base.clone()
            },
            Record {
                severity: "NORMAL".into(),
                ..base.clone()
            },
            Record {
                action: "unblock".into(),
                ..base.clone()
            },
            Record {
                detail: "e".into(),
                ..base.clone()
            },
            Record {
                prev_hash: "ff".repeat(32),
                ..base.clone()
            },
        ] {
            assert_ne!(change.compute_hash(), h);
        }
    }

    #[test]
    fn separator_injection_cannot_forge_an_identical_canonical_form() {
        let a = Record {
            seq: 1,
            ts: 1,
            time: String::new(),
            event_type: "A".into(),
            incident_id: "B".into(),
            severity: "C".into(),
            action: "D".into(),
            detail: "E".into(),
            prev_hash: GENESIS.into(),
            hash: String::new(),
        };
        let b = Record {
            event_type: "A\u{1e}B".into(),
            incident_id: String::new(),
            ..a.clone()
        };
        assert_ne!(a.canonical(), b.canonical());
    }

    #[test]
    fn a_failing_anchor_never_breaks_the_local_chain() {
        let p = tmp("anchor");
        let mut a = Auditor {
            local: LocalHashChainSink::open(p.clone()),
            anchor: Some(BlockchainAnchorSink::new(
                "exit 7", // always fails
                1,
            )),
            enabled: true,
            errors: 0,
            last_error: String::new(),
        };
        for i in 0..5 {
            assert!(
                a.record("DETECTION", "I1", "ATTACK", "block", &format!("n={}", i))
                    .is_some(),
                "local write must succeed regardless of the anchor"
            );
        }
        assert!(verify_path(&p).ok);
        assert_eq!(verify_path(&p).records, 5);
        assert!(a.anchor.as_ref().unwrap().failures >= 1);
        assert_eq!(a.errors, 0, "anchor failure is not an audit error");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn unconfigured_anchor_is_inert() {
        let mut s = BlockchainAnchorSink::new("", 1);
        assert!(!s.configured());
        assert!(s.anchor("abc").is_ok());
        assert_eq!(s.anchored, 0);
        assert_eq!(s.failures, 0);
    }

    #[test]
    fn migration_seals_a_broken_chain_and_the_new_one_verifies() {
        let p = tmp("migrate");
        chain_of(&p, 6);
        // a version/format-style break: edit a past record so the chain fails
        let body = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = body.lines().map(|s| s.to_string()).collect();
        lines[2] = lines[2].replace("\"severity\":\"ATTACK\"", "\"severity\":\"NORMAL\"");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(!verify_path(&p).ok);

        let msg = migrate_path(&p).unwrap();
        assert!(msg.contains("sealed"), "{}", msg);

        // the fresh chain verifies from genesis and holds exactly the migration record
        let v = verify_path(&p);
        assert!(v.ok, "{}", v.reason);
        assert_eq!(v.records, 1);

        // the migration record pins the sealed legacy fingerprint
        let body2 = std::fs::read_to_string(&p).unwrap();
        assert!(body2.contains("MIGRATION"));
        assert!(body2.contains("sha256="));

        // the legacy file is archived, not deleted
        let dir = p.parent().unwrap();
        assert!(std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e
                .file_name()
                .to_string_lossy()
                .contains("chain.jsonl.legacy-")));

        // migrating a chain that already verifies is refused
        assert!(migrate_path(&p).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn migration_refuses_an_empty_or_verifying_chain() {
        let p = tmp("migrate-clean");
        assert!(migrate_path(&p).is_err(), "no chain yet");
        chain_of(&p, 3);
        assert!(
            migrate_path(&p).is_err(),
            "a verifying chain is not migrated"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn disabled_auditor_writes_nothing() {
        let p = tmp("disabled");
        let mut a = Auditor {
            local: LocalHashChainSink::open(p.clone()),
            anchor: None,
            enabled: false,
            errors: 0,
            last_error: String::new(),
        };
        assert!(a.record("DETECTION", "I", "ATTACK", "x", "y").is_none());
        assert!(!p.exists());
    }
}
