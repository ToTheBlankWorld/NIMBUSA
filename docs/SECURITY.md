# NIMBUSA — Security of the tool itself

NIMBUSA is a security product, so it is built to be safe to run as root on a
production VPS.

## Privilege model

- The tool runs as root (it programs ipset/iptables). Non-root users may run it
  only if they are in the `nimbusa` group **and** already administrators; the
  binary then re-execs itself via a scoped sudoers drop-in. Access is granted
  from the Settings tab and requires sudo first.
- If not privileged, the shield runs **observe-only**: it detects and explains
  but records rather than enforces, and the UI shows `applied: false` instead of
  claiming protection that is not installed.

## No shell injection surface

- `sh()` runs only *fixed, literal* command strings and is never fed outside
  data.
- Everything carrying an IP, CIDR, domain, username or container name goes
  through `run()` / `run_status()`, which pass an explicit **argv** to `execve`
  — there is no shell, so no metacharacter surface.
- Every such value is validated first: `valid_ip`, `valid_ip_or_cidr`,
  `valid_domain`, `valid_username`. Inputs like `1.2.3.4; reboot`, `$(id)`,
  `` `id` `` or `--help` are rejected before any command runs. These rejections
  are unit-tested (`util`, `firewall`, `mitigate`).

## Firewall safety

- Automatic DDoS mitigation is fully isolated from permanent firewall state (see
  [RECOVERY.md](RECOVERY.md)). A failed or half-applied mitigation cannot damage
  the blacklist, whitelist, fail2ban, or Docker rules.
- Whitelisted addresses can never be auto-blocked, banned or blacklisted.
- Every automatic rule has a TTL; nothing NIMBUSA installs is permanent.

## State integrity

- All state files are written atomically (temp file + rename), so a crash
  mid-write never leaves a corrupt file.
- Corrupt or absurd persisted state (baseline, rules) is rejected and rebuilt
  rather than trusted — a corrupt baseline would otherwise silently suppress
  detection.
- The audit chain is append-only and hash-linked; tampering is detectable
  (`nimbusa audit verify`).

## Tamper-evident audit

Each security event (detection, mitigation, cooldown, rollback, recovery) is
canonically serialised and SHA-256 hash-chained to the previous record. Editing,
deleting, reordering or forging a record breaks every hash after it, and verify
reports exactly where. The SHA-256 primitive is implemented in-tree (verified
against NIST vectors) so the chain works on an air-gapped box with no external
crate to fetch.

An optional external anchor (`audit.anchor_cmd`) can publish the chain head to a
notary or blockchain. It is **best-effort only**: if it is unreachable,
misconfigured or slow, detection and mitigation are unaffected — the anchor is
never in the enforcement path.

## Data handling

- User-activity views read only system-level metadata (logins, sudo, processes);
  they never read anyone's `$HOME` or shell history.
- The operator's email/identity is used only for local attribution; nothing is
  sent to an external service.

## Fail-safe posture

The guiding rule throughout: **when NIMBUSA is unsure or something fails, it
leans toward availability and toward preserving existing firewall/whitelist
state — never toward blocking legitimate users or dropping protections it
cannot prove are safe to drop.**
