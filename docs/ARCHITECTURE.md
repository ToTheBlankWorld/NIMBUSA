# NIMBUSA — Architecture

## 1. Problem

SIH1649 asks for a DDoS protection system for cloud infrastructure that detects
suspicious traffic (from single sources, ranges, or coordinated distributed
sources), protects against it automatically, recovers automatically, maintains
high availability, and — under the *Blockchain & Cybersecurity* theme — keeps a
trustworthy security record.

## 2. Shape of the solution

One Rust binary on a Linux VPS. It keeps the original control-center
functionality (host, Docker/Traefik, SSH, users, permanent firewall, IP
intelligence) and adds **NIMBUSA SHIELD**, a background pipeline that never
blocks the UI.

```
                    INTERNET
                       │
                       ▼
              Traffic / Edge Intelligence
                       │
                       ▼
                    Traefik  (reverse proxy, access logs)
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
       Web Application           API
            └──────────┬──────────┘
                    SERVICES (Docker)

                  NIMBUSA SHIELD
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Telemetry       Detection       Health
    Engine          Engine         Monitor
        └──────────────┼──────────────┘
                       ▼
                 Risk Score Engine   (explainable, 9 signals)
                       ▼
                  Policy Engine      (threat band → level)
                       ▼
               Mitigation Engine
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
      ipset        iptables      rate/conn limit
        └──────────────┼──────────────┘
                       ▼
                Recovery Engine      (cooldown, health-verified rollback)
                       ▼
                Incident Engine
                       ▼
             Tamper-Evident Audit    (SHA-256 hash chain)
```

## 3. Threading & responsiveness

The TUI render loop never performs an expensive operation. Two background
mechanisms feed it:

- **System snapshot** (`main.rs::gather`) — host/docker/ssh/users/IP registry,
  fanned out across threads, polled non-blocking. Unchanged from the original
  design; the IP registry is still parsed incrementally by file offset.
- **Shield engine** (`shield::engine`) — owns all mutable shield state on its
  own thread, publishes an immutable `ShieldSnapshot` behind an
  `Arc<Mutex<…>>`. The UI/CLI only *read* that snapshot, so a firewall call can
  never happen on the render path, and the render path can never touch the
  firewall.

The engine ticks every `sample_interval_secs` (default 5). Each tick:

1. reads `/proc` counters → derives rates (no subprocess);
2. reads new Traefik access-log lines from a saved byte offset (never rescans);
3. folds them into bounded rolling windows;
4. probes application health on a slower cadence;
5. runs the detector → score, threat, attack type, explanation;
6. updates the baseline (skipped while the score is high);
7. drives the recovery state machine, which emits mitigation/rollback actions;
8. prunes expired rules;
9. appends any state changes to the audit chain;
10. publishes a fresh snapshot.

## 4. Data flow, stage by stage

| Stage | Module | Output |
|-------|--------|--------|
| OBSERVE / COLLECT | `telemetry`, `accesslog` | raw counters, parsed requests |
| NORMALIZE | `window` | bounded per-tick aggregates + rolling views |
| BASELINE | `baseline` | EWMA mean/variance per metric, hourly profile |
| DETECT / SCORE / EXPLAIN | `detect` | `Assessment` (score, signals, reasons) |
| CLASSIFY | `detect::classify` | `AttackType` |
| MITIGATE | `mitigate` | isolated, TTL'd firewall rules |
| VERIFY | `health` | per-service state, measured downtime |
| RECOVER | `recovery` | state machine + rollback |
| AUDIT | `audit`, `incident` | hash-chained incident ledger |

## 5. State on disk

```
/etc/nimbusa/config.toml           configuration (validated, self-documenting)
/etc/nimbusa/whitelist.txt         protected addresses (never auto-blocked)
/etc/nimbusa/blacklist.save        permanent ipset save
/var/lib/nimbusa/ips.json          IP intelligence registry (+ log offsets)
/var/lib/nimbusa/ddos/baseline.json    learned normal traffic
/var/lib/nimbusa/ddos/active_rules.json automatic mitigation rules (with TTL)
/var/lib/nimbusa/ddos/incidents.json    incident records
/var/lib/nimbusa/audit/chain.jsonl      tamper-evident audit chain
```

All writes are atomic (temp file + rename). Corrupt state is rejected and
rebuilt rather than trusted (a corrupt baseline would silently suppress
detection, so it is discarded).

## 6. Isolation of automatic mitigation

The permanent, operator-owned firewall (`nimbusa_blacklist` ipset + the
`nimbusa-firewall.sh` INPUT/DOCKER-USER rules, plus fail2ban) and the automatic
DDoS mitigation (`nimbusa_ddos` / `nimbusa_ddos_net` ipsets in the
`NIMBUSA-DDOS` chain) are completely separate structures. Rolling back an
incident flushes only what NIMBUSA owns. A failed or half-applied mitigation
therefore cannot damage permanent state, and the two layers can be reasoned
about independently.

## 7. Why not more infrastructure

No Kafka, Elasticsearch, Kubernetes, external database, or ML runtime. The
detector is explainable statistics over bounded windows; the audit chain is
SHA-256 in-tree. The whole system is one static binary that runs in a few MB of
RAM, which is what a VPS-resident guard needs to be. See
[DDOS.md](DDOS.md) for the detection detail and
[LIMITATIONS.md](LIMITATIONS.md) for the boundary.
