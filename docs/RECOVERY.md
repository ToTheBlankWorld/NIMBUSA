# NIMBUSA SHIELD — Mitigation & Recovery

## Mitigation engine (`shield/mitigate.rs`)

Two invariants govern everything:

1. **Temporary state is isolated.** Every automatic rule lives in the
   `NIMBUSA-DDOS` iptables chain and the `nimbusa_ddos` / `nimbusa_ddos_net`
   ipsets. Nothing else writes there, so rolling back is a flush of structures
   NIMBUSA owns — the permanent blacklist, whitelist, fail2ban and Docker's own
   rules are untouched by construction.
2. **Nothing is applied that cannot expire.** Every ipset entry carries a
   kernel-side `timeout`. Even if the process is killed mid-incident, the blocks
   drain by themselves.

Every recorded rule carries `incident_id`, `reason`, `level`, `created`,
`expires`, and an `applied` flag (false when the process lacks privilege, so the
UI never claims protection that is not really installed).

### Escalation levels (cumulative)

| Level | Action |
|------:|--------|
| L0 | Observe only |
| L1 | Adaptive per-source rate limiting (hashlimit on :80/:443) |
| L2 | Source scoring |
| L3 | Temporary filtering — block the worst-scoring sources (TTL'd) |
| L4 | + connection limiting + /24 network blocks for thinly-spread floods |
| L5 | + SYN-flood protection |

Escalation is cumulative: L4 keeps L1–L3 in place. The level is chosen from the
threat band, raised one step when the application is already failing.

### Safety rules

- A **whitelisted** address (or a member of a whitelisted /24, or the
  operator's own SSH source) is **never** auto-blocked — the attempt returns
  `MITIGATION_SKIPPED_WHITELIST` and no rule is even recorded.
- Private addresses are refused (`MITIGATION_SKIPPED_PRIVATE`).
- Invalid targets are refused before any firewall call
  (`MITIGATION_SKIPPED_INVALID`) — the firewall is only ever driven via explicit
  argv, never a shell string.
- A hard ceiling (`max_auto_blocks`) caps the blast radius; beyond it, remaining
  sources are left to rate limiting.
- Only sources that scored high enough on their *own* evidence (rate + share +
  connections) are blocked — never every address that appeared in the window.

## Recovery state machine (`shield/recovery.rs`)

A pure function of `(previous state, observation)`, unit-tested without a
firewall:

```
NORMAL → ANOMALY → ATTACK_DETECTED → MITIGATING → PROTECTED
                                          │              │
                                     (worsens)      (subsides)
                                          ▼              ▼
                                      ESCALATED    RECOVERY_PENDING
                                                        │
                                                   (cooldown +
                                                    healthy streak +
                                                    score down)
                                                        ▼
                                                   RECOVERING
                                                        ▼
                                                HEALTH_VERIFICATION
                                                        ▼
                                                     NORMAL
```

**Recovery is earned.** Leaving PROTECTED requires *all* of:

- the cooldown period to elapse (`cooldown_secs`);
- several consecutive healthy samples (`recovery_healthy_samples`);
- the score to fall back below the ATTACK band.

One quiet sample does nothing — an attacker pausing for five seconds cannot get
the defences torn down for free. If the attack returns during cooldown, the
machine re-escalates instead of rolling back. If the application is still
failing during HEALTH_VERIFICATION, the incident does not close.

## Automatic rollback

When recovery conditions are met, the engine flushes the `NIMBUSA-DDOS` chain
and ipsets (re-installing only the permanent drop *floor* so the path stays
wired for next time). Permanent rules, the blacklist ipset, fail2ban and
Docker's chains are never touched.

## Measured metrics (`shield/incident.rs`)

Nothing is a constant:

- **Detection time** = anomaly first seen → classified as an attack.
- **Mitigation time** = classified → first rule installed.
- **Recovery time** = cooldown started → back to NORMAL.
- **Downtime** = seconds a protected service was actually unreachable, summed
  from the health probes across the incident.
- **Availability** = `(duration − downtime) / duration`.

These come straight from the recovery machine's timestamps and the health
monitor. A `0 sec` downtime on the dashboard means the health probes saw the
application answer throughout — not that the number was hard-coded.

## Failure safety

- If telemetry fails, the shield does not panic, disable the firewall, or wipe
  state — that tick simply reads as quiet.
- If the audit system fails, DDoS protection continues (the failure is counted
  and surfaced, never propagated).
- If the baseline is corrupt, it is rebuilt.
- If the mitigation state file is corrupt, permanent rules are preserved.
