# NIMBUSA — Threat Model

For each threat: how NIMBUSA **detects** it, how it **mitigates**, how it
**recovers**, and the **residual risk** that remains.

---

### Volumetric attack (bandwidth/packet surge)
- **Detection** — traffic-anomaly signal (bytes/s and packets/s vs baseline,
  ratio + z-score, with an absolute floor).
- **Mitigation** — rate limiting; source/network blocking of the heaviest
  offenders (TTL'd).
- **Recovery** — automatic rollback once traffic normalises and health is
  verified.
- **Residual** — a flood large enough to saturate the **upstream link** cannot
  be absorbed by a single VPS; upstream/ISP scrubbing is required (see
  [LIMITATIONS.md](LIMITATIONS.md)).

### HTTP flood (single source)
- **Detection** — request-rate + source-concentration signals; one address
  holding a large share.
- **Mitigation** — per-source rate limiting; temporary block of the source
  (TTL'd).
- **Recovery** — block expires by TTL; rollback on recovery.
- **Residual** — a source rotating IPs quickly is handled as a distributed
  flood.

### Distributed HTTP flood (botnet)
- **Detection** — many requesting sources, none dominant, converging on the
  same endpoint with uniform behaviour (IP×endpoint coordination + user-agent /
  request-count uniformity).
- **Mitigation** — rate limiting; block high-scoring sources; /24 network blocks
  for thinly-spread floods; connection limiting at higher levels.
- **Recovery** — TTL expiry + health-verified rollback.
- **Residual** — an extremely large, highly-diverse botnet at line rate reaches
  the upstream-saturation boundary.

### Endpoint exhaustion
- **Detection** — endpoint-concentration signal (one resource absorbing a large
  share) from a few sources.
- **Mitigation** — rate limiting; block the concentrating sources.
- **Recovery** — TTL + rollback.
- **Residual** — a legitimately hot endpoint is protected from being called an
  attack by the diversity/health checks.

### Connection / SYN exhaustion
- **Detection** — connection-anomaly signal (creation rate, established ratio,
  half-open share) with little HTTP; SYN packet rate.
- **Mitigation** — connection limiting per source; SYN-rate ceiling (L5);
  connection-only offenders are still mitigable (no access-log trace needed).
- **Recovery** — rollback on recovery.
- **Residual** — kernel-level SYN cookies (OS config) complement this.

### Burst attack
- **Detection** — a spike present in the last 10 s but not across the window.
- **Mitigation** — rate limiting; short-lived blocks.
- **Recovery** — fast, since the burst is short.
- **Residual** — very short bursts may end before mitigation fully engages; the
  incident and audit record still capture them.

### Internal cloud / container-origin abuse
- **Detection** — docker-bridge traffic/connection anomaly while edge HTTP stays
  quiet (`InternalAnomaly`).
- **Mitigation** — surfaced as an incident with the offending container context;
  network/rate controls apply.
- **Recovery** — rollback on normalisation.
- **Residual** — deep per-container network policy is the container platform's
  job; NIMBUSA flags and correlates.

### SSH brute force / malicious automation
- **Detection** — existing IP intelligence (incremental auth-log parsing),
  attempt counts, country/network.
- **Mitigation** — fail2ban ban / permanent blacklist (operator-owned layer).
- **Recovery** — manual (permanent by intent).
- **Residual** — standard fail2ban limits apply.

### False-positive traffic surge (flash crowd)
- **Detection** — high volume but diverse sources/resources, low similarity,
  healthy app → classified **TRAFFIC SURGE**, score held below ATTACK.
- **Mitigation** — none (monitor). This is the point: legitimate spikes are not
  blocked.
- **Residual** — a botnet perfectly mimicking a diverse healthy crowd is the
  hardest case; the health and coordination signals still push it up as it
  starts to hurt the application.

### Firewall manipulation / state corruption
- **Detection** — health check verifies the enforcement path is actually
  present; corrupt state files are detected on load.
- **Mitigation** — automatic mitigation is isolated in its own chain/ipsets;
  permanent rules preserved; corrupt baseline/rules rebuilt.
- **Residual** — an attacker with root on the box is out of scope (they own the
  guard too).

### NIMBUSA privilege abuse
- **Detection** — access is limited to root + the `nimbusa` group (sudo-gated);
  granting is explicit.
- **Mitigation** — scoped sudoers drop-in; argv-only command execution; input
  validation everywhere.
- **Residual** — misgranting group membership is an operator responsibility.

### Audit tampering
- **Detection** — SHA-256 hash chain; `nimbusa audit verify` detects any edit,
  deletion, reorder or forgery and names the first broken record.
- **Mitigation** — optional external anchor for off-box notarisation.
- **Residual** — an attacker who can rewrite the whole chain *and* re-anchor is
  out of scope; detection of local tampering is guaranteed.
