# SIH1649 → NIMBUSA — Requirement Mapping

**SIH1649 — DDoS Protection System for Cloud: Architecture and Tool**
Ministry of Defence (MoD) · SAG, DRDO · Theme: *Blockchain & Cybersecurity*

Each problem-statement requirement mapped to the NIMBUSA feature that implements
it, with the source module and the tests that cover it.

| PS requirement | NIMBUSA feature | Where | Tests |
|----------------|-----------------|-------|-------|
| Suspicious amount of traffic from one IP / IP range | Source-level anomaly detection + per-source risk scoring + temporary, TTL'd mitigation | `detect.rs` (source-concentration signal, `rank_suspects`), `mitigate.rs` | `single_source_http_flood_is_detected_and_named`, `low_scoring_sources_are_not_blocked` |
| Many sources sharing a behavioural profile (coordinated) | Behaviour-similarity analysis: IP×endpoint coordination + user-agent uniformity + request-count uniformity (CV) | `detect.rs` (`sources_on_top_endpoint`, `uniformity`, behaviour signal) | `distributed_flood_is_detected_even_though_no_single_ip_stands_out`, `uniformity_separates_scripts_from_people` |
| Surge against a single endpoint | Endpoint-concentration signal (raw-path, query-stripped, not id-folded to preserve diversity) | `detect.rs`, `window.rs`, `accesslog.rs` | `endpoint_exhaustion_from_a_few_sources`, `concentration_and_diversity_are_distinguishable` |
| Odd / unusual traffic patterns | Temporal anomaly (per-hour-of-day baseline) + burst detection (10s vs window) | `detect.rs`, `baseline.rs` | `hourly_profile_separates_quiet_and_busy_hours`, `short_burst_is_classified_as_a_burst` |
| Automatic **detection** | Multi-signal detection engine (9 weighted, explainable signals; no single threshold) | `detect.rs::assess` | `normal_traffic_scores_normal`, `every_reason_carries_a_measurement`, `score_never_exceeds_one_hundred` |
| Distinguish attacks from legitimate spikes | False-positive damping → **TRAFFIC SURGE** verdict (diverse + healthy + low similarity) | `detect.rs` (`benign_surge`) | `legitimate_traffic_spike_is_not_called_an_attack` |
| Automatic **protection** / mitigation | Layered, isolated, TTL'd mitigation engine (rate-limit → filter → conn-limit → network-block → SYN-protect) via ipset/iptables | `mitigate.rs` | `escalation_is_cumulative`, `every_automatic_rule_has_a_ttl`, `block_cap_is_respected` |
| Automatic **recovery** | Recovery state machine with cooldown + health-verified rollback | `recovery.rs` | `full_lifecycle_reaches_protected_then_returns_to_normal`, `one_quiet_sample_does_not_trigger_rollback`, `attack_returning_during_cooldown_re_escalates` |
| Reversible protection (no permanent damage) | Automatic rules isolated in `NIMBUSA-DDOS` chain + `nimbusa_ddos*` ipsets; rollback flushes only NIMBUSA's own state | `mitigate.rs` | `rollback_clears_recorded_state`, `whitelisted_source_is_never_blocked` |
| **High availability** | Health-aware mitigation, graceful degradation, health-verified rollback, measured downtime/availability | `health.rs`, `recovery.rs`, `incident.rs` | `downtime_is_measured_not_assumed`, `availability_comes_from_measured_downtime` |
| Attacks originating **inside** the cloud | Internal (docker-bridge) traffic/connection anomaly detection + classification | `telemetry.rs`, `detect.rs` (`InternalAnomaly`) | `internal_container_anomaly_is_separated_from_edge_traffic` |
| Connection-layer attacks | Connection/SYN exhaustion detection + connection limiting + SYN ceiling | `telemetry.rs`, `detect.rs`, `mitigate.rs` | `connection_flood_without_http_requests` |
| Incident management / reporting | Unique incident ids (`NIMBUSA-DDOS-YYYYMMDD-NNNN`), full records with measured metrics, timeline, CLI/TUI reports, JSON export | `incident.rs`, `cli.rs` | `ids_increment_within_a_day_and_reset_across_days`, `absorb_keeps_the_worst_case`, `incident_round_trips_through_json` |
| **Theme: Blockchain & Cybersecurity** | Tamper-evident SHA-256 hash chain over every security event; `audit verify` detects edit/delete/reorder/forge; optional external anchor (`AuditSink` / `BlockchainAnchorSink`) that never gates protection | `audit.rs`, `sha256.rs` | `editing_a_past_record_is_detected`, `deleting_a_record_is_detected`, `reordering_records_is_detected`, `appending_a_forged_record_is_detected`, `a_failing_anchor_never_breaks_the_local_chain`, `nist_vectors` |
| Architecture **and tool** | Full CLI + SOC-style TUI + headless systemd engine; single Rust binary | `cli.rs`, `main.rs`, `ui_shield.rs`, `engine.rs`, `scripts/` | (integration on the VPS) |
| Configurable / tunable | Validated `/etc/nimbusa/config.toml`; `config validate` reports corrections | `config.rs` | `out_of_range_is_clamped_not_fatal`, `unordered_thresholds_reset`, `round_trips_through_toml` |
| Safe demonstrability | Local-only synthetic simulator (never targets third parties), flagged end-to-end | `simulate.rs`, `cli.rs` | `distributed_produces_many_sources_no_single_dominant`, `burst_is_silent_except_one_tick`, `simulated_incidents_are_flagged` |

## The pipeline, mapped

```
OBSERVE   telemetry.rs   /proc counters, connection census
COLLECT   accesslog.rs   incremental Traefik log tail
NORMALIZE window.rs      bounded rolling windows
BASELINE  baseline.rs    attack-aware EWMA + hourly profile
DETECT    detect.rs      9-signal assessment
CLASSIFY  detect.rs      attack type from fired signals
SCORE     detect.rs      0–100, banded
EXPLAIN   detect.rs      measurement-backed reasons
MITIGATE  mitigate.rs    isolated, TTL'd, reversible
VERIFY    health.rs      application health correlation
RECOVER   recovery.rs    cooldown + health-verified rollback
AUDIT     audit.rs       SHA-256 tamper-evident chain
```

## Test coverage summary

131 unit tests in the library crate cover risk scoring, anomaly detection,
baseline (incl. attack-poisoning resistance), classification of every attack
type, source/endpoint scoring, whitelist protection, rule TTLs, mitigation
policy/escalation, the recovery state machine, incident persistence, the hash
chain (tamper/forge/reorder detection), configuration validation, access-log
parsing, and the simulator. Run with `cargo test --lib`.
