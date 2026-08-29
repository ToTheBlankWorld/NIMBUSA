# NIMBUSA SHIELD — Detection

## 1. Telemetry (`shield/telemetry.rs`)

Everything on the collection path is a `/proc` read; there are no subprocesses
in the hot loop. Kernel counters are cumulative, so each tick keeps the previous
reading and reports the delta as a rate. A counter that goes *down* (reboot,
interface reset, 32-bit wrap) reads as `0`, never as a huge spike.

Sources:

- `/proc/net/dev` — per-interface rx/tx bytes and packets; docker bridges
  (`docker0`, `br-*`) summed separately as *internal* traffic.
- `/proc/net/snmp` — TCP `PassiveOpens` (accepted connection rate),
  `AttemptFails`, `CurrEstab`.
- `/proc/net/sockstat` — socket pressure.
- `/proc/net/tcp[6]` — live connection census: ESTABLISHED / SYN-RECV /
  TIME-WAIT counts and per-remote-address connection maps (public vs internal).

## 2. Access-log intelligence (`shield/accesslog.rs`)

The Traefik access log (JSON or extended CLF) is read *forward only* from a
saved byte offset. A 2 GB log costs the same per tick as an empty one. Rotation
is detected by (inode, size); a shrunk/replaced file resumes at 0. A single tick
never ingests more than a hard byte cap, so a log that explodes during an attack
cannot turn the reader into the outage. A half-written trailing line is deferred
to the next tick.

Each request yields: source IP, method, host, path, status, bytes, user-agent,
duration. The **endpoint** is the path with its query string removed but *not*
id-folded — folding `/article/1` and `/article/2` together would make a news
site (a crowd reading different articles) look like a flood on one endpoint,
which is exactly the false positive to avoid. Raw-path diversity is a signal.

## 3. Rolling windows (`shield/window.rs`)

Per-tick aggregates are kept in a ring bounded by `window_seconds`. Every
distribution (by IP, endpoint, user-agent, host, method, /24 network,
IP×endpoint) is a `Bounded` map that folds anything past a key cap into a single
`(other)` bucket — so totals stay exact under a 100k-source flood while memory
cannot grow without bound. Rates are computed over the *observed* span, so 12 s
of data is never divided by 60.

## 4. Attack-aware baseline (`shield/baseline.rs`)

Each tracked metric keeps an exponentially-weighted mean and variance (a few
bytes, no history buffer), giving both a **ratio** ("18× normal") and a
**z-score** ("9σ out"). A per-hour-of-day request-rate profile provides the
temporal reference.

The baseline **freezes** once the score reaches `baseline.freeze_score`
(default 50): while an attack is in progress, samples are counted but not
learned. Without this, a sustained flood teaches the system that a flood is
normal and the next wave scores zero. Legitimate growth *below* the freeze
threshold is still learned. A persisted baseline that is non-finite or negative
is discarded and rebuilt.

## 5. Multi-signal scoring (`shield/detect.rs`)

Nine independent signals, each contributing a bounded number of points; the
score is their sum (capped at 100). There is deliberately no single-threshold
rule anywhere.

| Signal | Weight | Answers |
|--------|-------:|---------|
| Traffic anomaly | 20 | is the pipe (edge **or** internal bridge) carrying far more than normal? |
| Request-rate anomaly | 20 | is the application being asked for far more? |
| Source concentration | 15 | is one address or /24 network responsible? |
| Endpoint concentration | 10 | is one resource absorbing everything? |
| Behaviour similarity | 10 | do many sources act like one script? |
| Connection anomaly | 10 | are sockets being created abnormally fast / half-open? |
| Error-rate anomaly | 5 | is the application starting to fail? |
| Temporal anomaly | 5 | is this abnormal *for this hour of day*? |
| Application health | 5 | are the protected services actually hurting? |

Each signal uses a ratio **and** an absolute floor, so "20× of 2 kbps" (still
nothing) never fires. Every fired signal produces a reason string containing the
measurement.

**Threat bands** (configurable): `0–29 NORMAL · 30–49 ELEVATED · 50–69
SUSPICIOUS · 70–84 ATTACK · 85–100 CRITICAL`.

### Explainability

The dashboard/CLI never says "AI detected DDoS". It says, for example:

```
DDOS RISK SCORE: 94/100   THREAT: CRITICAL
ATTACK: DISTRIBUTED HTTP FLOOD   CONFIDENCE: HIGH

REASONS:
  + Traffic anomaly (+20) — inbound 60.0 Mbps vs 2.0 Mbps baseline (30.0x), 14000 pkt/s vs 400 (35.0x)
  + Request-rate anomaly (+20) — 1500 req/s vs 10.0 baseline (150.0x) over 60 s
  + Endpoint concentration (+10) — /api/search receives 98% of all requests
  + Behaviour similarity (+9) — 91% of sources share the busiest endpoint, 100% share one user-agent
  + Connection anomaly (+10) — 120 new conn/s vs 4.0 baseline (30.0x)
```

Each reason is generated from the actual measurement — nothing is templated.

## 6. Distributed behaviour detection

The detector does not only ask "is one IP sending too much?". The
`IP × endpoint` counter measures **how many *different* sources converge on the
*same* endpoint** — the coordination signature of a botnet. Combined with
user-agent uniformity and request-count uniformity (coefficient of variation:
a crowd is uneven, a script is uniform), this catches a flood spread across
thousands of addresses where no single IP stands out. Classification uses the
*access-log* source count, not the TCP peer count, so idle background
connections cannot make a few-source endpoint flood look distributed.

## 7. Classification (`shield/detect.rs::classify`)

From the signals that actually fired:

- **Internal traffic anomaly** — docker-bridge traffic/connections dominate
  while edge HTTP stays quiet.
- **Connection exhaustion** — socket/SYN pressure with little HTTP.
- **Slow request anomaly** — many open connections, high latency, low completion.
- **Burst attack** — a spike present in the last 10 s but not across the window.
- **Distributed HTTP flood** — many sources, none dominant, acting alike.
- **Endpoint exhaustion** — a handful of sources concentrating on one resource.
- **HTTP flood** — one address carries the load.
- **Volumetric anomaly** — a bandwidth/packet surge with no clear L7 shape.

## 8. False-positive protection

A flash crowd — high volume, but **diverse** sources, **diverse** resources,
**low** behavioural similarity, and a **healthy** application — is classified as
a **TRAFFIC SURGE**, not an attack, and the score is held below the ATTACK band
so nothing auto-blocks a legitimate spike. This is an explicit, recorded
verdict (`damped` reason), not a silent side effect:

```
TRAFFIC SURGE   Confidence: LOW
traffic is 20.0x baseline but sources are diverse (5000 sources over 20 networks),
no endpoint holds more than 3%, behavioural similarity is only 31%, and every
protected service is healthy — classified as a surge, not an attack
```

## 9. Application-health correlation

Health is a *detection signal*: the same 20× traffic is a surge with a healthy
app and an attack with a degrading one. Health also makes recovery and reported
downtime honest — see [RECOVERY.md](RECOVERY.md).

## 10. Tuning

All thresholds, weights (via bands), windows, and floors live in
`/etc/nimbusa/config.toml` and are validated on load (`nimbusa config validate`
reports any correction). Defaults are documented in the generated config and in
`config.rs`.
