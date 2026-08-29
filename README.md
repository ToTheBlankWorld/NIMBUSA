<div align="center">

# 🛡️ NIMBUSA

### ☁️ Cloud Security Control Center — powered by **NIMBUSA SHIELD**

**Autonomous Cloud DDoS Detection · Mitigation · Recovery · Tamper-Evident Security Audit**

<br/>

![Rust](https://img.shields.io/badge/Built_with-Rust-CE422B?style=for-the-badge&logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux_VPS-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Tests](https://img.shields.io/badge/Tests-131_passing-2ea44f?style=for-the-badge&logo=github&logoColor=white)
![Single Binary](https://img.shields.io/badge/Deploy-Single_Binary-blue?style=for-the-badge)
![License](https://img.shields.io/badge/Theme-Blockchain_%26_Cybersecurity-8A2BE2?style=for-the-badge)

<br/>

> 🎯 **SIH1649 — DDoS Protection System for Cloud: Architecture & Tool**
> 🏛️ Ministry of Defence (MoD) · SAG, DRDO · 🔗 Theme: *Blockchain & Cybersecurity*

</div>

---

## 🌩️ What is NIMBUSA?

**NIMBUSA** is a single, self-contained **Rust** binary that turns a bare Linux
cloud VPS into a **Security Operations Center in your terminal**. It combines a
full server/firewall control center with **NIMBUSA SHIELD** — an autonomous DDoS
defense pipeline that never stops watching your traffic.

<div align="center">

```
🔭 OBSERVE → 📥 COLLECT → 🧮 NORMALIZE → 📊 BASELINE → 🧠 DETECT → 🏷️ CLASSIFY
     → 🎯 SCORE → 💬 EXPLAIN → 🛡️ MITIGATE → ✅ VERIFY → ♻️ RECOVER → ⛓️ AUDIT
```

</div>

NIMBUSA continuously **learns what normal looks like**, **detects abnormal
patterns** with multiple explainable signals, **classifies** the attack,
**applies layered mitigation**, **verifies** the application stays alive,
**rolls back** the protections once the storm passes, and **records every step**
in a tamper-evident audit chain — all with **minimal downtime** and **zero
config to get started**.

---

## ✨ Why it's different

| | Feature | What it means |
|---|---|---|
| 🧠 | **No dumb thresholds** | Verdicts are a weighted sum of **9 independent signals**. Every point awarded carries the exact measurement behind it — never "AI detected DDoS" with no evidence. |
| 🎭 | **False-positive aware** | A viral flash crowd (20× traffic but diverse & healthy) is labelled a **TRAFFIC SURGE**, *not* an attack — and is never auto-blocked. |
| ❄️ | **Attack-aware baseline** | The learning model **freezes** during an attack, so a 10-minute flood can never poison "normal". |
| 🔒 | **Reversible by design** | Every auto-rule lives in an isolated firewall chain with a **kernel TTL**. Your permanent blacklist, whitelist, fail2ban & Docker rules are **untouchable**. |
| ⏱️ | **Earned recovery** | Rollback needs a cooldown **and** multiple healthy samples **and** a falling score. One quiet second proves nothing. |
| 📐 | **Real metrics only** | Detection time, mitigation time, recovery time & downtime are **measured** — never hard-coded to look good. |
| ⛓️ | **Tamper-evident ledger** | Every incident event is **SHA-256 hash-chained**. Any edit, delete or reorder is detected by `nimbusa audit verify`. |

---

## 🎬 See it in action

```bash
nimbusa                                # 🖥️  launch the SOC control center (TUI)
nimbusa ddos status                    # 🎯  live risk score + threat posture
nimbusa ddos simulate distributed \
        --confirm-local-test           # 🧪  SAFE, LOCAL-ONLY synthetic attack demo
nimbusa audit verify                   # ⛓️  verify the tamper-evident chain
```

<div align="center">

**Watch the score climb → attack classified → auto-mitigated → app stays alive → auto-recovered → audited.**

```
t+ 5s   score  32/100   🟡 ELEVATED
t+10s   score  58/100   🟠 SUSPICIOUS
t+15s   score  84/100   🔴 ATTACK        DISTRIBUTED HTTP FLOOD
t+20s   score  94/100   🚨 CRITICAL      DISTRIBUTED HTTP FLOOD   →  🛡️ MITIGATING
```

</div>

---

## 🚀 Quick start

> On your VPS, as **root**:

```bash
git clone https://github.com/ToTheBlankWorld/NIMBUSA.git
cd NIMBUSA
sudo bash scripts/install.sh          # 🔨 build · install · arm the shield
nimbusa                               # 🛡️ launch NIMBUSA
```

Run it **always-on**, headless (no TUI):

```bash
sudo WITH_SERVICE=1 bash scripts/install.sh
systemctl status nimbusa-shield        # ♾️ the shield engine as a service
```

---

## 🧠 The 9 detection signals

<div align="center">

| Signal | ⚖️ Weight | Answers |
|--------|:---:|---------|
| 🌊 Traffic anomaly | `20` | Is the pipe (edge **or** internal bridge) carrying far more than normal? |
| 📨 Request-rate anomaly | `20` | Is the application being asked for far more? |
| 🎯 Source concentration | `15` | Is one address or `/24` network responsible? |
| 📍 Endpoint concentration | `10` | Is one resource absorbing everything? |
| 🤖 Behaviour similarity | `10` | Do many sources act like one coordinated script? |
| 🔌 Connection anomaly | `10` | Are sockets being created abnormally fast / half-open? |
| ❌ Error-rate anomaly | `5` | Is the application starting to fail? |
| 🕐 Temporal anomaly | `5` | Is this abnormal *for this hour of day*? |
| 💓 Application health | `5` | Are the protected services actually hurting? |

**`0–29` 🟢 NORMAL · `30–49` 🟡 ELEVATED · `50–69` 🟠 SUSPICIOUS · `70–84` 🔴 ATTACK · `85–100` 🚨 CRITICAL**

</div>

---

## 🛡️ Attacks it detects & stops

- 💥 **HTTP flood** — single-source request storms
- 🕸️ **Distributed HTTP flood** — thousands of coordinated sources, no single IP standing out
- 📍 **Endpoint exhaustion** — one resource hammered
- 🔌 **Connection / SYN exhaustion** — the socket table as the target
- ⚡ **Burst attacks** — short, sharp spikes
- 🐳 **Internal cloud anomalies** — container-origin floods from *inside* the infrastructure
- 🎭 **Flash crowds** — correctly identified as **legitimate**, never blocked

---

## 🏗️ Architecture

<div align="center">

```
                          🌍 INTERNET
                               │
                               ▼
                    🔀 Traefik (reverse proxy + access logs)
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
            🌐 Web App                     🔗 API
                 └─────────────┬─────────────┘
                          🐳 SERVICES

                       🛡️ NIMBUSA SHIELD
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
      🔭 Telemetry     🧠 Detection      💓 Health
          └────────────────┼────────────────┘
                           ▼
                   🎯 Risk Score Engine
                           ▼
                    📋 Policy Engine
                           ▼
                   🛡️ Mitigation Engine
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
       📦 ipset        🧱 iptables      ⏱️ rate/conn limit
          └────────────────┼────────────────┘
                           ▼
                   ♻️ Recovery Engine
                           ▼
                   📁 Incident Engine
                           ▼
                ⛓️ Tamper-Evident Audit
```

</div>

---

## 📂 Project layout

```
📦 NIMBUSA
├── 🦀 nimbusa-rs/            Rust workspace (lib + bin)
│   └── src/
│       ├── lib.rs            📚 library core (UI-free, fully tested)
│       ├── main.rs           🖥️ TUI app loop + base tabs
│       ├── ui_shield.rs      🛡️ SHIELD dashboard + active-incident screen
│       ├── config.rs         ⚙️ /etc/nimbusa/config.toml (parse + validate)
│       ├── sha256.rs         🔐 in-tree SHA-256 (audit primitive)
│       ├── firewall.rs       🧱 permanent ipset/fail2ban (operator-owned)
│       ├── system.rs         📡 host/docker/traefik/ssh/users/IP intel
│       ├── cli.rs            ⌨️ scriptable CLI (all `ddos` commands)
│       └── shield/           🛡️ the DDoS pipeline
│           ├── telemetry.rs  🔭 /proc counters → rates
│           ├── accesslog.rs  📥 incremental Traefik log tail
│           ├── window.rs     🧮 bounded rolling windows
│           ├── baseline.rs   📊 attack-aware EWMA baseline
│           ├── detect.rs     🧠 9-signal scoring + classification
│           ├── health.rs     💓 application health correlation
│           ├── mitigate.rs   🛡️ isolated, TTL'd, reversible mitigation
│           ├── recovery.rs   ♻️ recovery state machine
│           ├── incident.rs   📁 incident records + metrics
│           ├── audit.rs      ⛓️ tamper-evident hash chain
│           ├── simulate.rs   🧪 safe, local-only attack simulator
│           └── engine.rs     ⚙️ background orchestrator
├── 📜 scripts/               install.sh · nimbusa-firewall.sh · systemd unit
├── 📖 docs/                  architecture · DDoS · security · demo · threat model
└── 🗄️ legacy/                original prototype (kept for reference)
```

---

## 📖 Documentation

| 📄 Doc | What it covers |
|--------|----------------|
| [🏗️ ARCHITECTURE](docs/ARCHITECTURE.md) | System architecture & data flow |
| [🧠 DDOS](docs/DDOS.md) | Telemetry, baseline, signals, scoring, classification |
| [♻️ RECOVERY](docs/RECOVERY.md) | Recovery state machine, cooldown, rollback, metrics |
| [🔒 SECURITY](docs/SECURITY.md) | How NIMBUSA protects itself |
| [⚠️ THREAT_MODEL](docs/THREAT_MODEL.md) | Threats → detection → mitigation → residual risk |
| [🎬 DEMO](docs/DEMO.md) | Step-by-step SIH demonstration script |
| [📏 LIMITATIONS](docs/LIMITATIONS.md) | Honest protection boundary |
| [🎯 SIH1649_MAPPING](docs/SIH1649_MAPPING.md) | PS requirements → NIMBUSA features |

---

## 🧪 Build & test

```bash
cargo test --lib          # ✅ 131 unit tests — scoring, baseline, classification,
                          #    mitigation, recovery, audit chain, config & more
cargo build --release     # 🦀 the nimbusa binary
cargo clippy --lib        # 🧹 lint clean
```

---

## 📏 Protection boundary (the honest bit)

> ✅ NIMBUSA protects the **host, application, reverse proxy, services & internal
> cloud traffic** on a single VPS — HTTP floods, distributed floods,
> endpoint/connection exhaustion, burst & internal-origin attacks — keeping the
> app alive throughout.
>
> ⚠️ It **cannot** absorb an **upstream-link-saturating** volumetric flood — no
> single VPS can. For that, the cloud/ISP provider must supply upstream
> scrubbing. NIMBUSA is the host-and-application guard **behind** that layer.
> See [LIMITATIONS.md](docs/LIMITATIONS.md).

---

<div align="center">

### 🛡️ NIMBUSA — *observe · learn · detect · explain · mitigate · recover · audit*

**Built for SIH1649 · Blockchain & Cybersecurity**

⭐ *Star this repo if NIMBUSA guards your cloud* ⭐

</div>
