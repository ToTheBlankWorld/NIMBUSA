# NIMBUSA — Limitations & Protection Boundary

Being honest about the boundary is part of the engineering.

## What NIMBUSA protects

On a single Linux VPS, NIMBUSA protects the **host, the application, the reverse
proxy, the services, and internal cloud traffic**. It detects, classifies,
mitigates and recovers from:

- HTTP floods (single-source and distributed),
- endpoint and connection/SYN exhaustion,
- burst attacks,
- internal container-origin anomalies,

and keeps the application available through them (measured downtime, not
assumed), with automatic rollback and a tamper-evident record.

## What NIMBUSA cannot do

**It cannot absorb an upstream-link-saturating volumetric flood.** No single VPS
can. If the incoming attack traffic exceeds the capacity of the network link
into the machine, packets are dropped *before* NIMBUSA (or any host-resident
software) ever sees them. Host-level filtering reduces CPU/socket/application
load and keeps the box and its services alive against everything up to that
ceiling, but the pipe itself is a hard physical limit.

For volumetric attacks at or beyond link capacity, mitigation must happen
**upstream**: the cloud provider's or ISP's DDoS scrubbing, anycast, or a
CDN/WAF in front of the origin. NIMBUSA is the host-and-application guard behind
that; the two are complementary layers, not substitutes.

## Other honest caveats

- **Access-log dependency for L7 detail.** The richest request-level signals
  (endpoint concentration, behavioural similarity, per-source request rates)
  need the Traefik access log. Without it, NIMBUSA still runs on `/proc`
  telemetry (bandwidth, packets, connections) — it detects volumetric and
  connection attacks, but with less L7 resolution. Enabling the JSON access log
  is a one-line Traefik change.
- **IPv4 source resolution in the connection census.** `/proc/net/tcp6` peers
  count toward connection-state totals but are not resolved to per-source keys;
  per-source connection mitigation is IPv4-centric.
- **Baseline warm-up.** For roughly the first `baseline.warmup_samples` ticks on
  a fresh install, scoring is withheld while normal traffic is learned. This is
  deliberate — scoring against an empty baseline would flag the first request as
  a 100× surge.
- **GeoIP / whois are best-effort.** Country/org enrichment depends on
  `geoiplookup` / `whois` being installed; absence degrades enrichment only, not
  detection.
- **Single-box high availability.** NIMBUSA provides health-aware mitigation,
  graceful degradation, automatic rollback and health verification on one host.
  Multi-instance health-aware routing (Traefik in front of two app instances) is
  supported at the infrastructure level but is a deployment choice, not
  something the binary provisions.
- **The audit anchor is optional and external.** The local hash chain is always
  authoritative; the blockchain/notary anchor is best-effort and its
  availability is the operator's concern.

## Design stance

NIMBUSA deliberately avoids heavyweight infrastructure (no Kafka/ES/K8s/DB/ML
runtime). That keeps it a realistic, lightweight, single-binary guard for a
VPS — which is what the deployment target is — at the cost of not being a
full distributed scrubbing centre. Those are different products for different
points in the network.
