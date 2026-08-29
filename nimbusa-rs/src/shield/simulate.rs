//! Safe, local-only DDoS simulator.
//!
//! Two things make this safe by construction:
//!
//!  * It never generates a single real packet toward anyone. It produces
//!    *synthetic telemetry* — request records and counter samples — that are
//!    injected into the same pipeline the real collectors feed. The detector,
//!    the mitigation engine and the recovery machine cannot tell the difference,
//!    which is exactly what makes the demo honest; but nothing leaves the box.
//!  * Everything it produces is tagged `simulated = true` all the way into the
//!    incident record and the dashboard banner, so a simulated incident can
//!    never be mistaken for a real one.
//!
//! There is deliberately no mode that drives a load generator at a third party.
use super::accesslog::Req;
use super::telemetry::Sample;
use crate::util::epoch;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scenario {
    HttpFlood,
    Distributed,
    Burst,
    Connection,
    Internal,
    Surge,
}

impl Scenario {
    pub fn parse(s: &str) -> Option<Scenario> {
        match s.to_lowercase().as_str() {
            "http-flood" | "http" | "flood" => Some(Scenario::HttpFlood),
            "distributed" | "ddos" | "botnet" => Some(Scenario::Distributed),
            "burst" | "spike" => Some(Scenario::Burst),
            "connection" | "conn" | "syn" => Some(Scenario::Connection),
            "internal" | "container" => Some(Scenario::Internal),
            "surge" | "flash-crowd" | "legit" => Some(Scenario::Surge),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Scenario::HttpFlood => "http-flood",
            Scenario::Distributed => "distributed",
            Scenario::Burst => "burst",
            Scenario::Connection => "connection",
            Scenario::Internal => "internal",
            Scenario::Surge => "surge",
        }
    }
    pub fn describe(&self) -> &'static str {
        match self {
            Scenario::HttpFlood => "single-source HTTP flood against one endpoint",
            Scenario::Distributed => "distributed HTTP flood — thousands of coordinated sources",
            Scenario::Burst => "short, sharp traffic burst",
            Scenario::Connection => "connection/SYN exhaustion with little HTTP",
            Scenario::Internal => "internal container-origin traffic anomaly",
            Scenario::Surge => "legitimate flash crowd (should NOT be called an attack)",
        }
    }
    /// A higher-volume scenario needs explicit confirmation even though it is
    /// only synthetic, so the demo operator has to opt in deliberately.
    pub fn needs_confirm(&self) -> bool {
        matches!(self, Scenario::Distributed | Scenario::Connection)
    }
}

/// A live simulation. `intensity` ramps 0.0 -> 1.0 over the first few ticks so
/// the score visibly climbs (NORMAL -> ELEVATED -> ... -> CRITICAL) instead of
/// snapping straight to the top — that ramp is the demo's whole point.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Simulation {
    pub scenario: Scenario,
    pub started: u64,
    pub ticks: u64,
    /// Ticks over which the attack ramps to full strength.
    pub ramp_ticks: u64,
    /// Multiplier applied to the baseline volume at full strength.
    pub magnitude: f64,
}

impl Simulation {
    pub fn new(scenario: Scenario) -> Self {
        let magnitude = match scenario {
            Scenario::Burst => 60.0,
            Scenario::Distributed => 40.0,
            Scenario::HttpFlood => 30.0,
            Scenario::Surge => 22.0,
            Scenario::Connection => 1.0,
            Scenario::Internal => 1.0,
        };
        Simulation {
            scenario,
            started: epoch(),
            ticks: 0,
            ramp_ticks: 4,
            magnitude,
        }
    }

    pub fn intensity(&self) -> f64 {
        if self.scenario == Scenario::Burst {
            // burst: silent, then one loud tick, then gone
            return if self.ticks == 2 { 1.0 } else { 0.0 };
        }
        ((self.ticks as f64) / self.ramp_ticks as f64).min(1.0)
    }

    /// Produce the synthetic requests and counter deltas for this tick. The
    /// `base` sample carries the box's genuine idle counters so the injected
    /// traffic is added on top of reality, not substituted for it.
    pub fn tick(&mut self, base: &Sample, base_rps: f64) -> (Vec<Req>, Sample) {
        self.ticks += 1;
        let k = self.intensity();
        let now = epoch();
        let mut s = base.clone();
        s.t = now;
        let mut reqs = Vec::new();
        // a modest floor of genuine-looking background traffic every tick
        let bg = (base_rps.max(8.0) * 5.0) as usize;
        for i in 0..bg {
            reqs.push(sim_req(
                &format!("203.0.113.{}", (i * 7 + self.ticks as usize) % 240),
                &format!("/page/{}", i % 40),
                200,
                ["Chrome/120", "Firefox/121", "Safari/17"][i % 3],
                800,
            ));
        }
        if k <= 0.0 {
            return (reqs, s);
        }

        match self.scenario {
            Scenario::HttpFlood => {
                let n = (1500.0 * k) as usize;
                for _ in 0..n {
                    reqs.push(sim_req(
                        "198.51.100.9",
                        "/api/search",
                        if k > 0.6 { 503 } else { 200 },
                        "python-requests/2.31",
                        400,
                    ));
                }
                s.rx_bps += 40_000_000.0 * k;
                s.rx_pps += 9_000.0 * k;
                s.conn_rate += 60.0 * k;
                s.established += (900.0 * k) as u32;
            }
            Scenario::Distributed => {
                let n = (1600.0 * k) as usize;
                for i in 0..n {
                    let id = (i + self.ticks as usize * 700) % 4000;
                    reqs.push(sim_req(
                        &format!(
                            "100.{}.{}.{}",
                            id / 65536 % 200 + 1,
                            id / 256 % 256,
                            id % 256
                        ),
                        "/api/search",
                        if k > 0.6 { 503 } else { 200 },
                        "Go-http-client/1.1",
                        350,
                    ));
                }
                s.rx_bps += 60_000_000.0 * k;
                s.rx_pps += 14_000.0 * k;
                s.conn_rate += 120.0 * k;
                s.established += (1600.0 * k) as u32;
                s.conn_sources += (4000.0 * k) as u32;
            }
            Scenario::Burst => {
                let n = (2500.0 * k) as usize;
                for i in 0..n {
                    reqs.push(sim_req(
                        &format!("45.{}.{}.{}", i / 65536 % 200 + 1, i / 256 % 256, i % 256),
                        "/",
                        200,
                        "bot",
                        300,
                    ));
                }
                s.rx_bps += 90_000_000.0 * k;
                s.rx_pps += 20_000.0 * k;
            }
            Scenario::Connection => {
                s.conn_rate += 900.0 * k;
                s.established += (4000.0 * k) as u32;
                s.syn_recv += (6000.0 * k) as u32;
                s.rx_pps += 1200.0 * k;
                s.conn_sources += (300.0 * k) as u32;
            }
            Scenario::Internal => {
                s.internal_bps += 40_000_000.0 * k;
                s.internal_conns += (3000.0 * k) as u32;
            }
            Scenario::Surge => {
                // high volume, but DIVERSE — the false-positive test
                let n = (1200.0 * k) as usize;
                for i in 0..n {
                    let id = (i + self.ticks as usize * 211) % 6000;
                    reqs.push(sim_req(
                        &format!(
                            "203.{}.{}.{}",
                            id / 65536 % 200 + 1,
                            id / 256 % 256,
                            id % 256
                        ),
                        &format!("/article/{}", i % 500),
                        200,
                        ["Chrome/120", "Safari/17", "Firefox/121", "Edge/119"][i % 4],
                        1200,
                    ));
                }
                s.rx_bps += 40_000_000.0 * k;
                s.rx_pps += 8_000.0 * k;
                s.conn_sources += (6000.0 * k) as u32;
            }
        }
        (reqs, s)
    }

    /// Synthetic per-source connection census, so connection-based scenarios
    /// still yield mitigable suspects.
    pub fn conn_census(&self) -> std::collections::HashMap<String, u32> {
        let mut m = std::collections::HashMap::new();
        let k = self.intensity();
        if k <= 0.0 {
            return m;
        }
        match self.scenario {
            Scenario::Connection => {
                for i in 0..(300.0 * k) as usize {
                    m.insert(format!("45.9.{}.{}", i / 256, i % 256), 90);
                }
            }
            Scenario::HttpFlood => {
                m.insert("198.51.100.9".into(), (200.0 * k) as u32);
            }
            _ => {}
        }
        m
    }
}

fn sim_req(ip: &str, path: &str, status: u16, ua: &str, bytes: u64) -> Req {
    Req {
        ip: ip.into(),
        method: "GET".into(),
        host: "app.example.com".into(),
        path: path.into(),
        status,
        bytes,
        ua: ua.into(),
        duration_ms: if status >= 500 { 800.0 } else { 40.0 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Sample {
        Sample {
            rx_bps: 2_000_000.0,
            rx_pps: 400.0,
            conn_rate: 4.0,
            established: 60,
            conn_sources: 30,
            internal_bps: 500_000.0,
            internal_conns: 20,
            ..Default::default()
        }
    }

    #[test]
    fn scenarios_parse_and_round_trip() {
        for name in [
            "http-flood",
            "distributed",
            "burst",
            "connection",
            "internal",
            "surge",
        ] {
            let s = Scenario::parse(name).unwrap();
            assert_eq!(Scenario::parse(s.as_str()), Some(s));
        }
        assert!(Scenario::parse("nuke-google").is_none());
    }

    #[test]
    fn high_volume_scenarios_require_confirmation() {
        assert!(Scenario::Distributed.needs_confirm());
        assert!(Scenario::Connection.needs_confirm());
        assert!(!Scenario::HttpFlood.needs_confirm());
        assert!(!Scenario::Surge.needs_confirm());
    }

    #[test]
    fn intensity_ramps_up() {
        let mut sim = Simulation::new(Scenario::HttpFlood);
        let mut last = 0.0;
        for _ in 0..6 {
            sim.tick(&base(), 10.0);
            let k = sim.intensity();
            assert!(k >= last);
            last = k;
        }
        assert_eq!(last, 1.0);
    }

    #[test]
    fn http_flood_produces_a_dominant_source() {
        let mut sim = Simulation::new(Scenario::HttpFlood);
        for _ in 0..4 {
            sim.tick(&base(), 10.0);
        }
        let (reqs, s) = sim.tick(&base(), 10.0);
        let flood = reqs.iter().filter(|r| r.ip == "198.51.100.9").count();
        assert!(flood > reqs.len() / 2, "flood source should dominate");
        assert!(s.rx_bps > base().rx_bps);
    }

    #[test]
    fn distributed_produces_many_sources_no_single_dominant() {
        let mut sim = Simulation::new(Scenario::Distributed);
        for _ in 0..4 {
            sim.tick(&base(), 10.0);
        }
        let (reqs, _) = sim.tick(&base(), 10.0);
        let distinct: std::collections::HashSet<&str> =
            reqs.iter().map(|r| r.ip.as_str()).collect();
        assert!(distinct.len() > 500, "should be highly distributed");
        assert!(reqs
            .iter()
            .all(|r| r.endpoint() == "/api/search" || r.path.starts_with("/page")));
    }

    #[test]
    fn burst_is_silent_except_one_tick() {
        let mut sim = Simulation::new(Scenario::Burst);
        let loud: Vec<usize> = (0..6)
            .map(|_| {
                let (r, _) = sim.tick(&base(), 10.0);
                r.iter().filter(|q| q.ip.starts_with("45.")).count()
            })
            .collect();
        assert!(loud[1] > 1000, "the burst tick must be loud");
        assert_eq!(loud[0], 0);
        assert_eq!(loud[3], 0, "after the burst, quiet again");
    }

    #[test]
    fn connection_scenario_yields_conn_suspects_without_http() {
        let mut sim = Simulation::new(Scenario::Connection);
        for _ in 0..4 {
            sim.tick(&base(), 10.0);
        }
        let (reqs, s) = sim.tick(&base(), 10.0);
        // only background HTTP, but the connection census is heavy
        assert!(s.syn_recv > 1000);
        assert!(sim.conn_census().len() > 100);
        assert!(reqs.iter().all(|r| r.ip.starts_with("203.0.113.")));
    }

    #[test]
    fn surge_stays_diverse() {
        let mut sim = Simulation::new(Scenario::Surge);
        for _ in 0..4 {
            sim.tick(&base(), 10.0);
        }
        let (reqs, _) = sim.tick(&base(), 10.0);
        let endpoints: std::collections::HashSet<String> =
            reqs.iter().map(|r| r.endpoint()).collect();
        assert!(endpoints.len() > 50, "a flash crowd hits many endpoints");
    }

    #[test]
    fn internal_scenario_moves_bridge_counters_only() {
        let mut sim = Simulation::new(Scenario::Internal);
        for _ in 0..4 {
            sim.tick(&base(), 10.0);
        }
        let (reqs, s) = sim.tick(&base(), 10.0);
        assert!(s.internal_bps > base().internal_bps * 10.0);
        assert!(reqs.iter().all(|r| r.ip.starts_with("203.0.113.")));
    }
}
