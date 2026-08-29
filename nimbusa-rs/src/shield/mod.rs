//! NIMBUSA SHIELD — autonomous DDoS detection, mitigation, recovery & audit.
//!
//! Pipeline: OBSERVE -> COLLECT -> NORMALIZE -> BASELINE -> DETECT -> CLASSIFY
//! -> SCORE -> EXPLAIN -> MITIGATE -> VERIFY -> RECOVER -> AUDIT.
//!
//! Each stage is its own module and is unit-tested in isolation; `engine` wires
//! them into one background worker so the TUI render loop never touches any of
//! this directly.
pub mod accesslog;
pub mod audit;
pub mod baseline;
pub mod detect;
pub mod engine;
pub mod health;
pub mod incident;
pub mod inventory;
pub mod mitigate;
pub mod recovery;
pub mod simulate;
pub mod telemetry;
pub mod window;

pub use engine::Shield;
#[allow(unused_imports)]
pub use engine::ShieldSnapshot;
