//! NIMBUSA — Autonomous Cloud DDoS Detection, Mitigation, Recovery & Security
//! Control Center.
//!
//! This library crate holds everything that does not touch the terminal UI:
//! utilities, configuration, the SHA-256 primitive, filesystem paths and
//! migration, the permanent firewall layer, host/docker/SSH/user monitoring,
//! the whole NIMBUSA SHIELD DDoS pipeline, and the CLI. Keeping it UI-free lets
//! the full test suite build and run without the terminal backend, and gives
//! the `nimbusa` binary a thin `main.rs` over a tested core.
// Descending `sort_by(|a,b| b.cmp(a))` reads more clearly than sort_by_key with
// Reverse for the small top-N rankings used throughout; keep it.
#![allow(clippy::unnecessary_sort_by)]
pub mod cli;
pub mod config;
pub mod firewall;
pub mod paths;
pub mod sha256;
pub mod shield;
pub mod system;
pub mod util;
