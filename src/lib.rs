#![crate_type = "lib"]
#![forbid(unsafe_code)]
#![forbid(missing_debug_implementations)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

mod app;
mod audit;
mod criteria;
mod export;
mod firewall_rule;
mod loader;

pub use app::{run_firewall_audit, Args};
