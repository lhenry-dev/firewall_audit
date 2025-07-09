#![crate_type = "lib"]
#![forbid(unsafe_code)]
#![forbid(missing_debug_implementations)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

mod audit;
mod criteria;
mod error;
mod export;
mod firewall_rule;
mod loader;

pub use audit::run_audit_multi_with_criteria;
pub use criteria::{AuditRule, CriteriaCondition, CriteriaExpr, CriteriaOperator};
pub use error::FirewallAuditError;
pub use export::{audit_summary_phrase, export_csv, export_html, export_json, export_text};
pub use firewall_rule::{FirewallRule, FirewallRuleProvider, PlatformFirewallProvider};
pub use loader::load_audit_criteria_multi;
