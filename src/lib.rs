#![crate_type = "lib"]
#![forbid(unsafe_code)]
#![forbid(missing_debug_implementations)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

//! # firewall_audit
//!
//! A cross-platform firewall audit tool and library.
//!
//! - Audit firewall rules against user-defined criteria (YAML/JSON)
//! - Export results in CSV, HTML, or JSON
//! - Usable as a CLI or as a library
//!
//! ## Example (CLI)
//! ```sh
//! firewall_audit --rules rules.yaml --export csv --output result.csv
//! ```

mod audit;
mod criteria;
mod error;
mod export;
mod firewall_rule;

pub use audit::{
    load_audit_rules_json, load_audit_rules_multi, load_audit_rules_yaml,
    run_audit_multi_with_rules,
};
pub use criteria::{AuditRule, CriteriaCondition, CriteriaExpr, CriteriaOperator};
pub use error::{FirewallAuditError, Result};
pub use export::{
    audit_summary_phrase, export_csv, export_html, export_json, export_text, JsonAuditBlock,
    JsonAuditResult, JsonAuditSummary,
};
pub use firewall_rule::FirewallProvider;
pub use firewall_rule::FirewallRule;
pub use firewall_rule::FirewallRuleProvider;
