use clap::Parser;
use tracing::info;

use crate::export::ExportError;
use crate::firewall_rule::FirewallRuleError;
use crate::loader::LoaderError;
use crate::{
    audit::run_audit,
    export::{export_results, ExportFormat},
    firewall_rule::{FirewallRuleProvider, PlatformFirewallProvider},
    loader::load_audit_criteria,
};

/// Error type for `firewall_audit` operations.
#[derive(Debug, thiserror::Error)]
pub enum FirewallAuditError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),
    /// Loader error
    #[error("Loader error: {0}")]
    LoaderError(#[from] LoaderError),
    /// Firewall rule error
    #[error("Firewall rule error: {0}")]
    FirewallRuleError(#[from] FirewallRuleError),
    /// Export error
    #[error("Export error: {0}")]
    ExportError(#[from] ExportError),
}

/// Firewall Audit CLI arguments
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Cross-platform firewall audit tool (CSV/HTML/JSON export)",
    long_about = "This program audits local firewall rules against user-defined criteria \
                  from a YAML or JSON file. Results can be exported in various formats."
)]
pub struct Args {
    /// Path to the audit criteria file (YAML or JSON).
    /// Optional; if not provided, a default criteria file will be used.
    #[arg(long, short = 'c')]
    pub criteria: Option<String>,

    /// Export format (csv, html, json, stdout)
    #[arg(long, short = 'e', default_value = "stdout")]
    pub export: ExportFormat,

    /// Specify output filename
    #[arg(long, short = 'o')]
    pub output: Option<String>,

    /// Do not print anything to stdout
    #[arg(long, short = 'q')]
    pub quiet: bool,
}

/// Runs a full firewall audit based on the provided CLI arguments.
///
/// Steps performed:
/// 1. Load audit criteria from a YAML or JSON file (or use default if none specified).
///    Returns a `ValidationError` if no valid criteria are found.
/// 2. Retrieve the list of current firewall rules from the platform-specific provider.
/// 3. Run the audit by comparing the loaded criteria against the current firewall rules.
/// 4. Export the audit results in the requested format (CSV, HTML, JSON, or stdout).
///
/// # Errors
/// Returns `FirewallAuditError` variants if:
/// * There is an I/O issue while loading criteria or exporting results.
/// * The audit criteria fail validation.
/// * The loader, firewall rule provider, or exporter encounters an error.
pub fn run_firewall_audit(args: Args) -> Result<(), FirewallAuditError> {
    let audit_criteria = load_audit_criteria(args.criteria)?;

    if audit_criteria.is_empty() {
        return Err(FirewallAuditError::ValidationError(
            "No valid audit criteria loaded.".into(),
        ));
    }
    info!("Loaded {} audit criteria(s).", audit_criteria.len());

    let firewall_rules = PlatformFirewallProvider::list_rules()?;
    info!("Loaded {} firewall rule(s).", firewall_rules.len());

    let audit_results = run_audit(&audit_criteria, &firewall_rules);

    export_results(&audit_results, &args.export, args.output)?;

    Ok(())
}
