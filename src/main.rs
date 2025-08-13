//! Firewall Audit CLI
//!
//! This binary audits firewall rules against user-defined criteria and exports
//! the results in various formats (CSV, HTML, JSON).
//!
//! # Example
//! ```sh
//! firewall_audit --criteria audit_criteria.yaml --export html --output result.html
//! ```

use clap::{Parser, ValueEnum};
use firewall_audit::{
    audit_summary_phrase, export_csv, export_html, export_json, export_text,
    load_audit_criteria_multi, run_audit_multi_with_criteria, FirewallAuditError,
    FirewallRuleProvider, PlatformFirewallProvider,
};
use std::process;
use tracing::{error, info};

/// Supported export formats
#[derive(ValueEnum, Clone, Debug)]
enum ExportFormat {
    Csv,
    Html,
    Json,
}

/// Firewall Audit CLI
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Cross-platform firewall audit tool (CSV/HTML/JSON export)",
    long_about = "This program audits local firewall rules against user-defined criteria \
                  from a YAML or JSON file. Results can be exported in various formats."
)]
struct Cli {
    /// Path to the audit criteria file (YAML or JSON)
    #[arg(short, long, value_name = "FILE")]
    criteria: String,

    /// Export format
    #[arg(short, long, value_enum)]
    export: Option<ExportFormat>,

    /// Output file
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        error!("{e}");
        process::exit(1);
    }
}

fn run() -> Result<(), FirewallAuditError> {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let audit_criteria = load_audit_criteria_multi(&[cli.criteria])?;
    if audit_criteria.is_empty() {
        return Err(FirewallAuditError::ValidationError(
            "No valid audit criteria loaded.".into(),
        ));
    }
    info!("Loaded {} audit criteria(s).", audit_criteria.len());

    let firewall_rules = PlatformFirewallProvider::list_rules()?;
    info!("Loaded {} firewall rule(s).", firewall_rules.len());

    let audit_results = run_audit_multi_with_criteria(&audit_criteria, &firewall_rules);

    let output_path = cli.output.or_else(|| {
        cli.export.as_ref().map(|fmt| {
            format!(
                "firewall_audit_{}.{}",
                chrono::Utc::now().format("%Y%m%d_%H%M%S"),
                match fmt {
                    ExportFormat::Csv => "csv",
                    ExportFormat::Html => "html",
                    ExportFormat::Json => "json",
                }
            )
        })
    });

    match (&output_path, &cli.export) {
        (Some(path), Some(fmt)) => {
            match fmt {
                ExportFormat::Csv => export_csv(&audit_results, Some(path))?,
                ExportFormat::Html => export_html(&audit_results, Some(path))?,
                ExportFormat::Json => export_json(&audit_results, Some(path))?,
            };
            info!("Export successful to {}", path);
        }
        _ => {
            println!("{}", export_text(&audit_results)?);
        }
    }

    println!();
    info!("{}", audit_summary_phrase(&audit_results));

    Ok(())
}
