//! Firewall Audit CLI
//!
//! This binary audits firewall rules against user-defined criteria and exports the results in various formats (CSV, HTML, JSON).
//!
//! # Example
//! ```sh
//! firewall_audit --criteria audit_criteria.yaml --export html --output result.html
//! ```

use clap::{Parser, ValueEnum};
use firewall_audit::{
    export_csv, export_html, export_json, FirewallRuleProvider, PlatformFirewallProvider,
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
    long_about = "This program audits local firewall rules against user-defined criteria from a YAML or JSON file. Results can be exported in various formats."
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

/// Entry point for the `firewall_audit` CLI.
fn main() {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .init();
    let cli = Cli::parse();

    let audit_criteria = firewall_audit::load_audit_criteria_multi(&[cli.criteria.clone()])
        .unwrap_or_else(|e| {
            error!("Error loading audit criteria: {}", e);
            process::exit(1);
        });
    info!("Loaded {} audit criteria(s).", audit_criteria.len());
    if audit_criteria.is_empty() {
        error!("No valid audit criteria loaded. Exiting.");
        process::exit(1);
    }

    // Load firewall rules
    let firewall_rules = PlatformFirewallProvider::list_rules().unwrap_or_else(|e| {
        error!("Error loading firewall rules: {}", e);
        process::exit(1);
    });
    info!("Loaded {} firewall rule(s).", firewall_rules.len());

    // Run the audit and get structured results
    let audit_results =
        firewall_audit::run_audit_multi_with_criteria(&audit_criteria, &firewall_rules);

    let output_path = match (&cli.output, &cli.export) {
        (None, Some(fmt)) => Some({
            let ext = match fmt {
                ExportFormat::Csv => "csv",
                ExportFormat::Html => "html",
                ExportFormat::Json => "json",
            };

            format!(
                "firewall_audit_{}.{}",
                chrono::Utc::now().format("%Y%m%d_%H%M%S"),
                ext
            )
        }),
        _ => cli.output,
    };

    match (&output_path, &cli.export) {
        (Some(output_path), Some(fmt)) => {
            let result = match fmt {
                ExportFormat::Csv => {
                    export_csv(&audit_results, Some(output_path)).map_err(|e| e.to_string())
                }
                ExportFormat::Html => {
                    export_html(&audit_results, Some(output_path)).map_err(|e| e.to_string())
                }
                ExportFormat::Json => {
                    export_json(&audit_results, Some(output_path)).map_err(|e| e.to_string())
                }
            };
            match result {
                Ok(_) => info!("Export successful to {}", output_path),
                Err(e) => {
                    error!("Export error: {}", e);
                    process::exit(1);
                }
            }
        }
        _ => {
            println!("{}", firewall_audit::export_text(&audit_results));
        }
    }

    let summary = firewall_audit::audit_summary_phrase(&audit_results);
    println!();
    info!("{summary}");
}
