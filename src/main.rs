//! Firewall Audit CLI
//!
//! This binary audits firewall rules against user-defined criteria and exports the results in various formats (CSV, HTML, JSON).
//!
//! # Example
//! ```sh
//! firewall_audit --rules rules.yaml --export csv --output result.csv
//! ```

use clap::{Parser, ValueEnum};
use firewall_audit::{export_csv, export_html, export_json};
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
#[command(author, version, about = "Cross-platform firewall audit tool (CSV/HTML/JSON export)", long_about = None)]
struct Cli {
    /// Path to the rules file (YAML or JSON)
    #[arg(short, long, required = true)]
    rules: String,

    /// Export format (csv, html, json)
    #[arg(short, long, value_enum, default_value = "csv")]
    export: ExportFormat,

    /// Output file (if not set, print to stdout)
    #[arg(short, long)]
    output: Option<String>,
}

/// Entry point for the firewall_audit CLI.
fn main() {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .init();
    let cli = Cli::parse();

    let audit_rules =
        firewall_audit::load_audit_rules_multi(&[cli.rules.clone()]).unwrap_or_else(|e| {
            error!("Error loading audit rules: {}", e);
            process::exit(1);
        });
    info!("Loaded {} audit rule(s).", audit_rules.len());
    if audit_rules.is_empty() {
        error!("No valid audit rules loaded. Exiting.");
        process::exit(1);
    }

    let audit_output = firewall_audit::run_audit_multi(&audit_rules).unwrap_or_else(|e| {
        error!("Error running audit: {}", e);
        process::exit(1);
    });
    let summary = firewall_audit::audit_summary_phrase(&audit_output);
    if cli.output.is_none() {
        info!("{}", audit_output);
    } else {
        let output_path = cli.output.as_deref();
        let result = match cli.export {
            ExportFormat::Csv => export_csv(&audit_output, output_path).map_err(|e| e.to_string()),
            ExportFormat::Html => {
                export_html(&audit_output, output_path).map_err(|e| e.to_string())
            }
            ExportFormat::Json => {
                export_json(&audit_output, output_path).map_err(|e| e.to_string())
            }
        };
        match result {
            Ok(_) => info!("Export successful to {}", output_path.unwrap_or("Unknown")),
            Err(e) => {
                error!("Export error: {}", e);
                process::exit(1);
            }
        }
    }

    println!();
    info!("{summary}");
}
