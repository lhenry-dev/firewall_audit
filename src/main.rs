//! Firewall Audit CLI
//!
//! This binary audits firewall rules against user-defined criteria and exports the results in various formats (CSV, HTML, JSON).
//!
//! # Example
//! ```sh
//! firewall_audit --rules rules.yaml --export csv --output result.csv
//! ```

use clap::{Parser, ValueEnum};
use firewall_audit::{append_console_explanation, export_csv, export_html, export_json};
use std::process;

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
    let cli = Cli::parse();
    // Load rules file
    let rules_path = &cli.rules;
    let rules = std::fs::read_to_string(rules_path).unwrap_or_else(|e| {
        eprintln!("Error reading rules file '{}': {}", rules_path, e);
        process::exit(1);
    });
    // Simulate audit output (replace with real audit logic)
    let audit_output = rules; // TODO: call audit engine
    // Export
    let result = match cli.export {
        ExportFormat::Csv => {
            export_csv(&audit_output, cli.output.as_deref()).map_err(|e| e.to_string())
        }
        ExportFormat::Html => {
            export_html(&audit_output, cli.output.as_deref()).map_err(|e| e.to_string())
        }
        ExportFormat::Json => {
            export_json(&audit_output, cli.output.as_deref()).map_err(|e| e.to_string())
        }
    };
    match result {
        Ok(content) => {
            if cli.output.is_none() {
                println!("{}", append_console_explanation(&content));
            }
        }
        Err(e) => {
            eprintln!("Export error: {}", e);
            process::exit(1);
        }
    }
}
