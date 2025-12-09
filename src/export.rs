use clap::ValueEnum;

pub mod csv;
pub mod html;
pub mod json;
pub mod summary;
pub mod text;

pub use csv::export_csv;
pub use html::export_html;
pub use json::export_json;
pub use summary::audit_summary_phrase;
pub use text::export_text;
use tracing::info;

use crate::audit::AuditMatch;

/// Error type for `export` operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Formatting error
    #[error("Formatting error: {0}")]
    Fmt(#[from] std::fmt::Error),
    /// JSON parsing error
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
}

/// Supported export formats
#[derive(ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Csv,
    Html,
    Json,
    Stdout,
}

pub fn export_results(
    audit_results: &[AuditMatch],
    export: &ExportFormat,
    output_path: Option<String>,
) -> Result<(), ExportError> {
    let output_path = output_path.clone().unwrap_or_else(|| {
        format!(
            "firewall_audit_{}.{}",
            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            match export {
                ExportFormat::Csv => "csv",
                ExportFormat::Html => "html",
                ExportFormat::Json => "json",
                ExportFormat::Stdout => "txt",
            }
        )
    });

    match &export {
        ExportFormat::Csv => {
            export_csv(audit_results, Some(&output_path))?;
        }
        ExportFormat::Html => {
            export_html(audit_results, Some(&output_path))?;
        }
        ExportFormat::Json => {
            export_json(audit_results, Some(&output_path))?;
        }
        ExportFormat::Stdout => println!("{}", export_text(audit_results)?),
    }

    if !matches!(export, ExportFormat::Stdout) {
        info!("Export successful to {}", output_path);
    }

    println!();
    info!("{}", audit_summary_phrase(audit_results));

    Ok(())
}
