use tracing::warn;

use crate::{
    criteria::{types::AuditRule, validation::validate_criteria_expr},
    loader::load::load_audit_criteria_from_paths,
};

mod load;
mod tests;

const DEFAULT_CRITERIA: &str = include_str!("../audit_criteria/audit_criteria.yaml");

/// Error type for `loader` operations.
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// YAML parsing error
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),
    /// JSON parsing error
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    /// Unsupported file format
    #[error("Unsupported file format: {path}")]
    UnsupportedFileFormat {
        /// File path
        path: String,
    },
}

pub fn load_audit_criteria(criteria_path: Option<String>) -> Result<Vec<AuditRule>, LoaderError> {
    match criteria_path {
        Some(path) => load_audit_criteria_from_paths(&[path]),
        None => {
            let criteria: Vec<AuditRule> =
                serde_yaml::from_str(DEFAULT_CRITERIA).map_err(LoaderError::YamlParse)?;
            filter_and_validate(criteria)
        }
    }
}

fn filter_and_validate(criteria: Vec<AuditRule>) -> Result<Vec<AuditRule>, LoaderError> {
    let mut valid = Vec::new();
    let current_os = std::env::consts::OS;

    for rule in criteria {
        let applies = match &rule.os {
            None => true,
            Some(list) if list.is_empty() => true,
            Some(list) => list.iter().any(|os| os.eq_ignore_ascii_case(current_os)),
        };
        if !applies {
            continue;
        }

        let errors =
            validate_criteria_expr(&rule.criteria, &format!("criteria '{}':root", rule.id));
        if !errors.is_empty() {
            for err in errors {
                warn!("Criteria '{}' ignored: {}", rule.id, err);
            }
            continue;
        }
        valid.push(rule);
    }

    Ok(valid)
}
