use crate::criteria::types::AuditRule;
use crate::loader::{LoaderError, filter_and_validate};
use std::path::Path;
use tracing::warn;

fn get_extension(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

fn load_audit_criteria_from<T, F>(path: &str, parse: F) -> Result<Vec<AuditRule>, LoaderError>
where
    F: Fn(&str) -> Result<Vec<T>, LoaderError>,
    T: serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let contents = std::fs::read_to_string(path).map_err(LoaderError::Io)?;
    let values = parse(&contents)?;
    let mut criteria = Vec::new();
    for (i, val) in values.into_iter().enumerate() {
        let json_val = serde_json::to_value(&val)?;
        match serde_json::from_value::<AuditRule>(json_val) {
            Ok(rule) => criteria.push(rule),
            Err(e) => {
                warn!(
                    "Criteria at index {} ignored: {} (content: {:?})",
                    i, e, val
                );
            }
        }
    }
    Ok(criteria)
}

/// Loads audit criteria from a YAML file.
///
/// # Errors
/// Returns an error if parsing fails.
pub fn load_audit_criteria_yaml(path: &str) -> Result<Vec<AuditRule>, LoaderError> {
    load_audit_criteria_from(path, |c| {
        serde_yaml::from_str::<Vec<serde_yaml::Value>>(c).map_err(LoaderError::YamlParse)
    })
}

/// Loads audit criteria from a JSON file.
///
/// # Errors
/// Returns an error if parsing fails.
pub fn load_audit_criteria_json(path: &str) -> Result<Vec<AuditRule>, LoaderError> {
    load_audit_criteria_from(path, |c| {
        serde_json::from_str::<Vec<serde_json::Value>>(c).map_err(LoaderError::JsonParse)
    })
}

/// Loads and merges audit criteria from multiple YAML/JSON files.
///
/// # Errors
/// Returns an error if a file cannot be read or parsed.
pub fn load_audit_criteria_from_paths(paths: &[String]) -> Result<Vec<AuditRule>, LoaderError> {
    let mut all_criteria = Vec::new();

    for path in paths {
        let criteria: Vec<AuditRule> = match get_extension(path).as_deref() {
            Some("yaml" | "yml") => load_audit_criteria_yaml(path)?,
            Some("json") => load_audit_criteria_json(path)?,
            _ => {
                return Err(LoaderError::UnsupportedFileFormat {
                    path: path.to_string(),
                });
            }
        };

        all_criteria.extend(filter_and_validate(criteria)?);
    }

    Ok(all_criteria)
}
