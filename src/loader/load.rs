use crate::criteria::types::AuditRule;
use crate::criteria::validation::validate_criteria_expr;
use crate::error::FirewallAuditError;
use std::path::Path;
use tracing::warn;

fn get_extension(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

fn load_audit_criteria_from<T, F>(
    path: &str,
    parse: F,
) -> Result<Vec<AuditRule>, FirewallAuditError>
where
    F: Fn(&str) -> Result<Vec<T>, FirewallAuditError>,
    T: serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let contents = std::fs::read_to_string(path).map_err(FirewallAuditError::Io)?;
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
pub fn load_audit_criteria_yaml(path: &str) -> Result<Vec<AuditRule>, FirewallAuditError> {
    load_audit_criteria_from(path, |c| {
        serde_yaml::from_str::<Vec<serde_yaml::Value>>(c).map_err(FirewallAuditError::YamlParse)
    })
}

/// Loads audit criteria from a JSON file.
///
/// # Errors
/// Returns an error if parsing fails.
pub fn load_audit_criteria_json(path: &str) -> Result<Vec<AuditRule>, FirewallAuditError> {
    load_audit_criteria_from(path, |c| {
        serde_json::from_str::<Vec<serde_json::Value>>(c).map_err(FirewallAuditError::JsonParse)
    })
}

/// Loads and merges audit criteria from multiple YAML/JSON files.
///
/// # Errors
/// Returns an error if a file cannot be read or parsed.
pub fn load_audit_criteria_multi(paths: &[String]) -> Result<Vec<AuditRule>, FirewallAuditError> {
    let mut all_criteria = Vec::new();
    for path in paths {
        let criteria: Vec<AuditRule> = match get_extension(path).as_deref() {
            Some("yaml" | "yml") => load_audit_criteria_yaml(path)?,
            Some("json") => load_audit_criteria_json(path)?,
            _ => {
                return Err(FirewallAuditError::UnsupportedFileFormat { path: path.clone() });
            }
        };
        let mut valid_criteria = Vec::new();
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
            if errors.is_empty() {
                valid_criteria.push(rule);
            } else {
                for err in errors {
                    warn!("Criteria '{}' ignored: {}", rule.id, err);
                }
            }
        }
        all_criteria.extend(valid_criteria);
    }
    Ok(all_criteria)
}
