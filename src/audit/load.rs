use crate::criteria::types::AuditRule;
use crate::criteria::validation::validate_criteria_expr;
use crate::error::{FirewallAuditError, Result};
use std::path::Path;
use tracing::warn;

fn get_extension(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
}

fn load_audit_criteria_from<T, F>(path: &str, parse: F) -> Result<Vec<AuditRule>>
where
    F: Fn(&str) -> Result<Vec<T>>,
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
pub fn load_audit_criteria_yaml(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_criteria_from(path, |c| {
        serde_yaml::from_str::<Vec<serde_yaml::Value>>(c).map_err(FirewallAuditError::YamlParse)
    })
}

/// Loads audit criteria from a JSON file.
///
/// # Errors
/// Returns an error if parsing fails.
pub fn load_audit_criteria_json(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_criteria_from(path, |c| {
        serde_json::from_str::<Vec<serde_json::Value>>(c).map_err(FirewallAuditError::JsonParse)
    })
}

/// Loads and merges audit criteria from multiple YAML/JSON files.
///
/// # Errors
/// Returns an error if a file cannot be read or parsed.
pub fn load_audit_criteria_multi(paths: &[String]) -> Result<Vec<AuditRule>> {
    let mut all_criteria = Vec::new();
    for path in paths {
        let criteria: Vec<AuditRule> = match get_extension(path).as_deref() {
            Some("yaml" | "yml") => load_audit_criteria_yaml(path)?,
            Some("json") => load_audit_criteria_json(path)?,
            _ => {
                let try_yaml = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|c| serde_yaml::from_str::<Vec<AuditRule>>(&c).ok());
                if let Some(criteria) = try_yaml {
                    criteria
                } else {
                    let try_json = std::fs::read_to_string(path)
                        .ok()
                        .and_then(|c| serde_json::from_str::<Vec<AuditRule>>(&c).ok());
                    if let Some(criteria) = try_json {
                        criteria
                    } else {
                        return Err(FirewallAuditError::UnsupportedFileFormat {
                            path: path.clone(),
                        });
                    }
                }
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_audit_criteria_yaml() {
        let yaml = "- id: test\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = super::load_audit_criteria_yaml(path).expect("Failed to load YAML rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test");
    }

    #[test]
    fn test_load_audit_criteria_json() {
        let json = r#"[
            {"id": "testjson", "description": "desc", "criteria": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = super::load_audit_criteria_json(path).expect("Failed to load JSON rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "testjson");
    }

    #[test]
    fn test_load_audit_criteria_multi() {
        let yaml = "- id: test1\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let json = r#"[
            {"id": "test2", "description": "desc", "criteria": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpyaml = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let mut tmpjson = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        write!(tmpyaml, "{yaml}").unwrap();
        write!(tmpjson, "{json}").unwrap();
        let path_yaml = tmpyaml.path().to_str().unwrap().to_string();
        let path_json = tmpjson.path().to_str().unwrap().to_string();
        let rules = super::load_audit_criteria_multi(&[path_yaml, path_json])
            .expect("Failed to load multi rules");
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.id == "test1"));
        assert!(rules.iter().any(|r| r.id == "test2"));
    }

    #[test]
    fn test_load_audit_criteria_yaml_invalid_syntax() {
        let yaml = "- id: test\n  description: test\n  criteria: [INVALID\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_criteria_yaml(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_criteria_json_invalid_syntax() {
        let json = r#"[{\"id\": \"test\", \"description\": \"desc\", \"criteria\": {and: [}}]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_criteria_json(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_criteria_yaml_missing_field() {
        let yaml = "- description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_criteria_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.is_empty() || rules.iter().all(|r| !r.id.is_empty()));
    }

    #[test]
    fn test_load_audit_criteria_yaml_unknown_operator() {
        let yaml = "- id: test\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: unknownop\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_criteria_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.iter().any(|r| r.id == "test"));
        let rule = rules.iter().find(|r| r.id == "test").unwrap();
        if let crate::criteria::types::CriteriaExpr::Group { and } = &rule.criteria {
            for expr in and {
                if let crate::criteria::types::CriteriaExpr::Condition(cond) = expr {
                    assert!(cond.operator.is_none());
                }
            }
        }
    }

    #[test]
    fn test_load_audit_criteria_yaml_unknown_field_ignored() {
        let yaml = "- id: badfield\n  description: test\n  criteria:\n    and:\n      - field: notafield\n        operator: equals\n        value: 'foo'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules =
            super::load_audit_criteria_multi(&[path]).expect("Should not crash on unknown field");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_audit_criteria_yaml_wrong_type_ignored() {
        let yaml = "- id: badtype\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: in_range\n        value: 'notalist'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules =
            super::load_audit_criteria_multi(&[path]).expect("Should not crash on wrong type");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_audit_criteria_yaml_invalid_structure_ignored() {
        let yaml = "- id: invalid\n  description: test\n  criteria: 12345\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let res = super::load_audit_criteria_multi(&[path]);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_criteria_yaml_multiple_some_invalid() {
        let yaml = "- id: valid\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'ok'\n  severity: info\n- id: badfield\n  description: test\n  criteria:\n    and:\n      - field: notafield\n        operator: equals\n        value: 'foo'\n  severity: info\n- id: badtype\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: in_range\n        value: 'notalist'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules = super::load_audit_criteria_multi(&[path])
            .expect("Should not crash on mixed valid/invalid");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "valid");
    }
}
