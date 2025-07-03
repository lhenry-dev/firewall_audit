// Loading and parsing audit rules
// Functions extracted from the old audit.rs

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

fn load_audit_rules_from<T, F>(path: &str, parse: F) -> Result<Vec<AuditRule>>
where
    F: Fn(&str) -> Result<Vec<T>>,
    T: serde::de::DeserializeOwned + serde::Serialize + std::fmt::Debug,
{
    let contents = std::fs::read_to_string(path).map_err(FirewallAuditError::Io)?;
    let values = parse(&contents)?;
    let mut rules = Vec::new();
    for (i, val) in values.into_iter().enumerate() {
        let json_val = serde_json::to_value(&val)?;
        match serde_json::from_value::<AuditRule>(json_val) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                warn!("Rule at index {} ignored: {} (content: {:?})", i, e, val);
            }
        }
    }
    Ok(rules)
}

/// Loads audit rules from a YAML file.
/// Returns an error if parsing fails.
pub fn load_audit_rules_yaml(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_rules_from(path, |c| {
        serde_yaml::from_str::<Vec<serde_yaml::Value>>(c).map_err(FirewallAuditError::YamlParse)
    })
}

/// Loads audit rules from a JSON file.
/// Returns an error if parsing fails.
pub fn load_audit_rules_json(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_rules_from(path, |c| {
        serde_json::from_str::<Vec<serde_json::Value>>(c).map_err(FirewallAuditError::JsonParse)
    })
}

/// Loads and merges audit rules from multiple YAML/JSON files.
/// Returns an error if a file cannot be read or parsed.
pub fn load_audit_rules_multi(paths: &[String]) -> Result<Vec<AuditRule>> {
    let mut all_rules = Vec::new();
    for path in paths {
        let rules: Vec<AuditRule> = match get_extension(path).as_deref() {
            Some("yaml" | "yml") => load_audit_rules_yaml(path)?,
            Some("json") => load_audit_rules_json(path)?,
            _ => {
                let try_yaml = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|c| serde_yaml::from_str::<Vec<AuditRule>>(&c).ok());
                if let Some(rules) = try_yaml {
                    rules
                } else {
                    let try_json = std::fs::read_to_string(path)
                        .ok()
                        .and_then(|c| serde_json::from_str::<Vec<AuditRule>>(&c).ok());
                    if let Some(rules) = try_json {
                        rules
                    } else {
                        return Err(FirewallAuditError::UnsupportedFileFormat {
                            path: path.clone(),
                        });
                    }
                }
            }
        };
        let mut valid_rules = Vec::new();
        let current_os = std::env::consts::OS;
        for rule in rules {
            let applies = match &rule.os {
                None => true,
                Some(list) if list.is_empty() => true,
                Some(list) => list.iter().any(|os| os.eq_ignore_ascii_case(current_os)),
            };
            if !applies {
                continue;
            }
            let errors =
                validate_criteria_expr(&rule.criterias, &format!("rule '{}':root", rule.id));
            if errors.is_empty() {
                valid_rules.push(rule);
            } else {
                for err in errors {
                    warn!("Rule '{}' ignored: {}", rule.id, err);
                }
            }
        }
        all_rules.extend(valid_rules);
    }
    Ok(all_rules)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_audit_rules_yaml() {
        let yaml = "- id: test\n  description: test\n  criterias:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = super::load_audit_rules_yaml(path).expect("Failed to load YAML rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test");
    }

    #[test]
    fn test_load_audit_rules_json() {
        let json = r#"[
            {"id": "testjson", "description": "desc", "criterias": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = super::load_audit_rules_json(path).expect("Failed to load JSON rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "testjson");
    }

    #[test]
    fn test_load_audit_rules_multi() {
        let yaml = "- id: test1\n  description: test\n  criterias:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let json = r#"[
            {"id": "test2", "description": "desc", "criterias": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpyaml = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let mut tmpjson = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        write!(tmpyaml, "{yaml}").unwrap();
        write!(tmpjson, "{json}").unwrap();
        let path_yaml = tmpyaml.path().to_str().unwrap().to_string();
        let path_json = tmpjson.path().to_str().unwrap().to_string();
        let rules = super::load_audit_rules_multi(&[path_yaml, path_json])
            .expect("Failed to load multi rules");
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.id == "test1"));
        assert!(rules.iter().any(|r| r.id == "test2"));
    }

    #[test]
    fn test_load_audit_rules_yaml_invalid_syntax() {
        let yaml = "- id: test\n  description: test\n  criterias: [INVALID\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_rules_yaml(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_rules_json_invalid_syntax() {
        let json = r#"[{\"id\": \"test\", \"description\": \"desc\", \"criterias\": {and: [}}]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_rules_json(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_rules_yaml_missing_field() {
        let yaml = "- description: test\n  criterias:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_rules_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.is_empty() || rules.iter().all(|r| !r.id.is_empty()));
    }

    #[test]
    fn test_load_audit_rules_yaml_unknown_operator() {
        let yaml = "- id: test\n  description: test\n  criterias:\n    and:\n      - field: name\n        operator: unknownop\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = super::load_audit_rules_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.iter().any(|r| r.id == "test"));
        let rule = rules.iter().find(|r| r.id == "test").unwrap();
        if let crate::criteria::types::CriteriaExpr::Group { and } = &rule.criterias {
            for expr in and {
                if let crate::criteria::types::CriteriaExpr::Condition(cond) = expr {
                    assert!(cond.operator.is_none());
                }
            }
        }
    }
}
