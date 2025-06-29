use std::path::Path;
use tracing::warn;

use super::firewall_rule::{FirewallProvider, FirewallRule, FirewallRuleProvider};
use crate::criteria::eval::eval_criterias;
use crate::criteria::types::AuditRule;
use crate::criteria::validation::validate_criteria_expr;
use crate::error::{FirewallAuditError, Result};
use rayon::prelude::*;

/// Returns the file extension in lowercase, if any (without dot)
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
        // Convert value to serde_json::Value for uniform deserialization
        let json_val = serde_json::to_value(&val).unwrap();
        match serde_json::from_value::<AuditRule>(json_val) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                warn!("Rule at index {} ignored: {} (content: {:?})", i, e, val);
            }
        }
    }
    Ok(rules)
}

fn load_audit_rules_yaml(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_rules_from(path, |c| {
        serde_yaml::from_str::<Vec<serde_yaml::Value>>(c).map_err(FirewallAuditError::YamlParse)
    })
}

fn load_audit_rules_json(path: &str) -> Result<Vec<AuditRule>> {
    load_audit_rules_from(path, |c| {
        serde_json::from_str::<Vec<serde_json::Value>>(c).map_err(FirewallAuditError::JsonParse)
    })
}

/// Charge and merge audit rules from multiple YAML/JSON files
pub fn load_audit_rules_multi(paths: &[String]) -> Result<Vec<AuditRule>> {
    let mut all_rules = Vec::new();
    for path in paths {
        let rules: Vec<AuditRule> = match get_extension(path).as_deref() {
            Some("yaml" | "yml") => load_audit_rules_yaml(path)?,
            Some("json") => load_audit_rules_json(path)?,
            _ => {
                // Try YAML then JSON if no recognized extension
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
        // Validation: filter out invalid rules and print errors
        let mut valid_rules = Vec::new();
        for rule in rules {
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

/// Multi-file audit (YAML/JSON)
pub fn run_audit_multi(audit_rules: &[AuditRule]) -> Result<String> {
    let mut output = String::new();
    let firewall_rules: Vec<FirewallRule> = FirewallProvider::list_rules()?;
    output.push_str("\n--- Firewall Audit ---\n");
    for audit_rule in audit_rules {
        let matches: Vec<String> = firewall_rules
            .par_iter()
            .filter_map(|fw_rule| {
                if eval_criterias(fw_rule, &audit_rule.criterias) {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        if !matches.is_empty() {
            output.push_str(&format!("\nAudit Rule: {}\n", audit_rule.id));
            output.push_str(&format!("Description: {}\n", audit_rule.description));
            output.push_str(&format!("Severity: {}\n", audit_rule.severity));
            output.push_str(&format!("  ✅ {} match(es) found:\n", matches.len()));
            for name in matches {
                output.push_str(&format!("    - {name}\n"));
            }
        }
    }
    output.push_str("\n--- Audit End ---\n");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_parallel_vs_sequential_audit() {
        // Create a temporary YAML file with a single rule
        let yaml = "- id: test\n  description: test\n  criterias:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        // Simulate firewall rules
        let fw_rules: Vec<FirewallRule> = (0..1000)
            .map(|i| FirewallRule {
                name: if i == 42 {
                    "TestRule".to_string()
                } else {
                    format!("Rule-{i}")
                },
                direction: "In".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: None,
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
            })
            .collect();
        // Sequential audit
        let audit_rules = load_audit_rules_yaml(&path).expect("Failed to load audit rules");
        let mut matches_seq = Vec::new();
        for audit_rule in &audit_rules {
            for fw_rule in &fw_rules {
                if eval_criterias(fw_rule, &audit_rule.criterias) {
                    matches_seq.push(fw_rule.name.clone());
                }
            }
        }
        // Parallel audit
        let matches_par: Vec<String> = fw_rules
            .par_iter()
            .filter_map(|fw_rule| {
                if eval_criterias(fw_rule, &audit_rules[0].criterias) {
                    Some(fw_rule.name.clone())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(matches_seq, matches_par);
    }
}
