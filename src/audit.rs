use crate::criteria::{AuditRule, eval_criterias};
use crate::rule::FirewallRule;
use std::fs;
use windows_firewall::list_rules;

fn load_audit_rules_yaml(path: &str) -> Vec<AuditRule> {
    let contents =
        fs::read_to_string(path).expect("Erreur lors de la lecture du fichier rules.yaml");
    serde_yaml::from_str(&contents).expect("Erreur lors du parsing du fichier rules.yaml")
}

pub fn run_audit(yaml_path: &str) -> String {
    let audit_rules = load_audit_rules_yaml(yaml_path);
    let mut output = String::new();
    match list_rules() {
        Ok(rules) => {
            let firewall_rules: Vec<FirewallRule> = rules.iter().map(FirewallRule::from).collect();
            output.push_str("\n--- Audit Firewall ---\n");
            for audit_rule in &audit_rules {
                let mut matches = Vec::new();
                for fw_rule in &firewall_rules {
                    if eval_criterias(fw_rule, &audit_rule.criterias) {
                        matches.push(fw_rule.name.clone());
                    }
                }
                if !matches.is_empty() {
                    output.push_str(&format!("\nRègle d'audit: {}\n", audit_rule.id));
                    output.push_str(&format!("Description: {}\n", audit_rule.description));
                    output.push_str(&format!("Sévérité: {}\n", audit_rule.severity));
                    output.push_str(&format!(
                        "  ✅ {} correspondance(s) trouvée(s):\n",
                        matches.len()
                    ));
                    for name in matches {
                        output.push_str(&format!("    - {}\n", name));
                    }
                }
            }
            output.push_str("\n--- Fin de l'audit ---\n");
        }
        Err(e) => output.push_str(&format!("Échec récupération règles : {}\n", e)),
    }
    output
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    #[test]
    fn test_load_audit_rules_yaml() {
        let yaml = "- id: test\n  description: test\n  criterias:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, "{}", yaml).unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = super::load_audit_rules_yaml(path);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test");
    }
}
