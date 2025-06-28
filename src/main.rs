use optional_field::{Field, serde_optional_fields};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use windows_firewall::{WindowsFirewallRule, list_rules};

pub struct FirewallRule {
    pub name: String,
    pub local_ports: HashSet<u16>,
    pub protocol: String,
    pub remote_addresses: HashSet<IpAddr>,
    pub action: String,
    pub application_name: Option<String>,
}

impl From<&WindowsFirewallRule> for FirewallRule {
    fn from(rule: &WindowsFirewallRule) -> Self {
        FirewallRule {
            name: rule.name().to_string(),
            local_ports: rule.local_ports().unwrap_or(&HashSet::new()).clone(),
            protocol: format!(
                "{:?}",
                rule.protocol()
                    .unwrap_or(&windows_firewall::ProtocolFirewallWindows::Any)
            ),
            remote_addresses: rule.remote_addresses().unwrap_or(&HashSet::new()).clone(),
            action: format!("{:?}", rule.action()),
            application_name: rule.application_name().map(|s| s.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuditRule {
    id: String,
    description: String,
    criteria: RuleCriteria,
    severity: String,
}

// #[serde_optional_fields]
// #[derive(Debug, Serialize, Deserialize)]
// struct RuleCriteria {
//     local_ports: Vec<u16>,
//     protocol: String,
//     remote_addresses: Vec<String>,
//     action: String,
//     application_name: String,
// }

#[serde_optional_fields]
#[derive(Debug, Serialize, Deserialize)]
struct RuleCriteria {
    local_ports: Field<Vec<u16>>,
    protocol: Field<String>,
    remote_addresses: Field<Vec<String>>,
    action: Field<String>,
    application_name: Field<String>,
}

fn load_audit_rules_json(path: &str) -> Vec<AuditRule> {
    let contents =
        fs::read_to_string(path).expect("Erreur lors de la lecture du fichier rules.json");
    serde_json::from_str(&contents).expect("Erreur lors du parsing du fichier rules.json")
}

pub fn load_audit_rules_yaml(path: &str) -> Vec<AuditRule> {
    let contents =
        fs::read_to_string(path).expect("Erreur lors de la lecture du fichier rules.yaml");
    serde_yaml::from_str(&contents).expect("Erreur lors du parsing du fichier rules.yaml")
}

fn inspect_yaml_object(obj: &Value) {
    if let Value::Mapping(map) = obj {
        for (k, v) in map {
            println!("{:?}: {:?}", k, v);
        }
    }
}

fn check_rule_against_criteria(rule: &FirewallRule, criteria: &RuleCriteria) -> bool {
    // let Some(value) = serde_yaml::to_value(&rule.criteria).expect("Erreur de conversion en Value");

    true
}

// fn check_rule_against_criteria(rule: &FirewallRule, criteria: &RuleCriteria) -> bool {
//     // Ports
//     if let Some(ports) = &criteria.local_ports {
//         if rule.local_ports.is_empty() || !ports.iter().any(|&p| rule.local_ports.contains(&p)) {
//             return false;
//         }
//     }

//     // Protocole
//     if let Some(protocol) = &criteria.protocol {
//         if rule.protocol.to_uppercase() != protocol.to_uppercase() {
//             return false;
//         }
//     }

//     // Adresses IP
//     if let Some(addresses) = &criteria.remote_addresses {
//         if rule.remote_addresses.is_empty() {
//             return false;
//         }
//         let parsed_addresses: Vec<IpAddr> =
//             addresses.iter().filter_map(|s| s.parse().ok()).collect();
//         if !parsed_addresses
//             .iter()
//             .any(|addr| rule.remote_addresses.contains(addr))
//         {
//             return false;
//         }
//     }

//     // Action
//     if let Some(action) = &criteria.action {
//         if rule.action.to_uppercase() != action.to_uppercase() {
//             return false;
//         }
//     }

//     // Application
//     if let Some(app_name) = &criteria.application_name {
//         if rule.application_name.as_deref() != Some(app_name) {
//             return false;
//         }
//     }

//     true
// }

fn main() {
    // let audit_rules = load_audit_rules_json("rules.json");

    let audit_rules = load_audit_rules_yaml("rules.yaml");

    for rule in &audit_rules {
        let value = serde_yaml::to_value(&rule.criteria).expect("Erreur de conversion en Value");
        println!("Inspecting criteria for rule: {}", rule.id);
        inspect_yaml_object(&value);
        println!("----------------------------");
    }

    // for rule in &audit_rules {
    //     println!("\nRègle d'audit trouvée: {}", rule.id);
    //     println!("Description: {}", rule.description);
    //     println!("Sévérité: {}", rule.severity);
    //     println!("Critères:");
    //     println!("  - Ports locaux: {:?}", rule.criteria.local_ports);
    //     println!("  - Protocole: {:?}", rule.criteria.protocol);
    //     println!(
    //         "  - Adresses distantes: {:?}",
    //         rule.criteria.remote_addresses
    //     );
    //     println!("  - Action: {:?}", rule.criteria.action);
    //     println!(
    //         "  - Nom de l'application: {:?}",
    //         rule.criteria.application_name
    //     );
    // }

    match list_rules() {
        Ok(rules) => {
            // println!("\nRègles du firewall trouvées:");
            // for rule in &rules {
            //     println!("- {}", rule.name());
            // }

            // let firewall_rules: Vec<FirewallRule> = rules.iter().map(FirewallRule::from).collect();

            // for audit_rule in &audit_rules {
            //     println!("\nVérification de la règle d'audit: {}", audit_rule.id);
            //     println!("Description: {}", audit_rule.description);
            //     println!("Sévérité: {}", audit_rule.severity);

            //     let matching_rules: Vec<&FirewallRule> = firewall_rules
            //         .iter()
            //         .filter(|rule| check_rule_against_criteria(rule, &audit_rule.criteria))
            //         .collect();

            //     if matching_rules.is_empty() {
            //         println!("❌ Aucune règle correspondante trouvée");
            //     } else {
            //         println!("✅ Règles correspondantes trouvées:");
            //         for rule in matching_rules {
            //             println!("  - {}", rule.name);
            //         }
            //     }
            // }
        }
        Err(e) => eprintln!("Échec récupération règles : {}", e),
    }
}
