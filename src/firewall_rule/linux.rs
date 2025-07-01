use crate::error::{FirewallAuditError, Result};
use crate::firewall_rule::FirewallRule;
use crate::firewall_rule::FirewallRuleProvider;
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;

pub struct LinuxFirewallProvider;

#[derive(Debug, Clone)]
pub struct LinuxFirewallRule {
    pub tokens: Vec<String>,
    pub raw_line: String,
}

impl From<&LinuxFirewallRule> for FirewallRule {
    fn from(rule: &LinuxFirewallRule) -> Self {
        let tokens = &rule.tokens;
        let line = &rule.raw_line;
        let mut local_ports = None;
        let mut remote_ports = None;
        let mut local_addresses = None;
        let mut remote_addresses = None;
        let mut interfaces = None;
        let mut protocol = None;
        let mut action = None;
        let mut direction = "Unknown".to_string();
        let mut service_name = None;

        let mut i = 0;
        while i < tokens.len() {
            match tokens[i].as_str() {
                "-p" => {
                    if let Some(proto) = tokens.get(i + 1) {
                        protocol = Some(proto.clone());
                    }
                    i += 1;
                }
                "--dport" => {
                    if let Some(port) = tokens.get(i + 1) {
                        if let Ok(port) = port.parse() {
                            local_ports.get_or_insert_with(HashSet::new).insert(port);
                        }
                    }
                    i += 1;
                }
                "--sport" => {
                    if let Some(port) = tokens.get(i + 1) {
                        if let Ok(port) = port.parse() {
                            remote_ports.get_or_insert_with(HashSet::new).insert(port);
                        }
                    }
                    i += 1;
                }
                "-s" => {
                    if let Some(addr) = tokens.get(i + 1) {
                        if let Ok(ip) = addr.parse() {
                            local_addresses.get_or_insert_with(HashSet::new).insert(ip);
                        }
                    }
                    i += 1;
                }
                "-d" => {
                    if let Some(addr) = tokens.get(i + 1) {
                        if let Ok(ip) = addr.parse() {
                            remote_addresses.get_or_insert_with(HashSet::new).insert(ip);
                        }
                    }
                    i += 1;
                }
                "-i" => {
                    if let Some(intf) = tokens.get(i + 1) {
                        interfaces
                            .get_or_insert_with(HashSet::new)
                            .insert(intf.clone());
                    }
                    i += 1;
                }
                "-o" => {
                    if let Some(intf) = tokens.get(i + 1) {
                        interfaces
                            .get_or_insert_with(HashSet::new)
                            .insert(intf.clone());
                    }
                    i += 1;
                }
                "-j" => {
                    if let Some(target) = tokens.get(i + 1) {
                        action = Some(target.clone());
                    }
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }

        // Détection direction
        if line.contains("INPUT") {
            direction = "In".to_string();
        } else if line.contains("OUTPUT") {
            direction = "Out".to_string();
        }

        // Action friendly
        let action_friendly = match action.as_deref() {
            Some("ACCEPT") => "Allow".to_string(),
            Some("DROP") | Some("REJECT") => "Deny".to_string(),
            Some(a) => a.to_string(),
            None => "Other".to_string(),
        };

        FirewallRule {
            name: tokens
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("(unnamed)")
                .to_string(),
            direction,
            enabled: true,
            action: action_friendly,
            description: None,
            application_name: None,
            service_name,
            protocol,
            local_ports,
            remote_ports,
            local_addresses,
            remote_addresses,
            icmp_types_and_codes: None, // à parser si besoin
            interfaces,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
        }
    }
}

impl FirewallRuleProvider for LinuxFirewallProvider {
    fn list_rules() -> Result<Vec<FirewallRule>> {
        let output = Command::new("sudo").arg("iptables").arg("-S").output();
        if let Ok(out) = output {
            if !out.status.success() {
                return Err(FirewallAuditError::ValidationError(format!(
                    "Failed to execute iptables -S (code: {:?}, stderr: {})",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            println!("{stdout}");
            println!("Fin sortie brut");
            let mut rules = Vec::new();
            for line in stdout.lines() {
                if line.starts_with("-N") || line.starts_with("-P") {
                    // Ignore chain definitions and policies
                    continue;
                }
                let tokens: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
                if tokens.is_empty() {
                    continue;
                }
                let linux_rule = LinuxFirewallRule {
                    tokens,
                    raw_line: line.to_string(),
                };
                rules.push(FirewallRule::from(&linux_rule));
            }
            Ok(rules)
        } else {
            Err(FirewallAuditError::ValidationError(
                "Failed to run iptables -S".to_string(),
            ))
        }
    }
}
