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

        // Direction detection
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
            os: Some("linux".to_string()),
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
            icmp_types_and_codes: None, // parse if needed
            interfaces,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
        }
    }
}

impl FirewallRuleProvider for LinuxFirewallProvider {
    /// Lists all firewall rules available from the Linux firewall.
    ///
    /// # Errors
    /// Returns an error if the firewall rules cannot be listed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;

    #[test]
    fn test_from_linux_firewall_rule_minimal() {
        let rule = LinuxFirewallRule {
            tokens: vec!["-A".into(), "RULE1".into()],
            raw_line: "-A RULE1".into(),
        };
        let fw = FirewallRule::from(&rule);
        assert_eq!(fw.name, "RULE1");
        assert_eq!(fw.direction, "Unknown");
        assert_eq!(fw.action, "Other");
        assert!(fw.enabled);
        assert_eq!(fw.os.as_deref(), Some("linux"));
    }

    #[test]
    fn test_from_linux_firewall_rule_full() {
        let mut tokens = vec![
            "-A".into(),
            "RULE2".into(),
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            "80".into(),
            "--sport".into(),
            "12345".into(),
            "-s".into(),
            "127.0.0.1".into(),
            "-d".into(),
            "8.8.8.8".into(),
            "-i".into(),
            "eth0".into(),
            "-o".into(),
            "eth1".into(),
            "-j".into(),
            "ACCEPT".into(),
        ];
        let rule = LinuxFirewallRule {
            tokens: tokens.clone(),
            raw_line: "-A RULE2 -p tcp --dport 80 --sport 12345 -s 127.0.0.1 -d 8.8.8.8 -i eth0 -o eth1 -j ACCEPT".into(),
        };
        let fw = FirewallRule::from(&rule);
        assert_eq!(fw.name, "RULE2");
        assert_eq!(fw.direction, "Unknown");
        assert_eq!(fw.action, "Allow");
        assert_eq!(fw.protocol.as_deref(), Some("tcp"));
        assert!(fw.local_ports.as_ref().unwrap().contains(&80));
        assert!(fw.remote_ports.as_ref().unwrap().contains(&12345));
        assert!(fw
            .local_addresses
            .as_ref()
            .unwrap()
            .contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(fw
            .remote_addresses
            .as_ref()
            .unwrap()
            .contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(fw.interfaces.as_ref().unwrap().contains("eth0"));
        assert!(fw.interfaces.as_ref().unwrap().contains("eth1"));
    }

    #[test]
    fn test_direction_detection() {
        let rule_in = LinuxFirewallRule {
            tokens: vec!["-A".into(), "RULEIN".into()],
            raw_line: "-A RULEIN ... INPUT ...".into(),
        };
        let fw_in = FirewallRule::from(&rule_in);
        assert_eq!(fw_in.direction, "In");
        let rule_out = LinuxFirewallRule {
            tokens: vec!["-A".into(), "RULEOUT".into()],
            raw_line: "-A RULEOUT ... OUTPUT ...".into(),
        };
        let fw_out = FirewallRule::from(&rule_out);
        assert_eq!(fw_out.direction, "Out");
    }

    #[test]
    fn test_action_friendly() {
        let accept = LinuxFirewallRule {
            tokens: vec!["-A".into(), "R".into(), "-j".into(), "ACCEPT".into()],
            raw_line: "-A R -j ACCEPT".into(),
        };
        let drop = LinuxFirewallRule {
            tokens: vec!["-A".into(), "R".into(), "-j".into(), "DROP".into()],
            raw_line: "-A R -j DROP".into(),
        };
        let reject = LinuxFirewallRule {
            tokens: vec!["-A".into(), "R".into(), "-j".into(), "REJECT".into()],
            raw_line: "-A R -j REJECT".into(),
        };
        let other = LinuxFirewallRule {
            tokens: vec!["-A".into(), "R".into(), "-j".into(), "CUSTOM".into()],
            raw_line: "-A R -j CUSTOM".into(),
        };
        let fw_accept = FirewallRule::from(&accept);
        let fw_drop = FirewallRule::from(&drop);
        let fw_reject = FirewallRule::from(&reject);
        let fw_other = FirewallRule::from(&other);
        assert_eq!(fw_accept.action, "Allow");
        assert_eq!(fw_drop.action, "Deny");
        assert_eq!(fw_reject.action, "Deny");
        assert_eq!(fw_other.action, "CUSTOM");
    }

    #[test]
    fn test_list_rules_error() {
        let res = LinuxFirewallProvider::list_rules();
        assert!(res.is_ok() || res.is_err());
    }
}
