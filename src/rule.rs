use std::collections::HashSet;
use std::net::IpAddr;
use windows_firewall::WindowsFirewallRule;

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub name: String,
    pub direction: String,
    pub enabled: bool,
    pub action: String,
    pub description: Option<String>,
    pub application_name: Option<String>,
    pub service_name: Option<String>,
    pub protocol: Option<String>,
    pub local_ports: Option<HashSet<u16>>,
    pub remote_ports: Option<HashSet<u16>>,
    pub local_addresses: Option<HashSet<IpAddr>>,
    pub remote_addresses: Option<HashSet<IpAddr>>,
    pub icmp_types_and_codes: Option<String>,
    pub interfaces: Option<HashSet<String>>,
    pub interface_types: Option<HashSet<String>>,
    pub grouping: Option<String>,
    pub profiles: Option<String>,
    pub edge_traversal: Option<bool>,
}

impl From<&WindowsFirewallRule> for FirewallRule {
    fn from(rule: &WindowsFirewallRule) -> Self {
        FirewallRule {
            name: rule.name().to_string(),
            direction: format!("{:?}", rule.direction()),
            enabled: rule.enabled(),
            action: format!("{:?}", rule.action()),
            description: rule.description().map(|s| s.to_string()),
            application_name: rule.application_name().map(|s| s.to_string()),
            service_name: rule.service_name().map(|s| s.to_string()),
            protocol: rule.protocol().map(|p| format!("{:?}", p)),
            local_ports: rule.local_ports().cloned(),
            remote_ports: rule.remote_ports().cloned(),
            local_addresses: rule.local_addresses().cloned(),
            remote_addresses: rule.remote_addresses().cloned(),
            icmp_types_and_codes: rule.icmp_types_and_codes().map(|s| s.to_string()),
            interfaces: rule.interfaces().cloned(),
            interface_types: rule
                .interface_types()
                .map(|set| set.iter().map(|i| format!("{:?}", i)).collect()),
            grouping: rule.grouping().map(|s| s.to_string()),
            profiles: rule.profiles().map(|p| format!("{:?}", p)),
            edge_traversal: rule.edge_traversal(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;
    use windows_firewall::{ActionFirewallWindows, DirectionFirewallWindows, WindowsFirewallRule};

    #[test]
    fn test_firewall_rule_from_windows() {
        let mut ports = HashSet::new();
        ports.insert(22);
        let mut addrs = HashSet::new();
        addrs.insert("127.0.0.1".parse::<IpAddr>().unwrap());
        let win_rule = WindowsFirewallRule::builder()
            .name("TestRule")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .local_ports(ports.clone())
            .local_addresses(addrs.clone())
            .build();
        let fw_rule = FirewallRule::from(&win_rule);
        assert_eq!(fw_rule.name, "TestRule");
        assert_eq!(fw_rule.direction, "In");
        assert!(fw_rule.enabled);
        assert_eq!(fw_rule.action, "Allow");
        assert_eq!(fw_rule.local_ports, Some(ports));
        assert_eq!(fw_rule.local_addresses, Some(addrs));
    }
}
