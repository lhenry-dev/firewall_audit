use crate::error::{FirewallAuditError, Result};
use crate::firewall_rule::FirewallRule;
use crate::firewall_rule::FirewallRuleProvider;
use windows_firewall::WindowsFirewallRule;

pub struct WindowsFirewallProvider;

impl FirewallRuleProvider for WindowsFirewallProvider {
    fn list_rules() -> Result<Vec<FirewallRule>> {
        windows_firewall::list_rules()
            .map(|rules| rules.iter().map(FirewallRule::from).collect())
            .map_err(|e| FirewallAuditError::WindowsFirewallError(e.to_string()))
    }
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
