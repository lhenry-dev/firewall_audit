use std::collections::HashSet;
use std::net::IpAddr;

pub mod linux;
pub mod windows;

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

pub trait FirewallRuleProvider {
    fn list_rules() -> Vec<FirewallRule>;
}

#[cfg(target_os = "windows")]
pub use crate::firewall_rule::windows::WindowsFirewallProvider as FirewallProvider;

#[cfg(target_os = "linux")]
pub use crate::firewall_rule::linux::LinuxFirewallProvider as FirewallProvider;

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    pub struct WindowsFirewallProvider;
    impl FirewallRuleProvider for WindowsFirewallProvider {
        fn list_rules() -> Vec<FirewallRule> {
            match windows_firewall::list_rules() {
                Ok(rules) => rules.iter().map(FirewallRule::from).collect(),
                Err(e) => {
                    eprintln!("Failed to retrieve Windows Firewall rules: {}", e);
                    vec![]
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    pub struct LinuxFirewallProvider;
    impl FirewallRuleProvider for LinuxFirewallProvider {
        fn list_rules() -> Vec<FirewallRule> {
            eprintln!("Firewall rule listing is not implemented on Linux. Returning empty list.");
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_list_rules_compiles() {
        #[cfg(target_os = "windows")]
        {
            let _rules = crate::firewall_rule::platform::WindowsFirewallProvider::list_rules();
        }
        #[cfg(target_os = "linux")]
        {
            let _rules = crate::firewall_rule::platform::LinuxFirewallProvider::list_rules();
        }
    }
}
