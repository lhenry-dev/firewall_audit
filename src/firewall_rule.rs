use struct_field_names_as_array::FieldNamesAsSlice;

use crate::error::{FirewallAuditError, Result};
use std::collections::HashSet;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

/// Represents a firewall rule (cross-platform abstraction).
#[derive(Debug, Clone, FieldNamesAsSlice)]
pub struct FirewallRule {
    /// OS of rule origin (e.g., "linux", "windows")
    pub os: Option<String>,
    /// Rule name
    pub name: String,
    /// Rule direction (In/Out)
    pub direction: String,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Action (Allow/Deny)
    pub action: String,
    /// Description
    pub description: Option<String>,
    /// Application name
    pub application_name: Option<String>,
    /// Service name
    pub service_name: Option<String>,
    /// Protocol
    pub protocol: Option<String>,
    /// Local ports
    pub local_ports: Option<HashSet<u16>>,
    /// Remote ports
    pub remote_ports: Option<HashSet<u16>>,
    /// Local addresses
    pub local_addresses: Option<HashSet<IpAddr>>,
    /// Remote addresses
    pub remote_addresses: Option<HashSet<IpAddr>>,
    /// ICMP types and codes
    pub icmp_types_and_codes: Option<String>,
    /// Interfaces
    pub interfaces: Option<HashSet<String>>,
    /// Interface types
    pub interface_types: Option<HashSet<String>>,
    /// Grouping
    pub grouping: Option<String>,
    /// Profiles
    pub profiles: Option<String>,
    /// Edge traversal
    pub edge_traversal: Option<bool>,
}

impl FirewallRule {
    /// Returns the list of valid field names for criteria expressions.
    pub fn valid_fields() -> &'static [&'static str] {
        Self::FIELD_NAMES_AS_SLICE
    }
}

pub trait FirewallRuleProvider {
    fn list_rules() -> Result<Vec<FirewallRule>>;
}

#[cfg(target_os = "windows")]
pub use crate::firewall_rule::windows::WindowsFirewallProvider as FirewallProvider;

#[cfg(target_os = "linux")]
pub use crate::firewall_rule::linux::LinuxFirewallProvider as FirewallProvider;

#[cfg(target_os = "windows")]
mod platform {
    use super::{FirewallAuditError, FirewallRule, FirewallRuleProvider, Result};
    pub struct WindowsFirewallProvider;
    impl FirewallRuleProvider for WindowsFirewallProvider {
        fn list_rules() -> Result<Vec<FirewallRule>> {
            windows_firewall::list_rules()
                .map(|rules| rules.iter().map(FirewallRule::from).collect())
                .map_err(|e| FirewallAuditError::WindowsFirewallError(e.to_string()))
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{FirewallRule, FirewallRuleProvider, Result};
    use crate::firewall_rule::linux::LinuxFirewallProvider;
    pub struct PlatformLinuxFirewallProvider;
    impl FirewallRuleProvider for PlatformLinuxFirewallProvider {
        fn list_rules() -> Result<Vec<FirewallRule>> {
            LinuxFirewallProvider::list_rules()
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
            let rules = crate::firewall_rule::platform::WindowsFirewallProvider::list_rules();
            match rules {
                Ok(rules) => {
                    for rule in rules {
                        println!("{:?}", rule);
                    }
                }
                Err(e) => println!("Error: {:?}", e),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let rules = crate::firewall_rule::platform::PlatformLinuxFirewallProvider::list_rules();
            match rules {
                Ok(rules) => {
                    for rule in rules {
                        println!("{:?}", rule);
                    }
                }
                Err(e) => println!("Error: {:?}", e),
            }
        }
    }
}
