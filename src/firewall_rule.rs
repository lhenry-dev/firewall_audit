use struct_field_names_as_array::FieldNamesAsSlice;

use crate::error::{FirewallAuditError, Result};
use std::collections::HashSet;
use std::net::IpAddr;

pub mod linux;
pub mod windows;

/// Represents a firewall rule (cross-platform abstraction).
#[derive(Debug, Clone, FieldNamesAsSlice)]
pub struct FirewallRule {
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
    /// Application name (if any)
    pub application_name: Option<String>,
    /// Service name (if any)
    pub service_name: Option<String>,
    /// Protocol (if any)
    pub protocol: Option<String>,
    /// Local ports (if any)
    pub local_ports: Option<HashSet<u16>>,
    /// Remote ports (if any)
    pub remote_ports: Option<HashSet<u16>>,
    /// Local addresses (if any)
    pub local_addresses: Option<HashSet<IpAddr>>,
    /// Remote addresses (if any)
    pub remote_addresses: Option<HashSet<IpAddr>>,
    /// ICMP types and codes (if any)
    pub icmp_types_and_codes: Option<String>,
    /// Interfaces (if any)
    pub interfaces: Option<HashSet<String>>,
    /// Interface types (if any)
    pub interface_types: Option<HashSet<String>>,
    /// Grouping (if any)
    pub grouping: Option<String>,
    /// Profiles (if any)
    pub profiles: Option<String>,
    /// Edge traversal (if any)
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
    use super::{FirewallAuditError, FirewallRule, FirewallRuleProvider, Result};
    pub struct LinuxFirewallProvider;
    impl FirewallRuleProvider for LinuxFirewallProvider {
        fn list_rules() -> Result<Vec<FirewallRule>> {
            Err(FirewallAuditError::ValidationError(
                "Firewall rule listing is not implemented on Linux".to_string(),
            ))
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
