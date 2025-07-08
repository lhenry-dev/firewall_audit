use struct_field_names_as_array::FieldNamesAsSlice;

use crate::FirewallAuditError;
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

/// A trait for types that can provide firewall rules.
pub trait FirewallRuleProvider {
    /// Lists all firewall rules available from this provider.
    ///
    /// # Errors
    /// Returns an error if the firewall rules cannot be listed.
    fn list_rules() -> Result<Vec<FirewallRule>, FirewallAuditError>;
}

#[cfg(target_os = "windows")]
pub use crate::firewall_rule::windows::WindowsFirewallProvider as PlatformFirewallProvider;

#[cfg(target_os = "linux")]
pub use crate::firewall_rule::linux::LinuxFirewallProvider as PlatformFirewallProvider;

#[cfg(test)]
mod tests {
    use crate::FirewallRuleProvider;

    #[test]
    fn test_list_rules_compiles() {
        #[cfg(target_os = "windows")]
        {
            use crate::PlatformFirewallProvider;

            let rules = PlatformFirewallProvider::list_rules().unwrap();
            for rule in rules {
                println!("{rule:?}");
            }
        }
        #[cfg(target_os = "linux")]
        {
            use crate::firewall_rule::linux::LinuxFirewallProvider;

            let rules = LinuxFirewallProvider::list_rules().unwrap();
            for rule in rules {
                println!("{rule:?}");
            }
        }
    }
}
