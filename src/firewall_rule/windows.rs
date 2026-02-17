use std::collections::HashSet;
use std::net::IpAddr;

use windows_firewall::Address;
use windows_firewall::Port;
use windows_firewall::PortKeyword;

use crate::firewall_rule::FirewallRule;
use crate::firewall_rule::FirewallRuleError;
use crate::firewall_rule::FirewallRuleProvider;

/// Windows implementation of the firewall rule provider.
#[derive(Debug)]
pub struct WindowsFirewallProvider;

impl FirewallRuleProvider for WindowsFirewallProvider {
    fn list_rules() -> Result<Vec<FirewallRule>, FirewallRuleError> {
        windows_firewall::list_rules()
            .map(|rules| rules.iter().map(FirewallRule::from).collect())
            .map_err(|e| FirewallRuleError::WindowsFirewallError(e.to_string()))
    }
}

impl From<&windows_firewall::FirewallRule> for FirewallRule {
    fn from(rule: &windows_firewall::FirewallRule) -> Self {
        Self {
            os: Some("windows".to_string()),
            name: rule.name().to_string(),
            direction: format!("{:?}", rule.direction()),
            enabled: *rule.enabled(),
            action: format!("{:?}", rule.action()),
            description: rule.description().as_deref().map(ToString::to_string),
            application_name: rule.application_name().as_deref().map(ToString::to_string),
            service_name: rule.service_name().as_deref().map(ToString::to_string),
            protocol: rule.protocol().map(|p| format!("{p:?}")),
            local_ports: windows_ports_to_unit_list(rule.local_ports()),
            remote_ports: windows_ports_to_unit_list(rule.remote_ports()),
            local_addresses: windows_addresses_to_unit_list(rule.local_addresses()),
            remote_addresses: windows_addresses_to_unit_list(rule.remote_addresses()),
            icmp_types_and_codes: rule
                .icmp_types_and_codes()
                .as_deref()
                .map(ToString::to_string),
            interfaces: rule.interfaces().clone(),
            interface_types: rule
                .interface_types()
                .clone()
                .map(|set| set.iter().map(|i| format!("{i:?}")).collect()),
            grouping: rule.grouping().as_deref().map(ToString::to_string),
            profiles: rule.profiles().map(|p| format!("{p:?}")),
            edge_traversal: *rule.edge_traversal(),
        }
    }
}

pub fn windows_ports_to_unit_list(ports: &Option<HashSet<Port>>) -> Option<HashSet<u16>> {
    let mut result = HashSet::new();

    if let Some(set) = ports {
        for port in set {
            match port {
                Port::Any => return None,
                Port::Port(p) => {
                    result.insert(*p);
                }
                Port::Range(_r) => {}
                Port::Keyword(k) => match k {
                    PortKeyword::Rpc => {}
                    PortKeyword::RpcEpmap => {
                        result.insert(135);
                    }
                    PortKeyword::IpHttps => {
                        result.insert(443);
                    }
                    PortKeyword::Ply2Disc => {
                        result.insert(1900);
                    }
                    PortKeyword::Teredo => {
                        result.insert(3544);
                    }
                },
            }
        }
    }

    Some(result)
}

pub fn windows_addresses_to_unit_list(
    addresses: &Option<HashSet<Address>>,
) -> Option<HashSet<IpAddr>> {
    let mut result = HashSet::new();

    if let Some(set) = addresses {
        for addr in set {
            match addr {
                Address::Any => return None,
                Address::Ip(ip) => {
                    result.insert(*ip);
                }
                Address::Cidr(_net) => {}
                Address::Range(_range) => {}
                Address::Keyword(_) => {}
            }
        }
    }

    Some(result)
}
