use crate::firewall_rule::FirewallRule;
use crate::firewall_rule::FirewallRuleProvider;

pub struct LinuxFirewallProvider;

impl FirewallRuleProvider for LinuxFirewallProvider {
    fn list_rules() -> Vec<FirewallRule> {
        eprintln!("Firewall rule listing is not implemented on Linux. Returning empty list.");
        vec![]
    }
}
