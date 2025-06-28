use crate::error::{FirewallAuditError, Result};
use crate::firewall_rule::FirewallRule;
use crate::firewall_rule::FirewallRuleProvider;

pub struct LinuxFirewallProvider;

impl FirewallRuleProvider for LinuxFirewallProvider {
    fn list_rules() -> Result<Vec<FirewallRule>> {
        Err(FirewallAuditError::ValidationError(
            "Firewall rule listing is not implemented on Linux".to_string(),
        ))
    }
}
