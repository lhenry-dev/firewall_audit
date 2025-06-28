use firewall_audit::run_audit;
use std::collections::HashSet;
use std::net::IpAddr;
use windows_firewall::{
    ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows, WindowsFirewallRule,
    list_rules,
};

fn add_test_firewall_rules() {
    let mut rules = vec![];
    // Rule for equals
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-equals")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .description("Test equals")
            .build(),
    );
    // Rule for contains
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-contains-SSH")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .description("SSH access")
            .build(),
    );
    // Rule for regex
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-regex-SSH-01")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .description("Regex SSH")
            .build(),
    );
    // Rule for wildcard
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-wildcard-RDP-01")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .description("Wildcard RDP")
            .build(),
    );
    // Rule for matches (ports)
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-matches-port-22")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .local_ports([22].iter().cloned().collect::<HashSet<u16>>())
            .build(),
    );
    // Rule for in_range (ports)
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-inrange-port-1000")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .local_ports([1000].iter().cloned().collect::<HashSet<u16>>())
            .build(),
    );
    // Rule for gt/lt/lte/gte
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-gt-port-2000")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .local_ports([2001].iter().cloned().collect::<HashSet<u16>>())
            .build(),
    );
    // Rule for cidr
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-cidr-192.168.1.10")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Allow)
            .remote_addresses(
                ["192.168.1.10".parse::<IpAddr>().unwrap()]
                    .iter()
                    .cloned()
                    .collect::<HashSet<IpAddr>>(),
            )
            .build(),
    );
    // Rule for not
    rules.push(
        WindowsFirewallRule::builder()
            .name("AAA-firewallAuditTest-not-block")
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .action(ActionFirewallWindows::Block)
            .description("Should not match Allow")
            .build(),
    );
    // Add all rules
    for rule in rules {
        let _ = rule.add();
    }
}

fn remove_test_firewall_rules() {
    if let Ok(rules) = list_rules() {
        for rule in rules {
            if rule.name().starts_with("AAA-firewallAuditTest") {
                let _ = rule.remove();
            }
        }
    }
}

// #[test]
fn firewall_audit_end_to_end() {
    add_test_firewall_rules();
    // Afficher toutes les règles firewall présentes après ajout
    if let Ok(rules) = list_rules() {
        println!("\n--- Règles firewall présentes après ajout ---");
        for rule in rules {
            if rule.name().starts_with("AAA-firewallAuditTest") {
                println!(
                    "Nom: {} | Action: {:?} | Direction: {:?} | Enabled: {} | Desc: {:?} | LPorts: {:?} | RAddrs: {:?}",
                    rule.name(),
                    rule.action(),
                    rule.direction(),
                    rule.enabled(),
                    rule.description(),
                    rule.local_ports(),
                    rule.remote_addresses()
                );
            }
        }
        println!("--- Fin des règles firewall ---\n");
    }
    // Appeler la fonction d'audit principale et afficher la sortie complète
    let output = run_audit("rules_cursor.yaml");
    println!(
        "\n--- Sortie complète de l'audit ---\n{}\n--- Fin sortie audit ---\n",
        output
    );
    // Vérifier que chaque règle de test est bien présente dans la sortie
    let expected_rules = vec![
        "AAA-firewallAuditTest-equals",
        "AAA-firewallAuditTest-contains-SSH",
        "AAA-firewallAuditTest-regex-SSH-01",
        "AAA-firewallAuditTest-wildcard-RDP-01",
        "AAA-firewallAuditTest-matches-port-22",
        "AAA-firewallAuditTest-inrange-port-1000",
        "AAA-firewallAuditTest-gt-port-2000",
        "AAA-firewallAuditTest-cidr-192.168.1.10",
        "AAA-firewallAuditTest-not-block",
    ];
    for rule_name in expected_rules {
        assert!(
            output.contains(rule_name),
            "La règle '{}' devrait apparaître dans la sortie de l'audit",
            rule_name
        );
    }
    remove_test_firewall_rules();
}
