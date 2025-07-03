#[cfg(test)]
mod integration {
    use super::super::run::run_audit_multi_with_rules;
    use crate::criteria::{AuditRule, CriteriaCondition, CriteriaExpr};
    use crate::firewall_rule::FirewallRule;

    #[test]
    fn test_audit_match_on_name() {
        let fw_rules = vec![
            FirewallRule {
                name: "Allow SSH".to_string(),
                direction: "In".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: Some("SSH access".to_string()),
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("linux".to_string()),
            },
            FirewallRule {
                name: "Block Telnet".to_string(),
                direction: "In".to_string(),
                enabled: false,
                action: "Deny".to_string(),
                description: Some("Telnet blocked".to_string()),
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("linux".to_string()),
            },
        ];
        let audit_rules = vec![AuditRule {
            id: "ssh_rule".to_string(),
            description: "Detect SSH allow rule".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Allow SSH".to_string())),
                operator: None,
            }),
            severity: "high".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_rules(&audit_rules, &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, "ssh_rule");
        assert_eq!(audit.matched_firewall_rules, vec!["Allow SSH"]);
    }

    #[test]
    fn test_audit_no_match() {
        let fw_rules = vec![FirewallRule {
            name: "Allow HTTP".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: Some("HTTP access".to_string()),
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: Some("linux".to_string()),
        }];
        let audit_rules = vec![AuditRule {
            id: "no_match_rule".to_string(),
            description: "Should not match".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Block FTP".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_rules(&audit_rules, &fw_rules);
        assert!(results.is_empty());
    }

    #[test]
    fn test_audit_multiple_matches() {
        let fw_rules = vec![
            FirewallRule {
                name: "Allow SSH".to_string(),
                direction: "In".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: Some("SSH access".to_string()),
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("linux".to_string()),
            },
            FirewallRule {
                name: "Allow SSH".to_string(),
                direction: "Out".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: Some("SSH out".to_string()),
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("linux".to_string()),
            },
        ];
        let audit_rules = vec![AuditRule {
            id: "ssh_rule".to_string(),
            description: "Detect all SSH allow rules".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Allow SSH".to_string())),
                operator: None,
            }),
            severity: "medium".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_rules(&audit_rules, &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, "ssh_rule");
        assert_eq!(audit.matched_firewall_rules, vec!["Allow SSH", "Allow SSH"]);
    }

    fn fw_linux() -> FirewallRule {
        FirewallRule {
            name: "rule1".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: Some("linux".to_string()),
        }
    }
    fn fw_windows() -> FirewallRule {
        FirewallRule {
            name: "rule2".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: Some("windows".to_string()),
        }
    }
    fn fw_no_os() -> FirewallRule {
        FirewallRule {
            name: "rule3".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: None,
            application_name: None,
            service_name: None,
            protocol: None,
            local_ports: None,
            remote_ports: None,
            local_addresses: None,
            remote_addresses: None,
            icmp_types_and_codes: None,
            interfaces: None,
            interface_types: None,
            grouping: None,
            profiles: None,
            edge_traversal: None,
            os: None,
        }
    }

    #[test]
    fn test_os_filtering_linux_only() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_linux = AuditRule {
            id: "linux_only".to_string(),
            description: "Linux only".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_rules(&[audit_rule_linux.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_linux.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule1"]);
    }

    #[test]
    fn test_os_filtering_windows_only() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_windows = AuditRule {
            id: "windows_only".to_string(),
            description: "Windows only".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule2".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["windows".to_string()]),
        };
        let results = run_audit_multi_with_rules(&[audit_rule_windows.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_windows.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule2"]);
    }

    #[test]
    fn test_os_filtering_linux_and_windows() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_both = AuditRule {
            id: "both".to_string(),
            description: "Linux and Windows".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string(), "windows".to_string()]),
        };
        let results = run_audit_multi_with_rules(&[audit_rule_both.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_both.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule1"]); // rule2 is not in the name criteria
    }

    #[test]
    fn test_os_filtering_firewall_no_os() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_all = AuditRule {
            id: "all".to_string(),
            description: "All OS".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule3".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: None,
        };
        let results = run_audit_multi_with_rules(&[audit_rule_all.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_all.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule3"]);
    }

    #[test]
    fn test_parallel_vs_sequential_audit() {
        // Simulates a sequential vs parallel audit on a large list
        let fw_rules: Vec<FirewallRule> = (0..1000)
            .map(|i| FirewallRule {
                name: if i == 42 {
                    "TestRule".to_string()
                } else {
                    format!("Rule-{}", i)
                },
                direction: "In".to_string(),
                enabled: true,
                action: "Allow".to_string(),
                description: None,
                application_name: None,
                service_name: None,
                protocol: None,
                local_ports: None,
                remote_ports: None,
                local_addresses: None,
                remote_addresses: None,
                icmp_types_and_codes: None,
                interfaces: None,
                interface_types: None,
                grouping: None,
                profiles: None,
                edge_traversal: None,
                os: Some("windows".to_string()),
            })
            .collect();
        let audit_rule = AuditRule {
            id: "test_parallel".to_string(),
            description: "test".to_string(),
            criterias: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("TestRule".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["windows".to_string()]),
        };
        // Sequential
        let mut matches_seq = Vec::new();
        for fw_rule in &fw_rules {
            if crate::criteria::eval::eval_criterias(fw_rule, &audit_rule.criterias) {
                matches_seq.push(fw_rule.name.clone());
            }
        }
        // Parallel (via run_audit_multi_with_rules)
        let results = run_audit_multi_with_rules(&[audit_rule.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let matches_par = &results[0].matched_firewall_rules;
        assert_eq!(matches_seq, *matches_par);
    }
}
