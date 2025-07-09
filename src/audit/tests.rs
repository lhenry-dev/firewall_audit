#[cfg(test)]
mod audit {
    use super::super::run::run_audit_multi_with_criteria;
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Allow SSH".to_string())),
                operator: None,
            }),
            severity: "high".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_criteria(&audit_rules, &fw_rules);
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Block FTP".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_criteria(&audit_rules, &fw_rules);
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("Allow SSH".to_string())),
                operator: None,
            }),
            severity: "medium".to_string(),
            os: Some(vec!["linux".to_string()]),
        }];
        let results = run_audit_multi_with_criteria(&audit_rules, &fw_rules);
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule_linux.clone()], &fw_rules);
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule2".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["windows".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule_windows.clone()], &fw_rules);
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
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule1".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string(), "windows".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule_both.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_both.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule1"]);
    }

    #[test]
    fn test_os_filtering_firewall_no_os() {
        let fw_rules = vec![fw_linux(), fw_windows(), fw_no_os()];
        let audit_rule_all = AuditRule {
            id: "all".to_string(),
            description: "All OS".to_string(),
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("rule3".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: None,
        };
        let results = run_audit_multi_with_criteria(&[audit_rule_all.clone()], &fw_rules);
        assert_eq!(results.len(), 1);
        let audit = &results[0];
        assert_eq!(audit.rule_id, audit_rule_all.id);
        assert_eq!(audit.matched_firewall_rules, vec!["rule3"]);
    }

    #[test]
    fn test_match_on_all_fields_and_operators() {
        use crate::criteria::types::CriteriaExpr;
        let fw_rule = FirewallRule {
            name: "TestRule".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: Some("desc".to_string()),
            application_name: Some("app.exe".to_string()),
            service_name: Some("svc".to_string()),
            protocol: Some("TCP".to_string()),
            local_ports: Some(std::iter::once(&22).copied().collect()),
            remote_ports: Some(std::iter::once(&443).copied().collect()),
            local_addresses: Some(std::iter::once("127.0.0.1".parse().unwrap()).collect()),
            remote_addresses: Some(std::iter::once("0.0.0.0".parse().unwrap()).collect()),
            icmp_types_and_codes: Some("8:0".to_string()),
            interfaces: Some(std::iter::once("eth0".to_string()).collect()),
            interface_types: Some(std::iter::once("lan".to_string()).collect()),
            grouping: Some("grp".to_string()),
            profiles: Some("Domain".to_string()),
            edge_traversal: Some(false),
            os: Some("linux".to_string()),
        };
        let tests = vec![
            (
                "name",
                "equals",
                serde_yaml::Value::String("TestRule".to_string()),
                true,
            ),
            (
                "name",
                "not",
                serde_yaml::Value::String("Other".to_string()),
                true,
            ),
            (
                "name",
                "matches",
                serde_yaml::Value::String("TestRule".to_string()),
                true,
            ),
            (
                "name",
                "contains",
                serde_yaml::Value::String("Test".to_string()),
                true,
            ),
            (
                "protocol",
                "equals",
                serde_yaml::Value::String("TCP".to_string()),
                true,
            ),
            (
                "local_ports",
                "matches",
                serde_yaml::Value::Number(22.into()),
                true,
            ),
            (
                "local_ports",
                "in_range",
                serde_yaml::Value::Sequence(vec![
                    serde_yaml::Value::Number(20.into()),
                    serde_yaml::Value::Number(80.into()),
                ]),
                true,
            ),
            ("description", "is_null", serde_yaml::Value::Null, false),
            (
                "application_name",
                "equals",
                serde_yaml::Value::String("app.exe".to_string()),
                true,
            ),
            (
                "service_name",
                "equals",
                serde_yaml::Value::String("svc".to_string()),
                true,
            ),
            (
                "remote_addresses",
                "contains",
                serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("0.0.0.0".to_string())]),
                true,
            ),
            (
                "grouping",
                "wildcard",
                serde_yaml::Value::String("gr*".to_string()),
                true,
            ),
            (
                "name",
                "regex",
                serde_yaml::Value::String("Test.*".to_string()),
                true,
            ),
        ];
        for (field, op, val, should_match) in tests {
            let expr = CriteriaExpr::Condition(CriteriaCondition {
                field: field.to_string(),
                operator_raw: op.to_string(),
                value: Some(val.clone()),
                operator: None,
            });
            let audit_rule = AuditRule {
                id: format!("{field}_{op}_test"),
                description: "desc".to_string(),
                criteria: expr,
                severity: "info".to_string(),
                os: Some(vec!["linux".to_string()]),
            };
            let results = run_audit_multi_with_criteria(&[audit_rule], &[fw_rule.clone()]);
            if should_match {
                assert_eq!(results.len(), 1, "Should match for {field} {op}");
            } else {
                assert!(results.is_empty(), "Should not match for {field} {op}");
            }
        }
    }

    #[test]
    fn test_os_filtering_case_insensitive_and_none() {
        let fw_rule = FirewallRule {
            name: "TestRule".to_string(),
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
            os: Some("LINUX".to_string()),
        };
        let audit_rule = AuditRule {
            id: "os_case_test".to_string(),
            description: "desc".to_string(),
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("TestRule".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule.clone()], &[fw_rule.clone()]);
        assert_eq!(results.len(), 1);
        let audit_rule_none = AuditRule {
            os: None,
            ..audit_rule
        };
        let results = run_audit_multi_with_criteria(&[audit_rule_none], &[fw_rule]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_criteria_group_and_or_not() {
        let fw_rule = FirewallRule {
            name: "RuleA".to_string(),
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
        };

        let expr = CriteriaExpr::Group {
            and: vec![
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "name".to_string(),
                    operator_raw: "equals".to_string(),
                    value: Some(serde_yaml::Value::String("RuleA".to_string())),
                    operator: None,
                }),
                CriteriaExpr::NotGroup {
                    not: Box::new(CriteriaExpr::Condition(CriteriaCondition {
                        field: "direction".to_string(),
                        operator_raw: "equals".to_string(),
                        value: Some(serde_yaml::Value::String("Out".to_string())),
                        operator: None,
                    })),
                },
            ],
        };
        let audit_rule = AuditRule {
            id: "group_and_not".to_string(),
            description: "desc".to_string(),
            criteria: expr,
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule], &[fw_rule]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_missing_fields_and_nulls() {
        let fw_rule = FirewallRule {
            name: "TestRule".to_string(),
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
        };
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "is_null".to_string(),
            value: None,
            operator: None,
        });
        let audit_rule = AuditRule {
            id: "null_desc".to_string(),
            description: "desc".to_string(),
            criteria: expr,
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule], &[fw_rule]);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_multiple_criteria_and_overlap() {
        let fw_rule = FirewallRule {
            name: "RuleX".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: Some("desc".to_string()),
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
        };
        let audit_rule1 = AuditRule {
            id: "crit1".to_string(),
            description: "desc1".to_string(),
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("RuleX".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let audit_rule2 = AuditRule {
            id: "crit2".to_string(),
            description: "desc2".to_string(),
            criteria: CriteriaExpr::Condition(CriteriaCondition {
                field: "description".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(serde_yaml::Value::String("desc".to_string())),
                operator: None,
            }),
            severity: "info".to_string(),
            os: Some(vec!["linux".to_string()]),
        };
        let results = run_audit_multi_with_criteria(&[audit_rule1, audit_rule2], &[fw_rule]);
        assert_eq!(results.len(), 2);
    }
}
