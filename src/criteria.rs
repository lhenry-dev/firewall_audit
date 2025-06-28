use crate::rule::FirewallRule;
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
pub struct AuditRule {
    pub id: String,
    pub description: String,
    pub criterias: CriteriaExpr,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriteriaOperator {
    Equals,
    StartsWith,
    EndsWith,
    Contains,
    Matches,
    InRange,
    IsNull,
    Regex,
    Wildcard,
    Lt,
    Lte,
    Gt,
    Gte,
    Cidr,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CriteriaExpr {
    Group { and: Vec<CriteriaExpr> },
    OrGroup { or: Vec<CriteriaExpr> },
    NotGroup { not: Box<CriteriaExpr> },
    Condition(CriteriaCondition),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CriteriaCondition {
    pub field: String,
    pub operator: CriteriaOperator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

pub fn get_field_value(rule: &FirewallRule, field: &str) -> Option<Value> {
    match field {
        "name" => Some(Value::String(rule.name.clone())),
        "direction" => Some(Value::String(rule.direction.clone())),
        "enabled" => Some(Value::Bool(rule.enabled)),
        "action" => Some(Value::String(rule.action.clone())),
        "description" => rule.description.clone().map(Value::String),
        "application_name" => rule.application_name.clone().map(Value::String),
        "service_name" => rule.service_name.clone().map(Value::String),
        "protocol" => rule.protocol.clone().map(Value::String),
        "local_ports" => rule.local_ports.as_ref().map(|set| {
            Value::Sequence(
                set.iter()
                    .map(|p| Value::Number(serde_yaml::Number::from(*p)))
                    .collect(),
            )
        }),
        "remote_ports" => rule.remote_ports.as_ref().map(|set| {
            Value::Sequence(
                set.iter()
                    .map(|p| Value::Number(serde_yaml::Number::from(*p)))
                    .collect(),
            )
        }),
        "local_addresses" => rule.local_addresses.as_ref().map(|set| {
            Value::Sequence(set.iter().map(|ip| Value::String(ip.to_string())).collect())
        }),
        "remote_addresses" => rule.remote_addresses.as_ref().map(|set| {
            Value::Sequence(set.iter().map(|ip| Value::String(ip.to_string())).collect())
        }),
        "icmp_types_and_codes" => rule.icmp_types_and_codes.clone().map(Value::String),
        "interfaces" => rule.interfaces.as_ref().map(|set| {
            Value::Sequence(
                set.iter()
                    .map(|iface| Value::String(iface.clone()))
                    .collect(),
            )
        }),
        "interface_types" => rule
            .interface_types
            .as_ref()
            .map(|set| Value::Sequence(set.iter().map(|t| Value::String(t.clone())).collect())),
        "grouping" => rule.grouping.clone().map(Value::String),
        "profiles" => rule.profiles.clone().map(Value::String),
        "edge_traversal" => rule.edge_traversal.map(Value::Bool),
        _ => None,
    }
}

fn value_is_null(val: &Option<Value>) -> bool {
    matches!(val, None | Some(Value::Null))
}

pub fn eval_condition(rule: &FirewallRule, cond: &CriteriaCondition) -> bool {
    let field_val = get_field_value(rule, &cond.field);
    match cond.operator {
        CriteriaOperator::Equals => {
            if let (Some(Value::String(s)), Some(Value::String(expected))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                s.eq_ignore_ascii_case(expected)
            } else if let (Some(v), Some(expected)) = (field_val.as_ref(), cond.value.as_ref()) {
                v == expected
            } else {
                false
            }
        }
        CriteriaOperator::StartsWith => {
            if let (Some(Value::String(s)), Some(Value::String(prefix))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                s.to_lowercase().starts_with(&prefix.to_lowercase())
            } else {
                false
            }
        }
        CriteriaOperator::EndsWith => {
            if let (Some(Value::String(s)), Some(Value::String(suffix))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                s.to_lowercase().ends_with(&suffix.to_lowercase())
            } else {
                false
            }
        }
        CriteriaOperator::Contains => {
            if let (Some(Value::String(s)), Some(Value::String(substr))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                s.to_lowercase().contains(&substr.to_lowercase())
            } else if let (Some(Value::Sequence(seq)), Some(expected)) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                seq.iter().any(|v| match (v, expected) {
                    (Value::String(a), Value::String(b)) => a.eq_ignore_ascii_case(b),
                    _ => v == expected,
                })
            } else {
                false
            }
        }
        CriteriaOperator::Matches => match (field_val.as_ref(), cond.value.as_ref()) {
            (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) => {
                seq.iter().any(|v| list.iter().any(|port| v == port))
            }
            (Some(Value::Sequence(seq)), Some(Value::Number(port))) => {
                let port = port.as_u64().unwrap_or(0);
                seq.iter().any(|v| match v {
                    Value::Number(n) => n.as_u64().unwrap_or(0) == port,
                    _ => false,
                })
            }
            _ => false,
        },
        CriteriaOperator::InRange => match (field_val.as_ref(), cond.value.as_ref()) {
            (Some(Value::Sequence(seq)), Some(Value::Sequence(range))) if range.len() == 2 => {
                if let (Some(Value::Number(start)), Some(Value::Number(end))) =
                    (range.first(), range.get(1))
                {
                    let start = start.as_u64().unwrap_or(0);
                    let end = end.as_u64().unwrap_or(0);
                    seq.iter().any(|v| match v {
                        Value::Number(n) => {
                            let val = n.as_u64().unwrap_or(0);
                            val >= start && val <= end
                        }
                        _ => false,
                    })
                } else {
                    false
                }
            }
            _ => false,
        },
        CriteriaOperator::IsNull => value_is_null(&field_val),
        CriteriaOperator::Regex => {
            if let (Some(Value::String(s)), Some(Value::String(pattern))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                Regex::new(pattern)
                    .map(|re| re.is_match(s))
                    .unwrap_or(false)
            } else {
                false
            }
        }
        CriteriaOperator::Wildcard => {
            if let (Some(Value::String(s)), Some(Value::String(pattern))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                let mut regex_pattern = String::new();
                let chars = pattern.chars().peekable();
                for c in chars {
                    match c {
                        '*' => regex_pattern.push_str(".*"),
                        '?' => regex_pattern.push('.'),
                        _ => regex_pattern.push_str(&regex::escape(&c.to_string())),
                    }
                }
                let regex_pattern = format!("^{}$", regex_pattern);
                Regex::new(&regex_pattern)
                    .map(|re| re.is_match(s))
                    .unwrap_or(false)
            } else {
                false
            }
        }
        CriteriaOperator::Lt
        | CriteriaOperator::Lte
        | CriteriaOperator::Gt
        | CriteriaOperator::Gte => {
            let (left, right) = match (field_val.as_ref(), cond.value.as_ref()) {
                (Some(Value::Number(n)), Some(Value::Number(expected))) => {
                    (n.as_f64(), expected.as_f64())
                }
                (Some(Value::String(s)), Some(Value::Number(expected))) => {
                    (s.parse::<f64>().ok(), expected.as_f64())
                }
                (Some(Value::Number(n)), Some(Value::String(s))) => {
                    (n.as_f64(), s.parse::<f64>().ok())
                }
                (Some(Value::String(s1)), Some(Value::String(s2))) => {
                    (s1.parse::<f64>().ok(), s2.parse::<f64>().ok())
                }
                _ => (None, None),
            };
            match (left, right) {
                (Some(l), Some(r)) => match cond.operator {
                    CriteriaOperator::Lt => l < r,
                    CriteriaOperator::Lte => l <= r,
                    CriteriaOperator::Gt => l > r,
                    CriteriaOperator::Gte => l >= r,
                    _ => false,
                },
                _ => false,
            }
        }
        CriteriaOperator::Cidr => {
            if let (Some(Value::Sequence(seq)), Some(Value::String(cidr))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                if let Ok(ipnet) = cidr.parse::<IpNet>() {
                    seq.iter().any(|v| match v {
                        Value::String(ipstr) => ipstr
                            .parse::<IpAddr>()
                            .map(|ip| ipnet.contains(&ip))
                            .unwrap_or(false),
                        _ => false,
                    })
                } else {
                    false
                }
            } else if let (Some(Value::String(ipstr)), Some(Value::String(cidr))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                if let (Ok(ip), Ok(ipnet)) = (ipstr.parse::<IpAddr>(), cidr.parse::<IpNet>()) {
                    ipnet.contains(&ip)
                } else {
                    false
                }
            } else {
                false
            }
        }
    }
}

pub fn eval_criterias(rule: &FirewallRule, expr: &CriteriaExpr) -> bool {
    match expr {
        CriteriaExpr::Group { and } => and.iter().all(|c| eval_criterias(rule, c)),
        CriteriaExpr::OrGroup { or } => or.iter().any(|c| eval_criterias(rule, c)),
        CriteriaExpr::NotGroup { not } => !eval_criterias(rule, not),
        CriteriaExpr::Condition(cond) => eval_condition(rule, cond),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::FirewallRule;
    use serde_yaml::Value;
    use std::collections::HashSet;
    use std::net::IpAddr;

    fn dummy_rule() -> FirewallRule {
        let mut ports = HashSet::new();
        ports.insert(22);
        ports.insert(80);
        let mut addrs = HashSet::new();
        addrs.insert("127.0.0.1".parse::<IpAddr>().unwrap());
        addrs.insert("192.168.1.10".parse::<IpAddr>().unwrap());
        FirewallRule {
            name: "TestRule".to_string(),
            direction: "In".to_string(),
            enabled: true,
            action: "Allow".to_string(),
            description: Some("desc Windows SSH".to_string()),
            application_name: None,
            service_name: Some("Dhcp".to_string()),
            protocol: Some("Tcp".to_string()),
            local_ports: Some(ports),
            remote_ports: Some([53u16].iter().cloned().collect()),
            local_addresses: Some(addrs.clone()),
            remote_addresses: Some(addrs),
            icmp_types_and_codes: Some("8".to_string()),
            interfaces: Some(["Wi-Fi".to_string()].iter().cloned().collect()),
            interface_types: Some(["Lan".to_string()].iter().cloned().collect()),
            grouping: Some("File and Printer Sharing".to_string()),
            profiles: Some("Domain".to_string()),
            edge_traversal: Some(true),
        }
    }

    #[test]
    fn test_equals_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::Equals,
            value: Some(Value::String("TestRule".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::Equals,
            value: Some(Value::String("testrule".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::Equals,
            value: Some(Value::String("Other".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_startswith_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::StartsWith,
            value: Some(Value::String("Test".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::StartsWith,
            value: Some(Value::String("test".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::StartsWith,
            value: Some(Value::String("Rule".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_endswith_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::EndsWith,
            value: Some(Value::String("Rule".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::EndsWith,
            value: Some(Value::String("rule".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator: CriteriaOperator::EndsWith,
            value: Some(Value::String("Test".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_contains_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Contains,
            value: Some(Value::String("Windows".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Contains,
            value: Some(Value::String("ssh".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Contains,
            value: Some(Value::String("nope".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_matches_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::Matches,
            value: Some(Value::Number(22.into())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::Matches,
            value: Some(Value::Sequence(vec![
                Value::Number(22.into()),
                Value::Number(80.into()),
            ])),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::Matches,
            value: Some(Value::Number(443.into())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_inrange_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::InRange,
            value: Some(Value::Sequence(vec![
                Value::Number(20.into()),
                Value::Number(22.into()),
            ])),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::InRange,
            value: Some(Value::Sequence(vec![
                Value::Number(23.into()),
                Value::Number(80.into()),
            ])),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator: CriteriaOperator::InRange,
            value: Some(Value::Sequence(vec![
                Value::Number(100.into()),
                Value::Number(200.into()),
            ])),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_isnull_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "application_name".to_string(),
            operator: CriteriaOperator::IsNull,
            value: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "service_name".to_string(),
            operator: CriteriaOperator::IsNull,
            value: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_regex_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Regex,
            value: Some(Value::String("Win.*SSH".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Regex,
            value: Some(Value::String("^desc$".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_wildcard_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Wildcard,
            value: Some(Value::String("*Windows*SSH*".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Wildcard,
            value: Some(Value::String("desc*".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "description".to_string(),
            operator: CriteriaOperator::Wildcard,
            value: Some(Value::String("nope*".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_lt_lte_gt_gte_operators() {
        let rule = dummy_rule();
        let cond_lt = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator: CriteriaOperator::Lt,
            value: Some(Value::Number(10.into())),
        };
        assert!(super::eval_condition(&rule, &cond_lt));
        let cond_lte = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator: CriteriaOperator::Lte,
            value: Some(Value::Number(8.into())),
        };
        assert!(super::eval_condition(&rule, &cond_lte));
        let cond_gt = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator: CriteriaOperator::Gt,
            value: Some(Value::Number(7.into())),
        };
        assert!(super::eval_condition(&rule, &cond_gt));
        let cond_gte = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator: CriteriaOperator::Gte,
            value: Some(Value::Number(8.into())),
        };
        assert!(super::eval_condition(&rule, &cond_gte));
        let cond_fail = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator: CriteriaOperator::Lt,
            value: Some(Value::Number(5.into())),
        };
        assert!(!super::eval_condition(&rule, &cond_fail));
    }

    #[test]
    fn test_cidr_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_addresses".to_string(),
            operator: CriteriaOperator::Cidr,
            value: Some(Value::String("127.0.0.0/8".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "remote_addresses".to_string(),
            operator: CriteriaOperator::Cidr,
            value: Some(Value::String("192.168.0.0/16".to_string())),
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "remote_addresses".to_string(),
            operator: CriteriaOperator::Cidr,
            value: Some(Value::String("10.0.0.0/8".to_string())),
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_and_or_not_groups() {
        let rule = dummy_rule();
        let expr_and = CriteriaExpr::Group {
            and: vec![
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "name".to_string(),
                    operator: CriteriaOperator::Contains,
                    value: Some(Value::String("Test".to_string())),
                }),
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "action".to_string(),
                    operator: CriteriaOperator::Equals,
                    value: Some(Value::String("Allow".to_string())),
                }),
            ],
        };
        assert!(super::eval_criterias(&rule, &expr_and));
        let expr_or = CriteriaExpr::OrGroup {
            or: vec![
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "name".to_string(),
                    operator: CriteriaOperator::Equals,
                    value: Some(Value::String("Nope".to_string())),
                }),
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "action".to_string(),
                    operator: CriteriaOperator::Equals,
                    value: Some(Value::String("Allow".to_string())),
                }),
            ],
        };
        assert!(super::eval_criterias(&rule, &expr_or));
        let expr_not = CriteriaExpr::NotGroup {
            not: Box::new(CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator: CriteriaOperator::Equals,
                value: Some(Value::String("Nope".to_string())),
            })),
        };
        assert!(super::eval_criterias(&rule, &expr_not));
        let expr_not_fail = CriteriaExpr::NotGroup {
            not: Box::new(CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator: CriteriaOperator::Equals,
                value: Some(Value::String("TestRule".to_string())),
            })),
        };
        assert!(!super::eval_criterias(&rule, &expr_not_fail));
    }

    #[test]
    fn test_chained_and_groups() {
        let rule = dummy_rule();
        let expr = CriteriaExpr::Group {
            and: vec![
                CriteriaExpr::Group {
                    and: vec![
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "name".to_string(),
                            operator: CriteriaOperator::Contains,
                            value: Some(Value::String("Test".to_string())),
                        }),
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "action".to_string(),
                            operator: CriteriaOperator::Equals,
                            value: Some(Value::String("Allow".to_string())),
                        }),
                    ],
                },
                CriteriaExpr::Group {
                    and: vec![CriteriaExpr::Condition(CriteriaCondition {
                        field: "protocol".to_string(),
                        operator: CriteriaOperator::Equals,
                        value: Some(Value::String("Tcp".to_string())),
                    })],
                },
            ],
        };
        assert!(super::eval_criterias(&rule, &expr));
        // Test négatif : une des sous-groupes échoue
        let expr_fail = CriteriaExpr::Group {
            and: vec![
                CriteriaExpr::Group {
                    and: vec![
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "name".to_string(),
                            operator: CriteriaOperator::Contains,
                            value: Some(Value::String("Nope".to_string())),
                        }),
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "action".to_string(),
                            operator: CriteriaOperator::Equals,
                            value: Some(Value::String("Allow".to_string())),
                        }),
                    ],
                },
                CriteriaExpr::Group {
                    and: vec![CriteriaExpr::Condition(CriteriaCondition {
                        field: "protocol".to_string(),
                        operator: CriteriaOperator::Equals,
                        value: Some(Value::String("Tcp".to_string())),
                    })],
                },
            ],
        };
        assert!(!super::eval_criterias(&rule, &expr_fail));
    }
}
