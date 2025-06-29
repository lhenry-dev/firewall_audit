use super::types::{CriteriaCondition, CriteriaExpr, CriteriaOperator};
use crate::firewall_rule::FirewallRule;
use ipnet::IpNet;
use regex::Regex;
use serde_yaml::Value;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

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
    let mut cond = cond.clone();
    cond.parse_operator();
    let op = match &cond.operator {
        Some(op) => op,
        None => {
            return false;
        }
    };
    let field_val = get_field_value(rule, &cond.field);
    match op {
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
        CriteriaOperator::Matches => match (field_val.as_ref(), cond.value.as_ref()) {
            (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) => {
                seq.iter().any(|v| list.iter().any(|item| v == item))
            }
            (Some(Value::Sequence(seq)), Some(val)) => seq.iter().any(|v| v == val),
            (Some(val), Some(Value::Sequence(list))) => list.iter().any(|item| val == item),
            (Some(val), Some(expected)) => val == expected,
            _ => false,
        },
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
            } else {
                false
            }
        }
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
                (Some(l), Some(r)) => match op {
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
        CriteriaOperator::IsNull => value_is_null(&field_val),
        CriteriaOperator::ApplicationExists => {
            if let Some(Value::String(ref path)) = field_val {
                Path::new(path).exists()
            } else {
                false
            }
        }
        CriteriaOperator::ServiceExists => {
            if let Some(Value::String(ref service)) = field_val {
                #[cfg(target_os = "windows")]
                {
                    let output = Command::new("sc").arg("query").arg(service).output();
                    if let Ok(out) = output {
                        String::from_utf8_lossy(&out.stdout)
                            .to_ascii_lowercase()
                            .contains(&service.to_ascii_lowercase())
                    } else {
                        false
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    false
                }
            } else {
                false
            }
        }
        CriteriaOperator::Not => {
            if let (Some(Value::String(s)), Some(Value::String(expected))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                !s.eq_ignore_ascii_case(expected)
            } else if let (Some(Value::String(s)), Some(Value::Sequence(list))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                !list.iter().any(|v| match v {
                    Value::String(item) => s.eq_ignore_ascii_case(item),
                    Value::Number(n) => s == &n.to_string(),
                    _ => false,
                })
            } else if let (Some(Value::Sequence(seq)), Some(Value::String(expected))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                !seq.iter().any(|v| match v {
                    Value::String(item) => item.eq_ignore_ascii_case(expected),
                    Value::Number(n) => expected == &n.to_string(),
                    _ => false,
                })
            } else if let (Some(Value::Sequence(seq)), Some(Value::Number(expected))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                !seq.iter().any(|v| match v {
                    Value::Number(n) => n == expected,
                    Value::String(s) => s == &expected.to_string(),
                    _ => false,
                })
            } else if let (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) =
                (field_val.as_ref(), cond.value.as_ref())
            {
                !seq.iter().any(|v| list.contains(v))
            } else {
                field_val != cond.value
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
