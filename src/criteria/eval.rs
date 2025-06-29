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

fn value_is_null(val: Option<&Value>) -> bool {
    matches!(val, None | Some(Value::Null))
}

fn eval_equals(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(expected))) = (field_val, cond_val) {
        s.eq_ignore_ascii_case(expected)
    } else if let (Some(v), Some(expected)) = (field_val, cond_val) {
        v == expected
    } else {
        false
    }
}

fn eval_matches(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    match (field_val, cond_val) {
        (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) => {
            seq.iter().any(|v| list.iter().any(|item| v == item))
        }
        (Some(Value::Sequence(seq)), Some(val)) => seq.iter().any(|v| v == val),
        (Some(val), Some(Value::Sequence(list))) => list.iter().any(|item| val == item),
        (Some(val), Some(expected)) => val == expected,
        _ => false,
    }
}

fn eval_starts_with(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(prefix))) = (field_val, cond_val) {
        s.to_lowercase().starts_with(&prefix.to_lowercase())
    } else {
        false
    }
}

fn eval_ends_with(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(suffix))) = (field_val, cond_val) {
        s.to_lowercase().ends_with(&suffix.to_lowercase())
    } else {
        false
    }
}

fn eval_contains(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(substr))) = (field_val, cond_val) {
        s.to_lowercase().contains(&substr.to_lowercase())
    } else {
        false
    }
}

fn eval_regex(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(pattern))) = (field_val, cond_val) {
        Regex::new(pattern)
            .map(|re| re.is_match(s))
            .unwrap_or(false)
    } else {
        false
    }
}

fn eval_wildcard(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(pattern))) = (field_val, cond_val) {
        let mut regex_pattern = String::new();
        for c in pattern.chars() {
            match c {
                '*' => regex_pattern.push_str(".*"),
                '?' => regex_pattern.push('.'),
                _ => regex_pattern.push_str(&regex::escape(&c.to_string())),
            }
        }
        let regex_pattern = format!("^{regex_pattern}$");
        Regex::new(&regex_pattern)
            .map(|re| re.is_match(s))
            .unwrap_or(false)
    } else {
        false
    }
}

fn eval_in_range(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    match (field_val, cond_val) {
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
    }
}

fn eval_cmp(op: CriteriaOperator, field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    let (left, right) = match (field_val, cond_val) {
        (Some(Value::Number(n)), Some(Value::Number(expected))) => (n.as_f64(), expected.as_f64()),
        (Some(Value::String(s)), Some(Value::Number(expected))) => {
            (s.parse::<f64>().ok(), expected.as_f64())
        }
        (Some(Value::Number(n)), Some(Value::String(s))) => (n.as_f64(), s.parse::<f64>().ok()),
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

fn eval_cidr(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::Sequence(seq)), Some(Value::String(cidr))) = (field_val, cond_val) {
        cidr.parse::<IpNet>().is_ok_and(|ipnet| {
            seq.iter().any(|v| match v {
                Value::String(ipstr) => ipstr
                    .parse::<IpAddr>()
                    .map(|ip| ipnet.contains(&ip))
                    .unwrap_or(false),
                _ => false,
            })
        })
    } else if let (Some(Value::String(ipstr)), Some(Value::String(cidr))) = (field_val, cond_val) {
        if let (Ok(ip), Ok(ipnet)) = (ipstr.parse::<IpAddr>(), cidr.parse::<IpNet>()) {
            ipnet.contains(&ip)
        } else {
            false
        }
    } else {
        false
    }
}

fn eval_is_null(field_val: Option<&Value>) -> bool {
    value_is_null(field_val)
}

fn eval_application_exists(field_val: Option<&Value>) -> bool {
    if let Some(Value::String(ref path)) = field_val {
        Path::new(path).exists()
    } else {
        false
    }
}

fn eval_service_exists(field_val: Option<&Value>) -> bool {
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

fn eval_not(field_val: Option<&Value>, cond_val: Option<&Value>) -> bool {
    if let (Some(Value::String(s)), Some(Value::String(expected))) = (field_val, cond_val) {
        !s.eq_ignore_ascii_case(expected)
    } else if let (Some(Value::String(s)), Some(Value::Sequence(list))) = (field_val, cond_val) {
        !list.iter().any(|v| match v {
            Value::String(item) => s.eq_ignore_ascii_case(item),
            Value::Number(n) => s == &n.to_string(),
            _ => false,
        })
    } else if let (Some(Value::Sequence(seq)), Some(Value::String(expected))) =
        (field_val, cond_val)
    {
        !seq.iter().any(|v| match v {
            Value::String(item) => item.eq_ignore_ascii_case(expected),
            Value::Number(n) => expected == &n.to_string(),
            _ => false,
        })
    } else if let (Some(Value::Sequence(seq)), Some(Value::Number(expected))) =
        (field_val, cond_val)
    {
        !seq.iter().any(|v| match v {
            Value::Number(n) => n == expected,
            Value::String(s) => s == &expected.to_string(),
            _ => false,
        })
    } else if let (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) = (field_val, cond_val)
    {
        !seq.iter().any(|v| list.contains(v))
    } else {
        field_val != cond_val
    }
}

pub fn eval_condition(rule: &FirewallRule, cond: &CriteriaCondition) -> bool {
    let mut cond = cond.clone();
    cond.parse_operator();
    let Some(op) = &cond.operator else {
        return false;
    };
    let field_val = get_field_value(rule, &cond.field);
    match op {
        CriteriaOperator::Equals => eval_equals(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Matches => eval_matches(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::StartsWith => eval_starts_with(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::EndsWith => eval_ends_with(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Contains => eval_contains(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Regex => eval_regex(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Wildcard => eval_wildcard(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::InRange => eval_in_range(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Lt
        | CriteriaOperator::Lte
        | CriteriaOperator::Gt
        | CriteriaOperator::Gte => eval_cmp(*op, field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::Cidr => eval_cidr(field_val.as_ref(), cond.value.as_ref()),
        CriteriaOperator::IsNull => eval_is_null(field_val.as_ref()),
        CriteriaOperator::ApplicationExists => eval_application_exists(field_val.as_ref()),
        CriteriaOperator::ServiceExists => eval_service_exists(field_val.as_ref()),
        CriteriaOperator::Not => eval_not(field_val.as_ref(), cond.value.as_ref()),
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
