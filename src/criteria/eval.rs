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
        "os" => Some(Value::String(rule.os.clone()?)),
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
    // String contains string (default case)
    if let (Some(Value::String(s)), Some(Value::String(substr))) = (field_val, cond_val) {
        s.to_lowercase().contains(&substr.to_lowercase())
    // Sequence contains string or sequence
    } else if let (Some(Value::Sequence(seq)), Some(Value::String(item))) = (field_val, cond_val) {
        // Try IP address comparison if possible
        item.parse::<std::net::IpAddr>().map_or_else(
            |_| cond_val.is_some_and(|cond_val| seq.iter().any(|v| v == cond_val)),
            |ip_item| {
                seq.iter().any(|v| match v {
                    Value::String(s) => s
                        .parse::<std::net::IpAddr>()
                        .map(|ip| ip == ip_item)
                        .unwrap_or(false),
                    _ => false,
                })
            },
        )
    } else if let (Some(Value::Sequence(seq)), Some(Value::Sequence(list))) = (field_val, cond_val)
    {
        // Try IP address comparison for all items
        seq.iter().any(|v| {
            list.iter().any(|item| match (v, item) {
                (Value::String(s1), Value::String(s2)) => {
                    if let (Ok(ip1), Ok(ip2)) = (
                        s1.parse::<std::net::IpAddr>(),
                        s2.parse::<std::net::IpAddr>(),
                    ) {
                        ip1 == ip2
                    } else {
                        s1 == s2
                    }
                }
                _ => v == item,
            })
        })
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
    matches!(field_val, None | Some(Value::Null))
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
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .arg("status")
                .arg(service)
                .output();
            if let Ok(out) = output {
                out.status.success()
            } else {
                false
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
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

pub fn eval_criteria(rule: &FirewallRule, expr: &CriteriaExpr) -> bool {
    match expr {
        CriteriaExpr::Group { and } => and.iter().all(|c| eval_criteria(rule, c)),
        CriteriaExpr::OrGroup { or } => or.iter().any(|c| eval_criteria(rule, c)),
        CriteriaExpr::NotGroup { not } => !eval_criteria(rule, not),
        CriteriaExpr::Condition(cond) => eval_condition(rule, cond),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        criteria::eval::{
            eval_cmp, eval_contains, eval_ends_with, eval_equals, eval_in_range, eval_is_null,
            eval_matches, eval_regex, eval_starts_with, eval_wildcard, get_field_value,
        },
        CriteriaOperator, FirewallRule,
    };
    use serde_yaml::Value;
    #[test]
    fn test_get_field_value_all_fields() {
        let rule = FirewallRule {
            name: "n".into(),
            direction: "d".into(),
            enabled: true,
            action: "a".into(),
            description: Some("desc".into()),
            application_name: Some("app".into()),
            service_name: Some("svc".into()),
            protocol: Some("TCP".into()),
            local_ports: Some(std::iter::once(&1u16).copied().collect()),
            remote_ports: Some(std::iter::once(&2u16).copied().collect()),
            local_addresses: Some(std::iter::once("127.0.0.1".parse().unwrap()).collect()),
            remote_addresses: Some(std::iter::once("0.0.0.0".parse().unwrap()).collect()),
            icmp_types_and_codes: Some("8:0".into()),
            interfaces: Some(std::iter::once("eth0".to_string()).collect()),
            interface_types: Some(std::iter::once("lan".to_string()).collect()),
            grouping: Some("grp".into()),
            profiles: Some("Domain".into()),
            edge_traversal: Some(false),
            os: Some("linux".into()),
        };
        let fields = FirewallRule::valid_fields();
        for f in fields {
            let v = get_field_value(&rule, f);
            assert!(v.is_some(), "field {f} should be Some");
        }
        assert!(get_field_value(&rule, "notafield").is_none());
    }
    #[test]
    fn test_eval_equals() {
        assert!(eval_equals(
            Some(&Value::String("foo".to_string())),
            Some(&Value::String("foo".to_string()))
        ));
        assert!(!eval_equals(
            Some(&Value::String("foo".to_string())),
            Some(&Value::String("bar".to_string()))
        ));
    }
    #[test]
    fn test_eval_matches() {
        let seq = Value::Sequence(vec![Value::Number(22.into()), Value::Number(80.into())]);
        assert!(eval_matches(Some(&seq), Some(&Value::Number(22.into()))));
        assert!(!eval_matches(Some(&seq), Some(&Value::Number(23.into()))));
    }
    #[test]
    fn test_eval_starts_ends_contains() {
        assert!(eval_starts_with(
            Some(&Value::String("foobar".to_string())),
            Some(&Value::String("foo".to_string()))
        ));
        assert!(eval_ends_with(
            Some(&Value::String("foobar".to_string())),
            Some(&Value::String("bar".to_string()))
        ));
        assert!(eval_contains(
            Some(&Value::String("foobar".to_string())),
            Some(&Value::String("oba".to_string()))
        ));
    }
    #[test]
    fn test_eval_regex_wildcard() {
        assert!(eval_regex(
            Some(&Value::String("abc123".to_string())),
            Some(&Value::String("abc.*".to_string()))
        ));
        assert!(eval_wildcard(
            Some(&Value::String("file.txt".to_string())),
            Some(&Value::String("*.txt".to_string()))
        ));
    }
    #[test]
    fn test_eval_in_range_cmp() {
        let seq = Value::Sequence(vec![Value::Number(22.into()), Value::Number(80.into())]);
        let range = Value::Sequence(vec![Value::Number(20.into()), Value::Number(90.into())]);
        assert!(eval_in_range(Some(&seq), Some(&range)));
        assert!(eval_cmp(
            CriteriaOperator::Gt,
            Some(&Value::Number(5.into())),
            Some(&Value::Number(2.into()))
        ));
        assert!(!eval_cmp(
            CriteriaOperator::Lt,
            Some(&Value::Number(5.into())),
            Some(&Value::Number(2.into()))
        ));
    }
    #[test]
    fn test_eval_is_null() {
        assert!(eval_is_null(None));
        assert!(!eval_is_null(Some(&Value::String("foo".to_string()))));
    }
    #[test]
    fn test_eval_matches_various_types() {
        let val = Value::Number(22.into());
        assert!(!eval_matches(
            Some(&val),
            Some(&Value::String("foo".to_string()))
        ));
        let val = Value::Bool(true);
        assert!(!eval_matches(Some(&val), Some(&Value::Bool(false))));
    }
    #[test]
    fn test_eval_contains_ip_sequence() {
        let seq = Value::Sequence(vec![
            Value::String("127.0.0.1".to_string()),
            Value::String("0.0.0.0".to_string()),
        ]);
        assert!(eval_contains(
            Some(&seq),
            Some(&Value::String("127.0.0.1".to_string()))
        ));
        assert!(!eval_contains(
            Some(&seq),
            Some(&Value::String("192.168.1.1".to_string()))
        ));
    }
    #[test]
    fn test_eval_regex_invalid_pattern() {
        assert!(!eval_regex(
            Some(&Value::String("abc".to_string())),
            Some(&Value::String("[".to_string()))
        ));
    }
    #[test]
    fn test_eval_wildcard_non_string() {
        assert!(!eval_wildcard(
            Some(&Value::Number(1.into())),
            Some(&Value::String("*".to_string()))
        ));
        assert!(!eval_wildcard(
            Some(&Value::String("foo".to_string())),
            Some(&Value::Number(1.into()))
        ));
    }
    #[test]
    fn test_eval_in_range_wrong_type() {
        let val = Value::String("notalist".to_string());
        let range = Value::Sequence(vec![Value::Number(1.into()), Value::Number(2.into())]);
        assert!(!eval_in_range(Some(&val), Some(&range)));
    }
    #[test]
    fn test_eval_cmp_non_number() {
        assert!(!eval_cmp(
            CriteriaOperator::Gt,
            Some(&Value::String("foo".to_string())),
            Some(&Value::String("bar".to_string()))
        ));
    }
    #[test]
    fn test_eval_matches_empty_sequence() {
        let seq = Value::Sequence(vec![]);
        assert!(!eval_matches(Some(&seq), Some(&Value::Number(1.into()))));
    }
    #[test]
    fn test_eval_contains_empty_sequence() {
        let seq = Value::Sequence(vec![]);
        assert!(!eval_contains(
            Some(&seq),
            Some(&Value::String("foo".to_string()))
        ));
    }
    #[test]
    fn test_eval_in_range_empty_sequence() {
        let seq = Value::Sequence(vec![]);
        let range = Value::Sequence(vec![Value::Number(1.into()), Value::Number(2.into())]);
        assert!(!eval_in_range(Some(&seq), Some(&range)));
    }
    #[test]
    fn test_eval_cmp_nulls() {
        assert!(!eval_cmp(CriteriaOperator::Gt, None, None));
    }
}

#[cfg(test)]
mod extra_coverage {
    use super::*;
    use serde_yaml::Value;

    #[test]
    fn test_eval_matches_all_branches() {
        let seq = Value::Sequence(vec![Value::Number(1.into()), Value::Number(2.into())]);
        let list = Value::Sequence(vec![Value::Number(2.into()), Value::Number(3.into())]);
        assert!(super::eval_matches(Some(&seq), Some(&list)));
        assert!(super::eval_matches(
            Some(&seq),
            Some(&Value::Number(1.into()))
        ));
        assert!(super::eval_matches(
            Some(&Value::Number(2.into())),
            Some(&list)
        ));
        assert!(super::eval_matches(
            Some(&Value::Number(2.into())),
            Some(&Value::Number(2.into()))
        ));
        assert!(!super::eval_matches(None, None));
        assert!(!super::eval_matches(
            Some(&Value::Bool(true)),
            Some(&Value::Null)
        ));
    }

    #[test]
    fn test_eval_contains_ip_and_else() {
        let seq = Value::Sequence(vec![Value::String("127.0.0.1".to_string())]);
        assert!(super::eval_contains(
            Some(&seq),
            Some(&Value::String("127.0.0.1".to_string()))
        ));
        let seq = Value::Sequence(vec![Value::String("foo".to_string())]);
        assert!(super::eval_contains(
            Some(&seq),
            Some(&Value::String("foo".to_string()))
        ));
        let seq = Value::Sequence(vec![Value::String("127.0.0.1".to_string())]);
        let list = Value::Sequence(vec![Value::String("127.0.0.1".to_string())]);
        assert!(super::eval_contains(Some(&seq), Some(&list)));
        assert!(!super::eval_contains(
            Some(&Value::Bool(true)),
            Some(&Value::Null)
        ));
    }

    #[test]
    fn test_eval_regex_and_wildcard_else() {
        assert!(!super::eval_regex(
            Some(&Value::String("abc".to_string())),
            Some(&Value::String("[".to_string()))
        ));
        assert!(!super::eval_regex(
            Some(&Value::Bool(true)),
            Some(&Value::Null)
        ));
        assert!(!super::eval_wildcard(
            Some(&Value::Number(1.into())),
            Some(&Value::String("*".to_string()))
        ));
        assert!(!super::eval_wildcard(
            Some(&Value::String("foo".to_string())),
            Some(&Value::Number(1.into()))
        ));
    }

    #[test]
    fn test_eval_cidr_all_branches() {
        let seq = Value::Sequence(vec![Value::String("127.0.0.1".to_string())]);
        assert!(super::eval_cidr(
            Some(&seq),
            Some(&Value::String("127.0.0.0/8".to_string()))
        ));
        assert!(super::eval_cidr(
            Some(&Value::String("127.0.0.1".to_string())),
            Some(&Value::String("127.0.0.0/8".to_string()))
        ));
        assert!(!super::eval_cidr(
            Some(&Value::String("notanip".to_string())),
            Some(&Value::String("notacidr".to_string()))
        ));
        assert!(!super::eval_cidr(
            Some(&Value::Bool(true)),
            Some(&Value::Null)
        ));
    }

    #[test]
    fn test_eval_application_exists_and_service_exists() {
        assert!(!super::eval_application_exists(Some(&Value::Bool(true))));
        assert!(!super::eval_service_exists(Some(&Value::Bool(true))));
        assert!(!super::eval_application_exists(Some(&Value::String(
            "/unlikely/path/to/file".to_string()
        ))));
        assert!(!super::eval_service_exists(Some(&Value::String(
            "unlikely_service_name_123456".to_string()
        ))));
    }

    #[test]
    fn test_eval_not_all_branches() {
        assert!(super::eval_not(
            Some(&Value::String("foo".to_string())),
            Some(&Value::String("bar".to_string()))
        ));
        let list = Value::Sequence(vec![
            Value::String("bar".to_string()),
            Value::Number(1.into()),
        ]);
        assert!(super::eval_not(
            Some(&Value::String("foo".to_string())),
            Some(&list)
        ));
        let seq = Value::Sequence(vec![
            Value::String("foo".to_string()),
            Value::Number(1.into()),
        ]);
        assert!(super::eval_not(
            Some(&seq),
            Some(&Value::String("bar".to_string()))
        ));
        assert!(super::eval_not(Some(&seq), Some(&Value::Number(2.into()))));
        let seq2 = Value::Sequence(vec![Value::String("baz".to_string())]);
        assert!(super::eval_not(Some(&seq), Some(&seq2)));
        assert!(!super::eval_not(
            Some(&Value::Number(1.into())),
            Some(&Value::Number(1.into()))
        ));
    }

    #[test]
    fn test_eval_condition_and_criteria_else_branches() {
        let rule = FirewallRule {
            name: "n".into(),
            direction: "d".into(),
            enabled: true,
            action: "a".into(),
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
        };
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond));
        let expr = CriteriaExpr::Group { and: vec![] };
        assert!(super::eval_criteria(&rule, &expr));
        let expr = CriteriaExpr::OrGroup { or: vec![] };
        assert!(!super::eval_criteria(&rule, &expr));
        let expr = CriteriaExpr::NotGroup {
            not: Box::new(CriteriaExpr::Group { and: vec![] }),
        };
        assert!(!super::eval_criteria(&rule, &expr));
    }
}
