use super::firewall_rule::FirewallRule;
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct AuditRule {
    pub id: String,
    pub description: String,
    pub criterias: CriteriaExpr,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CriteriaOperator {
    // Any type
    Equals,  // any (string, number, bool, list, ...)
    Not,     // any
    Matches, // any (true if any value matches any in the list/value)
    // String operators
    StartsWith, // string
    EndsWith,   // string
    Contains,   // string, list
    Regex,      // string
    Wildcard,   // string
    // Number operators
    InRange, // number, list of 2 numbers
    Lt,      // number
    Lte,     // number
    Gt,      // number
    Gte,     // number
    // IP/network operators
    Cidr, // string (IP or CIDR)
    // Boolean/null
    IsNull, // any
    // Existence
    ApplicationExists, // string
    ServiceExists,     // string
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum CriteriaExpr {
    Group { and: Vec<CriteriaExpr> },
    OrGroup { or: Vec<CriteriaExpr> },
    NotGroup { not: Box<CriteriaExpr> },
    Condition(CriteriaCondition),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CriteriaCondition {
    pub field: String,
    #[serde(rename = "operator")]
    pub operator_raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip)]
    pub operator: Option<CriteriaOperator>,
}

impl CriteriaCondition {
    pub fn parse_operator(&mut self) {
        self.operator = match self.operator_raw.to_lowercase().as_str() {
            "equals" => Some(CriteriaOperator::Equals),
            "not" => Some(CriteriaOperator::Not),
            "matches" => Some(CriteriaOperator::Matches),
            "startswith" => Some(CriteriaOperator::StartsWith),
            "endswith" => Some(CriteriaOperator::EndsWith),
            "contains" => Some(CriteriaOperator::Contains),
            "regex" => Some(CriteriaOperator::Regex),
            "wildcard" => Some(CriteriaOperator::Wildcard),
            "in_range" => Some(CriteriaOperator::InRange),
            "lt" => Some(CriteriaOperator::Lt),
            "lte" => Some(CriteriaOperator::Lte),
            "gt" => Some(CriteriaOperator::Gt),
            "gte" => Some(CriteriaOperator::Gte),
            "cidr" => Some(CriteriaOperator::Cidr),
            "is_null" => Some(CriteriaOperator::IsNull),
            "application_exists" => Some(CriteriaOperator::ApplicationExists),
            "service_exists" => Some(CriteriaOperator::ServiceExists),
            _ => None,
        };
    }
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
    let mut cond = cond.clone();
    cond.parse_operator();
    let op = match &cond.operator {
        Some(op) => op,
        None => {
            // Opérateur inconnu, ne matche jamais
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
                    false // Non supporté sur autre OS
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

impl CriteriaOperator {
    /// Returns the expected value type(s) for this operator as a string (for error messages)
    pub fn expected_type(&self) -> &'static str {
        match self {
            // Any
            CriteriaOperator::Equals | CriteriaOperator::Not | CriteriaOperator::Matches => {
                "any (string, number, bool, list, ...)"
            }
            // String
            CriteriaOperator::StartsWith
            | CriteriaOperator::EndsWith
            | CriteriaOperator::Regex
            | CriteriaOperator::Wildcard => "string",
            CriteriaOperator::Contains => "string",
            // Number
            CriteriaOperator::InRange => "list of 2 numbers",
            CriteriaOperator::Lt
            | CriteriaOperator::Lte
            | CriteriaOperator::Gt
            | CriteriaOperator::Gte => "number",
            // IP/network
            CriteriaOperator::Cidr => "string (IP or CIDR)",
            // Boolean/null
            CriteriaOperator::IsNull => "(no value)",
            // Existence
            CriteriaOperator::ApplicationExists | CriteriaOperator::ServiceExists => "string",
        }
    }
}

fn valid_fields() -> &'static [&'static str] {
    &[
        "name",
        "direction",
        "enabled",
        "action",
        "description",
        "application_name",
        "service_name",
        "protocol",
        "local_ports",
        "remote_ports",
        "local_addresses",
        "remote_addresses",
        "icmp_types_and_codes",
        "interfaces",
        "interface_types",
        "grouping",
        "profiles",
        "edge_traversal",
    ]
}

pub fn validate_criteria_expr(expr: &CriteriaExpr, path: &str) -> Vec<String> {
    let mut errors = Vec::new();
    match expr {
        CriteriaExpr::Group { and } => {
            for (i, sub) in and.iter().enumerate() {
                errors.extend(validate_criteria_expr(
                    sub,
                    &format!("{}->and[{}]", path, i),
                ));
            }
        }
        CriteriaExpr::OrGroup { or } => {
            for (i, sub) in or.iter().enumerate() {
                errors.extend(validate_criteria_expr(sub, &format!("{}->or[{}]", path, i)));
            }
        }
        CriteriaExpr::NotGroup { not } => {
            errors.extend(validate_criteria_expr(not, &format!("{}->not", path)));
        }
        CriteriaExpr::Condition(cond) => {
            // Vérification du champ
            if !valid_fields().contains(&cond.field.as_str()) {
                errors.push(format!("Unknown field '{}' at {}", cond.field, path));
                return errors;
            }
            let mut cond = cond.clone();
            cond.parse_operator();
            let op = match cond.operator.as_ref() {
                Some(op) => op,
                None => return errors, // déjà reporté ci-dessus
            };
            let val = &cond.value;
            let err = match op {
                CriteriaOperator::Equals | CriteriaOperator::Not | CriteriaOperator::Matches => {
                    None
                }
                CriteriaOperator::StartsWith
                | CriteriaOperator::EndsWith
                | CriteriaOperator::Regex
                | CriteriaOperator::Wildcard => {
                    if let Some(Value::String(_)) = val {
                        None
                    } else {
                        Some("must be a string")
                    }
                }
                CriteriaOperator::Contains => {
                    if let Some(Value::String(_)) = val {
                        None
                    } else {
                        Some("must be a string (lists are not allowed)")
                    }
                }
                CriteriaOperator::InRange => {
                    if let Some(Value::Sequence(seq)) = val {
                        if seq.len() == 2 && seq.iter().all(|v| matches!(v, Value::Number(_))) {
                            None
                        } else {
                            Some("must be a list of 2 numbers")
                        }
                    } else {
                        Some("must be a list of 2 numbers")
                    }
                }
                CriteriaOperator::Lt
                | CriteriaOperator::Lte
                | CriteriaOperator::Gt
                | CriteriaOperator::Gte => {
                    if let Some(Value::Number(_)) = val {
                        None
                    } else {
                        Some("must be a number")
                    }
                }
                CriteriaOperator::Cidr => {
                    if let Some(Value::String(_)) = val {
                        None
                    } else {
                        Some("must be a string (IP or CIDR)")
                    }
                }
                CriteriaOperator::IsNull => {
                    if val.is_none() {
                        None
                    } else {
                        Some("must not have a value")
                    }
                }
                CriteriaOperator::ApplicationExists | CriteriaOperator::ServiceExists => {
                    if let Some(Value::String(_)) = val {
                        None
                    } else {
                        Some("must be a string")
                    }
                }
            };
            if let Some(msg) = err {
                errors.push(format!(
                    "Invalid value for operator '{:?}' at {}: {} (got {:?})",
                    op, path, msg, val
                ));
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall_rule::FirewallRule;
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

    fn dummy_rule_with_app_and_service(app: Option<&str>, service: Option<&str>) -> FirewallRule {
        let mut rule = dummy_rule();
        rule.application_name = app.map(|s| s.to_string());
        rule.service_name = service.map(|s| s.to_string());
        rule
    }

    #[test]
    fn test_equals_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("TestRule".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("testrule".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("Other".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_startswith_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "startswith".to_string(),
            value: Some(Value::String("Test".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "startswith".to_string(),
            value: Some(Value::String("test".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "startswith".to_string(),
            value: Some(Value::String("Rule".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_endswith_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "endswith".to_string(),
            value: Some(Value::String("Rule".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "endswith".to_string(),
            value: Some(Value::String("rule".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "endswith".to_string(),
            value: Some(Value::String("Test".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_contains_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(Value::String("Windows".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(Value::String("ssh".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(Value::String("nope".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_regex_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "regex".to_string(),
            value: Some(Value::String("Win.*SSH".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "regex".to_string(),
            value: Some(Value::String("^desc$".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_wildcard_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "wildcard".to_string(),
            value: Some(Value::String("*Windows*SSH*".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "wildcard".to_string(),
            value: Some(Value::String("desc*".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "wildcard".to_string(),
            value: Some(Value::String("nope*".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_lt_lte_gt_gte_operators() {
        let rule = dummy_rule();
        let cond_lt = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator_raw: "lt".to_string(),
            value: Some(Value::Number(10.into())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond_lt));
        let cond_lte = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator_raw: "lte".to_string(),
            value: Some(Value::Number(8.into())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond_lte));
        let cond_gt = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator_raw: "gt".to_string(),
            value: Some(Value::Number(7.into())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond_gt));
        let cond_gte = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator_raw: "gte".to_string(),
            value: Some(Value::Number(8.into())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond_gte));
        let cond_fail = CriteriaCondition {
            field: "icmp_types_and_codes".to_string(),
            operator_raw: "lt".to_string(),
            value: Some(Value::Number(5.into())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond_fail));
    }

    #[test]
    fn test_cidr_operator() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_addresses".to_string(),
            operator_raw: "cidr".to_string(),
            value: Some(Value::String("127.0.0.0/8".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "remote_addresses".to_string(),
            operator_raw: "cidr".to_string(),
            value: Some(Value::String("192.168.0.0/16".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond2));
        let cond3 = CriteriaCondition {
            field: "remote_addresses".to_string(),
            operator_raw: "cidr".to_string(),
            value: Some(Value::String("10.0.0.0/8".to_string())),
            operator: None,
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
                    operator_raw: "contains".to_string(),
                    value: Some(Value::String("Test".to_string())),
                    operator: None,
                }),
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "action".to_string(),
                    operator_raw: "equals".to_string(),
                    value: Some(Value::String("Allow".to_string())),
                    operator: None,
                }),
            ],
        };
        assert!(super::eval_criterias(&rule, &expr_and));
        let expr_or = CriteriaExpr::OrGroup {
            or: vec![
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "name".to_string(),
                    operator_raw: "equals".to_string(),
                    value: Some(Value::String("Nope".to_string())),
                    operator: None,
                }),
                CriteriaExpr::Condition(CriteriaCondition {
                    field: "action".to_string(),
                    operator_raw: "equals".to_string(),
                    value: Some(Value::String("Allow".to_string())),
                    operator: None,
                }),
            ],
        };
        assert!(super::eval_criterias(&rule, &expr_or));
        let expr_not = CriteriaExpr::NotGroup {
            not: Box::new(CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(Value::String("Nope".to_string())),
                operator: None,
            })),
        };
        assert!(super::eval_criterias(&rule, &expr_not));
        let expr_not_fail = CriteriaExpr::NotGroup {
            not: Box::new(CriteriaExpr::Condition(CriteriaCondition {
                field: "name".to_string(),
                operator_raw: "equals".to_string(),
                value: Some(Value::String("TestRule".to_string())),
                operator: None,
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
                            operator_raw: "contains".to_string(),
                            value: Some(Value::String("Test".to_string())),
                            operator: None,
                        }),
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "action".to_string(),
                            operator_raw: "equals".to_string(),
                            value: Some(Value::String("Allow".to_string())),
                            operator: None,
                        }),
                    ],
                },
                CriteriaExpr::Group {
                    and: vec![CriteriaExpr::Condition(CriteriaCondition {
                        field: "protocol".to_string(),
                        operator_raw: "equals".to_string(),
                        value: Some(Value::String("Tcp".to_string())),
                        operator: None,
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
                            operator_raw: "contains".to_string(),
                            value: Some(Value::String("Nope".to_string())),
                            operator: None,
                        }),
                        CriteriaExpr::Condition(CriteriaCondition {
                            field: "action".to_string(),
                            operator_raw: "equals".to_string(),
                            value: Some(Value::String("Allow".to_string())),
                            operator: None,
                        }),
                    ],
                },
                CriteriaExpr::Group {
                    and: vec![CriteriaExpr::Condition(CriteriaCondition {
                        field: "protocol".to_string(),
                        operator_raw: "equals".to_string(),
                        value: Some(Value::String("Tcp".to_string())),
                        operator: None,
                    })],
                },
            ],
        };
        assert!(!super::eval_criterias(&rule, &expr_fail));
    }

    #[test]
    fn test_application_exists_operator() {
        // Crée un fichier temporaire
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let rule = dummy_rule_with_app_and_service(Some(path), None);
        let cond = CriteriaCondition {
            field: "application_name".to_string(),
            operator_raw: "application_exists".to_string(),
            value: None,
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        // Cas négatif
        let rule2 = dummy_rule_with_app_and_service(Some("/chemin/inexistant/foobar.exe"), None);
        assert!(!super::eval_condition(&rule2, &cond));
    }

    #[test]
    fn test_service_exists_operator() {
        // Test sur un service courant (Windows : "EventLog", sinon false)
        let rule = dummy_rule_with_app_and_service(None, Some("EventLog"));
        let cond = CriteriaCondition {
            field: "service_name".to_string(),
            operator_raw: "service_exists".to_string(),
            value: None,
            operator: None,
        };
        #[cfg(target_os = "windows")]
        {
            assert!(super::eval_condition(&rule, &cond));
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!super::eval_condition(&rule, &cond));
        }
        // Cas négatif
        let rule2 = dummy_rule_with_app_and_service(None, Some("ServiceQuiNexistePas"));
        assert!(!super::eval_condition(&rule2, &cond));
    }

    #[test]
    fn test_not_operator_single_value() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::String("OtherRule".to_string())),
            operator: None,
        };
        assert!(eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::String("TestRule".to_string())),
            operator: None,
        };
        assert!(!eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_not_operator_list() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Sequence(vec![
                Value::String("OtherRule".to_string()),
                Value::String("Another".to_string()),
            ])),
            operator: None,
        };
        assert!(eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Sequence(vec![
                Value::String("TestRule".to_string()),
                Value::String("Another".to_string()),
            ])),
            operator: None,
        };
        assert!(!eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_not_operator_sequence_field() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Number(serde_yaml::Number::from(443))),
            operator: None,
        };
        assert!(eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Number(serde_yaml::Number::from(22))),
            operator: None,
        };
        assert!(!eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_not_operator_sequence_vs_sequence() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Sequence(vec![
                Value::Number(serde_yaml::Number::from(443)),
                Value::Number(serde_yaml::Number::from(8080)),
            ])),
            operator: None,
        };
        assert!(eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "not".to_string(),
            value: Some(Value::Sequence(vec![
                Value::Number(serde_yaml::Number::from(22)),
                Value::Number(serde_yaml::Number::from(80)),
            ])),
            operator: None,
        };
        assert!(!eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_matches_operator_string_and_list() {
        let rule = dummy_rule();
        // String field vs list
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Sequence(vec![
                Value::String("TestRule".to_string()),
                Value::String("Other".to_string()),
            ])),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Sequence(vec![Value::String("Nope".to_string())])),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_matches_operator_list_and_list() {
        let rule = dummy_rule();
        // List field vs list
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Sequence(vec![
                Value::Number(22.into()),
                Value::Number(443.into()),
            ])),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Sequence(vec![
                Value::Number(443.into()),
                Value::Number(8080.into()),
            ])),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_matches_operator_list_and_scalar() {
        let rule = dummy_rule();
        // List field vs scalar
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Number(22.into())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::Number(443.into())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_matches_operator_scalar_and_scalar() {
        let rule = dummy_rule();
        // Scalar field vs scalar
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::String("TestRule".to_string())),
            operator: None,
        };
        assert!(super::eval_condition(&rule, &cond));
        let cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "matches".to_string(),
            value: Some(Value::String("Nope".to_string())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
    }

    #[test]
    fn test_contains_operator_with_list_should_fail() {
        let rule = dummy_rule();
        let cond = CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(Value::Sequence(vec![Value::String("Windows".to_string())])),
            operator: None,
        };
        // Should always be false
        assert!(!super::eval_condition(&rule, &cond));
    }

    #[test]
    fn test_inrange_operator_with_wrong_types() {
        let rule = dummy_rule();
        // Not a list
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::Number(22.into())),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond));
        // List but not 2 elements
        let cond2 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::Sequence(vec![Value::Number(22.into())])),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond2));
        // List of 2 but not numbers
        let cond3 = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::Sequence(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
            ])),
            operator: None,
        };
        assert!(!super::eval_condition(&rule, &cond3));
    }

    #[test]
    fn test_validation_errors() {
        use super::{CriteriaCondition, CriteriaExpr, validate_criteria_expr};
        // Contains with list
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "description".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(Value::Sequence(vec![Value::String("foo".to_string())])),
            operator: None,
        });
        let errors = validate_criteria_expr(&expr, "root");
        assert!(!errors.is_empty());
        // InRange with wrong type
        let expr2 = CriteriaExpr::Condition(CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::Number(22.into())),
            operator: None,
        });
        let errors2 = validate_criteria_expr(&expr2, "root");
        assert!(!errors2.is_empty());
        // ApplicationExists with non-string
        let expr3 = CriteriaExpr::Condition(CriteriaCondition {
            field: "application_name".to_string(),
            operator_raw: "application_exists".to_string(),
            value: Some(Value::Number(1.into())),
            operator: None,
        });
        let errors3 = validate_criteria_expr(&expr3, "root");
        assert!(!errors3.is_empty());
    }
}
