use super::types::{CriteriaExpr, CriteriaOperator};
use crate::firewall_rule::FirewallRule;
use serde_yaml::Value;

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
            if !FirewallRule::valid_fields().contains(&cond.field.as_str()) {
                errors.push(format!("Unknown field '{}' at {}", cond.field, path));
                return errors;
            }
            let mut cond = cond.clone();
            cond.parse_operator();
            let op = match cond.operator.as_ref() {
                Some(op) => op,
                None => return errors,
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
