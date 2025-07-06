use super::types::{CriteriaExpr, CriteriaOperator};
use crate::firewall_rule::FirewallRule;
use serde_yaml::Value;

impl CriteriaOperator {
    /// Returns the expected value type(s) for this operator as a string (for error messages)
    pub fn expected_type(&self) -> &'static str {
        match self {
            // Any
            Self::Equals | Self::Not | Self::Matches => "any (string, number, bool, list, ...)",
            // String
            Self::StartsWith
            | Self::EndsWith
            | Self::Regex
            | Self::Wildcard
            | Self::Contains
            | Self::ApplicationExists
            | Self::ServiceExists => "string",
            // Number
            Self::InRange => "list of 2 numbers",
            Self::Lt | Self::Lte | Self::Gt | Self::Gte => "number",
            // IP/network
            Self::Cidr => "string (IP or CIDR)",
            // Boolean/null
            Self::IsNull => "(no value)",
        }
    }
}

pub fn validate_criteria_expr(expr: &CriteriaExpr, path: &str) -> Vec<String> {
    let mut errors = Vec::new();
    match expr {
        CriteriaExpr::Group { and } => {
            for (i, sub) in and.iter().enumerate() {
                errors.extend(validate_criteria_expr(sub, &format!("{path}->and[{i}]")));
            }
        }
        CriteriaExpr::OrGroup { or } => {
            for (i, sub) in or.iter().enumerate() {
                errors.extend(validate_criteria_expr(sub, &format!("{path}->or[{i}]")));
            }
        }
        CriteriaExpr::NotGroup { not } => {
            errors.extend(validate_criteria_expr(not, &format!("{path}->not")));
        }
        CriteriaExpr::Condition(cond) => {
            if !FirewallRule::valid_fields().contains(&cond.field.as_str()) {
                errors.push(format!("Unknown field '{}' at {path}", cond.field));
                return errors;
            }
            let mut cond = cond.clone();
            cond.parse_operator();
            let Some(op) = cond.operator.as_ref() else {
                return errors;
            };
            let val = &cond.value;
            let err = match op {
                CriteriaOperator::Equals | CriteriaOperator::Not | CriteriaOperator::Matches => {
                    None
                }
                CriteriaOperator::StartsWith
                | CriteriaOperator::EndsWith
                | CriteriaOperator::Regex
                | CriteriaOperator::Wildcard
                | CriteriaOperator::Contains
                | CriteriaOperator::ApplicationExists
                | CriteriaOperator::ServiceExists => {
                    if let Some(Value::String(_)) = val {
                        None
                    } else {
                        Some("must be a string")
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
            };
            if let Some(msg) = err {
                errors.push(format!(
                    "Invalid value for operator '{op:?}' at {path}: {msg} (got {val:?})"
                ));
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::criteria::types::{CriteriaCondition, CriteriaExpr};
    use serde_yaml::Value;

    #[test]
    fn test_validate_criteria_expr_unknown_field() {
        let cond = CriteriaCondition {
            field: "notafield".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("Unknown field")));
    }

    #[test]
    fn test_validate_criteria_expr_wrong_type() {
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::String("notalist".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors
            .iter()
            .any(|e| e.contains("must be a list of 2 numbers")));
    }

    #[test]
    fn test_validate_criteria_expr_unknown_operator() {
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_criteria_expr_valid_field_wrong_operator_type() {
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "starts_with".to_string(),
            value: Some(Value::Number(22.into())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("must be a string")));
    }

    #[test]
    fn test_starts_with_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "starts_with".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for starts_with on name with number"
        );
    }

    #[test]
    fn test_ends_with_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "ends_with".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for ends_with on name with number"
        );
    }

    #[test]
    fn test_regex_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "regex".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for regex on name with number"
        );
    }

    #[test]
    fn test_wildcard_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "wildcard".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for wildcard on name with number"
        );
    }

    #[test]
    fn test_contains_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "contains".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for contains on name with number"
        );
    }

    #[test]
    fn test_application_exists_wrong_type_on_application_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "application_name".to_string(),
            operator_raw: "application_exists".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for application_exists on application_name with number"
        );
    }

    #[test]
    fn test_service_exists_wrong_type_on_service_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "service_name".to_string(),
            operator_raw: "service_exists".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a string")),
            "Should catch error for service_exists on service_name with number"
        );
    }

    #[test]
    fn test_in_range_wrong_type_on_local_ports() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(serde_yaml::Value::String("notalist".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("must be a list of 2 numbers")),
            "Should catch error for in_range on local_ports with string"
        );
    }

    #[test]
    fn test_lt_wrong_type_on_local_ports() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "lt".to_string(),
            value: Some(serde_yaml::Value::String("notanumber".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a number")),
            "Should catch error for lt on local_ports with string"
        );
    }

    #[test]
    fn test_lte_wrong_type_on_local_ports() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "lte".to_string(),
            value: Some(serde_yaml::Value::String("notanumber".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a number")),
            "Should catch error for lte on local_ports with string"
        );
    }

    #[test]
    fn test_gt_wrong_type_on_local_ports() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "gt".to_string(),
            value: Some(serde_yaml::Value::String("notanumber".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a number")),
            "Should catch error for gt on local_ports with string"
        );
    }

    #[test]
    fn test_gte_wrong_type_on_local_ports() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "gte".to_string(),
            value: Some(serde_yaml::Value::String("notanumber".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must be a number")),
            "Should catch error for gte on local_ports with string"
        );
    }

    #[test]
    fn test_cidr_wrong_type_on_local_addresses() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "local_addresses".to_string(),
            operator_raw: "cidr".to_string(),
            value: Some(serde_yaml::Value::Number(1.into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("must be a string (IP or CIDR)")),
            "Should catch error for cidr on local_addresses with number"
        );
    }

    #[test]
    fn test_is_null_wrong_type_on_name() {
        let cond = crate::criteria::types::CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "is_null".to_string(),
            value: Some(serde_yaml::Value::String("foo".into())),
            operator: None,
        };
        let expr = crate::criteria::types::CriteriaExpr::Condition(cond);
        let errors = super::validate_criteria_expr(&expr, "root");
        assert!(
            errors.iter().any(|e| e.contains("must not have a value")),
            "Should catch error for is_null on name with string"
        );
    }
}

#[cfg(test)]
mod coverage {
    use crate::criteria::types::CriteriaOperator;

    #[test]
    fn test_expected_type_all_variants() {
        use CriteriaOperator::*;
        let all = [
            Equals,
            Not,
            Matches,
            StartsWith,
            EndsWith,
            Regex,
            Wildcard,
            Contains,
            InRange,
            Lt,
            Lte,
            Gt,
            Gte,
            Cidr,
            IsNull,
            ApplicationExists,
            ServiceExists,
        ];
        for op in all.iter() {
            let t = op.expected_type();
            assert!(
                !t.is_empty(),
                "expected_type for {:?} should not be empty",
                op
            );
        }
    }
}
