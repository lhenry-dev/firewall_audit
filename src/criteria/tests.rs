#[cfg(test)]
mod criteria {
    use crate::criteria::types::*;
    use crate::criteria::validation::*;
    use serde_yaml::Value;

    #[test]
    fn test_parse_operator_valid_invalid() {
        let mut cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        cond.parse_operator();
        assert_eq!(cond.operator, Some(CriteriaOperator::Equals));
        let mut cond2 = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        cond2.parse_operator();
        assert_eq!(cond2.operator, None);
        // Unknown field
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "notafield".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        });
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("Unknown field")));
        // Unknown operator: validate_criteria_expr returns no error for unknown operator
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        });
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_criteria_expr_all_branches() {
        // Unknown field
        let cond = CriteriaCondition {
            field: "notafield".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("Unknown field")));
        // Unknown operator: validate_criteria_expr returns no error for unknown operator
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.is_empty());
        // Wrong type for in_range
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::String("notalist".to_string())),
            operator: None,
        });
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors
            .iter()
            .any(|e| e.contains("must be a list of 2 numbers")));
        // Wrong type for is_null
        let expr = CriteriaExpr::Condition(CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "is_null".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        });
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("must not have a value")));
    }
}
