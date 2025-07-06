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
    }

    #[test]
    fn test_validate_criteria_expr_all_branches() {
        // Champ inconnu
        let cond = CriteriaCondition {
            field: "notafield".to_string(),
            operator_raw: "equals".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("Unknown field")));
        // Opérateur inconnu
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "notanop".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.is_empty());
        // Mauvais type pour in_range
        let cond = CriteriaCondition {
            field: "local_ports".to_string(),
            operator_raw: "in_range".to_string(),
            value: Some(Value::String("notalist".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors
            .iter()
            .any(|e| e.contains("must be a list of 2 numbers")));
        // Mauvais type pour is_null
        let cond = CriteriaCondition {
            field: "name".to_string(),
            operator_raw: "is_null".to_string(),
            value: Some(Value::String("foo".to_string())),
            operator: None,
        };
        let expr = CriteriaExpr::Condition(cond);
        let errors = validate_criteria_expr(&expr, "root");
        assert!(errors.iter().any(|e| e.contains("must not have a value")));
    }
}
