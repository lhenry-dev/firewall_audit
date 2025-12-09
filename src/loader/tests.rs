#[cfg(test)]
mod loader {
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::loader::load::{
        load_audit_criteria_from_paths, load_audit_criteria_json, load_audit_criteria_yaml,
    };

    #[test]
    fn test_load_audit_criteria_yaml() {
        let yaml = "- id: test\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = load_audit_criteria_yaml(path).expect("Failed to load YAML rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test");
    }

    #[test]
    fn test_load_audit_criteria_json() {
        let json = r#"[
            {"id": "testjson", "description": "desc", "criteria": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let rules = load_audit_criteria_json(path).expect("Failed to load JSON rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "testjson");
    }

    #[test]
    fn test_load_audit_criteria_multi() {
        let yaml = "- id: test1\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let json = r#"[
            {"id": "test2", "description": "desc", "criteria": {"and": [{"field": "name", "operator": "equals", "value": "TestRule"}]}, "severity": "info"}
        ]"#;
        let mut tmpyaml = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        let mut tmpjson = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        write!(tmpyaml, "{yaml}").unwrap();
        write!(tmpjson, "{json}").unwrap();
        let path_yaml = tmpyaml.path().to_str().unwrap().to_string();
        let path_json = tmpjson.path().to_str().unwrap().to_string();
        let rules = load_audit_criteria_from_paths(&[path_yaml, path_json])
            .expect("Failed to load multi rules");
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.id == "test1"));
        assert!(rules.iter().any(|r| r.id == "test2"));
    }

    #[test]
    fn test_load_audit_criteria_yaml_invalid_syntax() {
        let yaml = "- id: test\n  description: test\n  criteria: [INVALID\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = load_audit_criteria_yaml(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_criteria_json_invalid_syntax() {
        let json = r#"[{\"id\": \"test\", \"description\": \"desc\", \"criteria\": {and: [}}]"#;
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "{json}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = load_audit_criteria_json(path);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_audit_criteria_yaml_missing_field() {
        let yaml = "- description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = load_audit_criteria_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.is_empty() || rules.iter().all(|r| !r.id.is_empty()));
    }

    #[test]
    fn test_load_audit_criteria_yaml_unknown_operator() {
        let yaml = "- id: test\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: unknownop\n        value: 'TestRule'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap();
        let res = load_audit_criteria_yaml(path);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.iter().any(|r| r.id == "test"));
        let rule = rules.iter().find(|r| r.id == "test").unwrap();
        if let crate::criteria::types::CriteriaExpr::Group { and } = &rule.criteria {
            for expr in and {
                if let crate::criteria::types::CriteriaExpr::Condition(cond) = expr {
                    assert!(cond.operator.is_none());
                }
            }
        }
    }

    #[test]
    fn test_load_audit_criteria_yaml_unknown_field_ignored() {
        let yaml = "- id: badfield\n  description: test\n  criteria:\n    and:\n      - field: notafield\n        operator: equals\n        value: 'foo'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules =
            load_audit_criteria_from_paths(&[path]).expect("Should not crash on unknown field");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_audit_criteria_yaml_wrong_type_ignored() {
        let yaml = "- id: badtype\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: in_range\n        value: 'notalist'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules =
            load_audit_criteria_from_paths(&[path]).expect("Should not crash on wrong type");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_audit_criteria_yaml_invalid_structure_ignored() {
        let yaml = "- id: invalid\n  description: test\n  criteria: 12345\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let res = load_audit_criteria_from_paths(&[path]);
        assert!(res.is_ok());
        let rules = res.unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_audit_criteria_yaml_multiple_some_invalid() {
        let yaml = "- id: valid\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: equals\n        value: 'ok'\n  severity: info\n- id: badfield\n  description: test\n  criteria:\n    and:\n      - field: notafield\n        operator: equals\n        value: 'foo'\n  severity: info\n- id: badtype\n  description: test\n  criteria:\n    and:\n      - field: name\n        operator: in_range\n        value: 'notalist'\n  severity: info\n";
        let mut tmpfile = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        write!(tmpfile, "{yaml}").unwrap();
        let path = tmpfile.path().to_str().unwrap().to_string();
        let rules = load_audit_criteria_from_paths(&[path])
            .expect("Should not crash on mixed valid/invalid");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "valid");
    }
}
