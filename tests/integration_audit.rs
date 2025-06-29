use assert_cmd::Command;
use predicates::str::contains;
use std::fs;

#[test]
fn test_audit_integration_yaml_and_exports() {
    // Prepare a minimal YAML rules file
    let rules = r#"
- id: test
  description: test rule
  criterias:
    and:
      - field: name
        operator: equals
        value: "TestRule"
  severity: high
"#;
    let rules_path = "test_rules.yaml";
    fs::write(rules_path, rules).unwrap();

    // Test console output
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.arg("--rules").arg(rules_path);
    cmd.assert().success().stdout(contains(
        "No problem detected according to the audit criteria.",
    ));

    // Test export CSV
    let csv_path = "test_result.csv";
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.args([
        "--rules", rules_path, "--export", "csv", "--output", csv_path,
    ]);
    cmd.assert().success();
    let csv = fs::read_to_string(csv_path).unwrap();
    assert!(csv.starts_with("rule_id,description,severity,matches"));
    let lines: Vec<_> = csv.lines().collect();
    assert_eq!(lines.len(), 1); // Only header, no results

    // Test export HTML
    let html_path = "test_result.html";
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.args([
        "--rules", rules_path, "--export", "html", "--output", html_path,
    ]);
    cmd.assert().success();
    let html = fs::read_to_string(html_path).unwrap();
    assert!(!html.is_empty());

    // Test export JSON
    let json_path = "test_result.json";
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    cmd.args([
        "--rules", rules_path, "--export", "json", "--output", json_path,
    ]);
    cmd.assert().success();
    let json = fs::read_to_string(json_path).unwrap();
    assert!(!json.is_empty());

    // Cleanup
    let _ = fs::remove_file(rules_path);
    let _ = fs::remove_file(csv_path);
    let _ = fs::remove_file(html_path);
    let _ = fs::remove_file(json_path);
}
