//! CSV export module for `firewall_audit`
//!
//! Provides a function to export audit results to CSV format.

use crate::audit::run::AuditMatch;
use std::fs::File;
use std::io::{self, Write};

/// Export the audit result (Vec<AuditMatch>) to CSV format in a file or return the CSV as a String.
///
/// # Arguments
/// * `audit_results` - The audit results as a vector of AuditMatch
/// * `path` - Optional output file path. If None, returns the CSV as a String.
///
/// # Returns
/// * `Ok(String)` - The CSV content (also written to file if path is Some)
/// * `Err(io::Error)` - If writing to file fails
///
/// # Errors
/// Returns an error if writing to the file fails.
pub fn export_csv(audit_results: &[AuditMatch], path: Option<&str>) -> io::Result<String> {
    let mut csv = String::from("rule_id,description,severity,matches\n");
    for a in audit_results.iter() {
        let match_str = a.matched_firewall_rules.join("|");
        // Escape CSV fields (double quotes)
        let esc = |s: &str| {
            let mut s = s.replace('"', "\"\"");
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('|') {
                s = format!("\"{s}\"");
            }
            s
        };
        csv.push_str(&format!(
            "{},{},{},{}\n",
            esc(&a.rule_id),
            esc(&a.description),
            esc(&a.severity),
            esc(&match_str)
        ));
    }
    if let Some(path) = path {
        let mut file = File::create(path)?;
        file.write_all(csv.as_bytes())?;
    }
    Ok(csv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::run::AuditMatch;

    #[test]
    fn test_export_csv_format() {
        let audit_results = vec![
            AuditMatch {
                rule_id: "test-high".to_string(),
                description: "Critical".to_string(),
                severity: "high".to_string(),
                matched_firewall_rules: vec!["Rule1".to_string(), "Rule2".to_string()],
            },
            AuditMatch {
                rule_id: "test-info".to_string(),
                description: "Info".to_string(),
                severity: "info".to_string(),
                matched_firewall_rules: vec!["Rule3".to_string()],
            },
        ];
        let csv = export_csv(&audit_results, None).unwrap();
        // Should contain the header and two lines (not the no-match rule)
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines[0], "rule_id,description,severity,matches");
        assert!(lines[1].contains(",Critical,high,"));
        assert!(lines[2].contains(",Info,info,"));
        assert_eq!(lines.len(), 3); // header + 2
                                    // Check CSV escaping if needed
        let audit_results2 = vec![AuditMatch {
            rule_id: "test".to_string(),
            description: "a,b".to_string(),
            severity: "high".to_string(),
            matched_firewall_rules: vec!["Rule1,Rule2".to_string()],
        }];
        let csv2 = export_csv(&audit_results2, None).unwrap();
        assert!(csv2.contains("\"a,b\""));
        assert!(csv2.contains("\"Rule1,Rule2\""));
    }
}
