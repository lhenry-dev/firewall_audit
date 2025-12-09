use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Write};

use crate::audit::AuditMatch;
use crate::export::ExportError;

/// Exports the audit results to CSV format, writing to a file if a path is provided.
///
/// # Errors
/// Returns an error if writing to the file fails.
pub fn export_csv(audit_results: &[AuditMatch], path: Option<&str>) -> Result<String, ExportError> {
    let mut csv = String::from("rule_id,description,severity,matches\n");
    for a in audit_results {
        let match_str = a.matched_firewall_rules.join("|");
        // Escape CSV fields (double quotes)
        let esc = |s: &str| {
            let mut s = s.replace('"', "\"\"");
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('|') {
                s = format!("\"{s}\"");
            }
            s
        };
        writeln!(
            &mut csv,
            "{},{},{},{}",
            esc(&a.rule_id),
            esc(&a.description),
            esc(&a.severity),
            esc(&match_str)
        )
        .map_err(io::Error::other)?;
    }
    if let Some(path) = path {
        let mut file = File::create(path)?;
        file.write_all(csv.as_bytes())?;
    }
    Ok(csv)
}

#[cfg(test)]
mod tests {
    use crate::{audit::AuditMatch, export::export_csv};

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

    #[test]
    fn test_export_csv_file_error() {
        let audit_results = vec![];
        let res = export_csv(&audit_results, Some("/invalid/path/to/file.csv"));
        assert!(res.is_err());
    }

    #[test]
    fn test_export_csv_empty() {
        let csv = export_csv(&[], None).unwrap();
        assert!(csv.contains("rule_id,description,severity,matches"));
        assert_eq!(csv.lines().count(), 1);
    }
}
