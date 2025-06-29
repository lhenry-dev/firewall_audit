//! CSV export module for `firewall_audit`
//!
//! Provides a function to export audit results to CSV format.

use crate::export::block::{parse_audit_blocks, severity_order};
use std::fs::File;
use std::io::{self, Write};

/// Export the audit result (String) to CSV format in a file or return the CSV as a String.
///
/// # Arguments
/// * `audit_output` - The audit result as a string (from the audit engine)
/// * `path` - Optional output file path. If None, returns the CSV as a String.
///
/// # Returns
/// * `Ok(String)` - The CSV content (also written to file if path is Some)
/// * `Err(io::Error)` - If writing to file fails
///
/// # Errors
/// Returns an error if writing to the file fails.
pub fn export_csv(audit_output: &str, path: Option<&str>) -> io::Result<String> {
    let mut blocks = parse_audit_blocks(audit_output);
    blocks.sort_by_key(|b| std::cmp::Reverse(severity_order(&b.severity)));
    let mut csv = String::from("rule_id,description,severity,matches\n");
    for b in blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
    {
        let match_str = b.matches.join("|");
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
            esc(&b.id),
            esc(&b.description),
            esc(&b.severity),
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

    const AUDIT_SAMPLE: &str = r"
Audit Rule: test-high
Description: Critical
Severity: high
  ✅ 2 match(es) found:
    - Rule1
    - Rule2
Audit Rule: test-info
Description: Info
Severity: info
  ✅ 1 match(es) found:
    - Rule3
Audit Rule: test-nomatch
Description: No match
Severity: low
  ❌ no firewall rule matches this audit rule
--- Audit End ---
";

    #[test]
    fn test_export_csv_format() {
        let csv = export_csv(AUDIT_SAMPLE, None).unwrap();
        // Should contain the header and two lines (not the no-match rule)
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines[0], "rule_id,description,severity,matches");
        assert!(lines[1].contains(",Critical,high,"));
        assert!(lines[2].contains(",Info,info,"));
        assert_eq!(lines.len(), 3); // header + 2
                                    // Check CSV escaping if needed
        let csv2 = export_csv("Audit Rule: test\nDescription: a,b\nSeverity: high\n  ✅ 1 match(es) found:\n    - Rule1,Rule2\n--- Audit End ---\n", None).unwrap();
        assert!(csv2.contains("\"a,b\""));
        assert!(csv2.contains("\"Rule1,Rule2\""));
    }
}
