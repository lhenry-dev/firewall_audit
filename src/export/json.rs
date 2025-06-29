//! JSON export module for `firewall_audit`
//!
//! Provides a function to export audit results to JSON format.

use crate::error::FirewallAuditError;
use crate::export::block::{count_by_severity, parse_audit_blocks};
use serde::Serialize;
use std::fs::File;
use std::io::Write;

/// Represents a single audit block for JSON export.
#[derive(Debug, Serialize)]
pub struct JsonAuditBlock {
    /// Rule ID
    pub id: String,
    /// Rule description
    pub description: String,
    /// Rule severity
    pub severity: String,
    /// List of matching firewall rules
    pub matches: Vec<String>,
}

/// Represents the summary of audit results for JSON export.
#[derive(Debug, Serialize)]
pub struct JsonAuditSummary {
    /// Number of high severity rules
    pub high: usize,
    /// Number of medium severity rules
    pub medium: usize,
    /// Number of low severity rules
    pub low: usize,
    /// Number of info severity rules
    pub info: usize,
    /// Total number of rules
    pub total: usize,
}

/// Represents the full audit result for JSON export.
#[derive(Debug, Serialize)]
pub struct JsonAuditResult {
    /// Summary of the audit
    pub summary: JsonAuditSummary,
    /// List of audit blocks
    pub results: Vec<JsonAuditBlock>,
}

/// Export the audit result (String) to JSON format in a file or return the JSON as a String.
///
/// # Arguments
/// * `audit_output` - The audit result as a string (from the audit engine)
/// * `path` - Optional output file path. If None, returns the JSON as a String.
///
/// # Returns
/// * `Ok(String)` - The JSON content (also written to file if path is Some)
/// * `Err(FirewallAuditError)` - If writing to file or serializing fails
pub fn export_json(audit_output: &str, path: Option<&str>) -> Result<String, FirewallAuditError> {
    let blocks = parse_audit_blocks(audit_output);
    let filtered: Vec<_> = blocks
        .into_iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter());
    let total = high + medium + low + info;
    let json_blocks: Vec<JsonAuditBlock> = filtered
        .into_iter()
        .map(|b| JsonAuditBlock {
            id: b.id,
            description: b.description,
            severity: b.severity,
            matches: b.matches,
        })
        .collect();
    let summary = JsonAuditSummary {
        high,
        medium,
        low,
        info,
        total,
    };
    let result = JsonAuditResult {
        summary,
        results: json_blocks,
    };
    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| FirewallAuditError::ExportError(e.to_string()))?;
    if let Some(path) = path {
        let mut file = File::create(path).map_err(FirewallAuditError::Io)?;
        file.write_all(json.as_bytes())
            .map_err(FirewallAuditError::Io)?;
    }
    Ok(json)
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
    fn test_export_json_format() {
        let json = export_json(AUDIT_SAMPLE, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("summary").is_some());
        assert!(v.get("results").is_some());
        let results = v.get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 2); // 2 rules with matches
        let ids: Vec<_> = results
            .iter()
            .map(|r| r.get("id").unwrap().as_str().unwrap())
            .collect();
        assert!(ids.contains(&"test-high"));
        assert!(ids.contains(&"test-info"));
        let summary = v.get("summary").unwrap();
        assert_eq!(summary.get("high").unwrap().as_u64().unwrap(), 1);
        assert_eq!(summary.get("info").unwrap().as_u64().unwrap(), 1);
    }
}
