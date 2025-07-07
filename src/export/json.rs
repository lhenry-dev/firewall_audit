use crate::audit::run::AuditMatch;
use crate::error::FirewallAuditError;
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

/// Exports the audit results to JSON format, writing to a file if a path is provided.
///
/// # Errors
/// Returns an error if writing to the file or serializing fails.
pub fn export_json(
    audit_results: &[AuditMatch],
    path: Option<&str>,
) -> Result<String, FirewallAuditError> {
    let (high, medium, low, info) = audit_results.iter().fold((0, 0, 0, 0), |mut acc, a| {
        match a.severity.to_lowercase().as_str() {
            "high" => acc.0 += 1,
            "medium" => acc.1 += 1,
            "low" => acc.2 += 1,
            "info" => acc.3 += 1,
            _ => {}
        }
        acc
    });
    let total = high + medium + low + info;
    let json_blocks: Vec<JsonAuditBlock> = audit_results
        .iter()
        .map(|a| JsonAuditBlock {
            id: a.rule_id.clone(),
            description: a.description.clone(),
            severity: a.severity.clone(),
            matches: a.matched_firewall_rules.clone(),
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
    use crate::{audit::run::AuditMatch, export_json};

    #[test]
    fn test_export_json_format() {
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
        let json = export_json(&audit_results, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("summary").is_some());
        assert!(v.get("results").is_some());
        let results = v.get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 2);
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

    #[test]
    fn test_export_json_file_error() {
        let audit_results = vec![];
        let res = export_json(&audit_results, Some("/invalid/path/to/file.json"));
        assert!(res.is_err());
    }

    #[test]
    fn test_export_json_empty() {
        let json = export_json(&[], None).unwrap();
        assert!(json.contains("\"results\": []"));
    }
}
