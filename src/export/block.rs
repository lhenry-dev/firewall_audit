//! Audit block utilities for `firewall_audit`
//!
//! Provides parsing and severity helpers for audit result blocks.

/// Represents a parsed audit block from the audit output.
#[derive(Debug, Clone)]
pub struct AuditBlock {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub matches: Vec<String>,
    pub no_match: bool,
}

/// Returns a numeric order for severity (higher is more severe).
pub fn severity_order(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Parses the audit output into a vector of `AuditBlock` structs.
pub fn parse_audit_blocks(audit_output: &str) -> Vec<AuditBlock> {
    let mut blocks = Vec::new();
    let mut current = AuditBlock {
        id: String::new(),
        description: String::new(),
        severity: String::new(),
        matches: Vec::new(),
        no_match: false,
    };
    for line in audit_output.lines() {
        if let Some(rest) = line.strip_prefix("Audit Rule: ") {
            if !current.id.is_empty() {
                blocks.push(current);
                current = AuditBlock {
                    id: String::new(),
                    description: String::new(),
                    severity: String::new(),
                    matches: Vec::new(),
                    no_match: false,
                };
            }
            current.id = rest.trim().to_string();
        } else if let Some(desc) = line.strip_prefix("Description: ") {
            current.description = desc.trim().to_string();
        } else if let Some(sev) = line.strip_prefix("Severity: ") {
            current.severity = sev.trim().to_string();
        } else if line.trim_start().starts_with("- ") {
            current.matches.push(line.trim_start()[2..].to_string());
        } else if line.contains("no firewall rule matches") {
            current.no_match = true;
        }
    }
    if !current.id.is_empty() {
        blocks.push(current);
    }
    blocks
}

/// Counts the number of blocks by severity.
pub fn count_by_severity<'a, I: Iterator<Item = &'a AuditBlock>>(
    blocks: I,
) -> (usize, usize, usize, usize) {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for b in blocks {
        match b.severity.to_lowercase().as_str() {
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            "info" => info += 1,
            _ => {}
        }
    }
    (high, medium, low, info)
}
