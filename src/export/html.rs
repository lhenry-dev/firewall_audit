//! HTML export module for `firewall_audit`
//!
//! Provides a function to export audit results to HTML format.

use crate::export::block::{count_by_severity, parse_audit_blocks, severity_order};
use std::fs::File;
use std::io::{self, Write};

/// Export the audit result (String) to HTML format in a file or return the HTML as a String.
///
/// # Arguments
/// * `audit_output` - The audit result as a string (from the audit engine)
/// * `path` - Optional output file path. If None, returns the HTML as a String.
///
/// # Returns
/// * `Ok(String)` - The HTML content (also written to file if path is Some)
/// * `Err(io::Error)` - If writing to file fails
pub fn export_html(audit_output: &str, path: Option<&str>) -> io::Result<String> {
    let mut blocks = parse_audit_blocks(audit_output);
    blocks.sort_by_key(|b| std::cmp::Reverse(severity_order(&b.severity)));
    let filtered: Vec<_> = blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter().copied());
    let style = r"
    <style>
    body { font-family: Arial, sans-serif; background: #f8f8f8; }
    .rule { background: #fff; border-radius: 8px; margin: 1em 0; box-shadow: 0 2px 8px #0001; padding: 1em; }
    .sev-high { border-left: 8px solid #e53935; }
    .sev-medium { border-left: 8px solid #fbc02d; }
    .sev-low { border-left: 8px solid #1976d2; }
    .sev-info { border-left: 8px solid #43a047; }
    summary { font-weight: bold; font-size: 1.1em; cursor: pointer; }
    ul { margin: 0.5em 0 0.5em 1.5em; }
    .synth { font-size: 1.1em; margin-bottom: 1.5em; }
    .sev-high-txt { color: #e53935; font-weight: bold; }
    .sev-medium-txt { color: #fbc02d; font-weight: bold; }
    .sev-low-txt { color: #1976d2; font-weight: bold; }
    .sev-info-txt { color: #43a047; font-weight: bold; }
    </style>
    ";
    let mut html = format!(
        "<html><head><meta charset='utf-8'><title>Firewall Audit</title>{style}</head><body><h1>Firewall Audit</h1>"
    );
    let total = high + medium + low + info;
    if total > 0 {
        html.push_str(&format!(
            "<div class='synth'>{total} problem(s) detected : <span class='sev-high-txt'>{high} critical(s)</span>, <span class='sev-medium-txt'>{medium} important(s)</span>, <span class='sev-low-txt'>{low} minor(s)</span>, <span class='sev-info-txt'>{info} informational(s)</span>.</div>"
        ));
    }
    let mut any = false;
    for b in filtered {
        any = true;
        let sev_class = match b.severity.to_lowercase().as_str() {
            "high" => "sev-high",
            "medium" => "sev-medium",
            "low" => "sev-low",
            "info" => "sev-info",
            _ => "",
        };
        html.push_str(&format!("<div class=\"rule {sev_class}\">"));
        html.push_str(&format!(
            "<div><b>ID:</b> {}<br><b>Description:</b> {}<br><b>Severity:</b> {}</div>",
            b.id, b.description, b.severity
        ));
        html.push_str("<details><summary>Show matching rules</summary>");
        html.push_str("<ul>");
        for m in &b.matches {
            html.push_str(&format!("<li>{m}</li>"));
        }
        html.push_str("</ul></details></div>");
    }
    if !any {
        html.push_str("<div style='color:#43a047;font-weight:bold;'>No problem detected according to the audit criteria.</div>");
    }
    html.push_str("</body></html>");
    if let Some(path) = path {
        let mut file = File::create(path)?;
        file.write_all(html.as_bytes())?;
    }
    Ok(html)
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
    fn test_export_html_format() {
        let html = export_html(AUDIT_SAMPLE, None).unwrap();
        // Should contain the summary phrase, the two rules with matches, and not the no-match rule
        assert!(html.contains("problem(s) detected"));
        assert!(html.contains("test-high"));
        assert!(html.contains("test-info"));
        assert!(!html.contains("test-nomatch"));
        // Should contain severity colors
        assert!(html.contains("sev-high-txt"));
        assert!(html.contains("sev-info-txt"));
    }
}
