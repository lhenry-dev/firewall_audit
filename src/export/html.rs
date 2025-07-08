use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Write};

use crate::audit::run::AuditMatch;
use crate::FirewallAuditError;

/// Exports the audit results to HTML format, writing to a file if a path is provided.
///
/// # Errors
/// Returns an error if writing to the file fails.
pub fn export_html(
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
        write!(
            &mut html,
            "<div class='synth'>{total} problem(s) detected : <span class='sev-high-txt'>{high} critical(s)</span>, <span class='sev-medium-txt'>{medium} important(s)</span>, <span class='sev-low-txt'>{low} minor(s)</span>, <span class='sev-info-txt'>{info} informational(s)</span>.</div>"
        ).map_err(io::Error::other)?;
    }
    let mut any = false;
    for a in audit_results {
        any = true;
        let sev_class = match a.severity.to_lowercase().as_str() {
            "high" => "sev-high",
            "medium" => "sev-medium",
            "low" => "sev-low",
            "info" => "sev-info",
            _ => "",
        };
        write!(&mut html, "<div class=\"rule {sev_class}\">").map_err(io::Error::other)?;
        write!(
            &mut html,
            "<div><b>ID:</b> {}<br><b>Description:</b> {}<br><b>Severity:</b> {}</div>",
            a.rule_id, a.description, a.severity
        )
        .map_err(io::Error::other)?;
        html.push_str("<details><summary>Show matching rules</summary>");
        html.push_str("<ul>");
        for m in &a.matched_firewall_rules {
            write!(&mut html, "<li>{m}</li>").map_err(io::Error::other)?;
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
    use crate::{audit::run::AuditMatch, export_html};

    #[test]
    fn test_export_html_format() {
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
        let html = export_html(&audit_results, None).unwrap();
        // Should contain the summary phrase, the two rules with matches
        assert!(html.contains("problem(s) detected"));
        assert!(html.contains("test-high"));
        assert!(html.contains("test-info"));
        // Should contain severity colors
        assert!(html.contains("sev-high-txt"));
        assert!(html.contains("sev-info-txt"));
    }

    #[test]
    fn test_export_html_file_error() {
        let audit_results = vec![];
        let res = export_html(&audit_results, Some("/invalid/path/to/file.html"));
        assert!(res.is_err());
    }

    #[test]
    fn test_export_html_empty() {
        let html = export_html(&[], None).unwrap();
        assert!(html.contains("No problem detected"));
    }
}
