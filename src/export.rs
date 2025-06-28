use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};

pub enum ExportFormat {
    Csv,
    Html,
    // Ajoute d'autres formats ici si besoin
}

fn severity_order(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

struct AuditBlock {
    id: String,
    description: String,
    severity: String,
    matches: Vec<String>,
    no_match: bool,
}

fn parse_audit_blocks(audit_output: &str) -> Vec<AuditBlock> {
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

fn count_by_severity<'a, I: Iterator<Item = &'a AuditBlock>>(
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

/// Export the audit result (String) to CSV format in a file or return the CSV as a String
pub fn export_csv(audit_output: &str, path: Option<&str>) -> io::Result<String> {
    let mut blocks = parse_audit_blocks(audit_output);
    blocks.sort_by_key(|b| std::cmp::Reverse(severity_order(&b.severity)));
    let mut csv = String::from("regle_id,description,severite,match\n");
    for b in blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
    {
        let match_str = b.matches.join("|");
        // Échapper les champs CSV (guillemets doubles)
        let esc = |s: &str| {
            let mut s = s.replace('"', "\"\"");
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('|') {
                s = format!("\"{}\"", s);
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

/// Export the audit result (String) to HTML format in a file or return the HTML as a String
pub fn export_html(audit_output: &str, path: Option<&str>) -> io::Result<String> {
    let mut blocks = parse_audit_blocks(audit_output);
    blocks.sort_by_key(|b| std::cmp::Reverse(severity_order(&b.severity)));
    let filtered: Vec<_> = blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter().copied());
    let style = r#"
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
    "#;
    let mut html = format!(
        "<html><head><meta charset='utf-8'><title>Audit Firewall</title>{}</head><body><h1>Audit Firewall</h1>",
        style
    );
    let total = high + medium + low + info;
    if total > 0 {
        html.push_str(&format!(
            "<div class='synth'>{} problem(s) detected : <span class='sev-high-txt'>{} critical(s)</span>, <span class='sev-medium-txt'>{} important(s)</span>, <span class='sev-low-txt'>{} minor(s)</span>, <span class='sev-info-txt'>{} informational(s)</span>.</div>",
            total, high, medium, low, info
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
        html.push_str(&format!("<div class=\"rule {}\">", sev_class));
        html.push_str(&format!(
            "<div><b>ID:</b> {}<br><b>Description:</b> {}<br><b>Sévérité:</b> {}</div>",
            b.id, b.description, b.severity
        ));
        html.push_str("<details><summary>Voir les règles correspondantes</summary>");
        html.push_str("<ul>");
        for m in &b.matches {
            html.push_str(&format!("<li>{}</li>", m));
        }
        html.push_str("</ul></details></div>");
    }
    if !any {
        html.push_str("<div style='color:#43a047;font-weight:bold;'>Aucun problème détecté selon les critères d'audit.</div>");
    }
    html.push_str("</body></html>");
    if let Some(path) = path {
        let mut file = File::create(path)?;
        file.write_all(html.as_bytes())?;
    }
    Ok(html)
}

/// Ajoute un message explicatif à la fin du print console si besoin
pub fn append_console_explanation(audit_output: &str) -> String {
    let blocks = parse_audit_blocks(audit_output);
    let filtered: Vec<_> = blocks
        .iter()
        .filter(|b| !b.no_match && !b.matches.is_empty())
        .collect();
    let (high, medium, low, info) = count_by_severity(filtered.iter().copied());
    let total = high + medium + low + info;
    let mut out = audit_output.to_string();
    out.push('\n');
    if total > 0 {
        out.push_str(&format!(
            "{} problem(s) detected : {} critical(s), {} important(s), {} minor(s), {} informational(s).\n",
            total, high, medium, low, info
        ));
    } else {
        out.push_str("Aucun problème détecté selon les critères d'audit.\n");
    }
    out
}

#[derive(Serialize)]
pub struct JsonAuditBlock {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub matches: Vec<String>,
}

#[derive(Serialize)]
pub struct JsonAuditSummary {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct JsonAuditResult {
    pub summary: JsonAuditSummary,
    pub results: Vec<JsonAuditBlock>,
}

pub fn export_json(audit_output: &str, path: Option<&str>) -> std::io::Result<String> {
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
    let json = serde_json::to_string_pretty(&result).unwrap();
    if let Some(path) = path {
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT_SAMPLE: &str = r#"
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
"#;

    #[test]
    fn test_export_csv_format() {
        let csv = export_csv(AUDIT_SAMPLE, None).unwrap();
        // Should contain the header and two lines (not the no-match rule)
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines[0], "regle_id,description,severite,match");
        assert!(lines[1].contains(",Critical,high,"));
        assert!(lines[2].contains(",Info,info,"));
        assert_eq!(lines.len(), 3); // header + 2
        // Check CSV escaping if needed
        let csv2 = export_csv("Audit Rule: test\nDescription: a,b\nSeverity: high\n  ✅ 1 match(es) found:\n    - Rule1,Rule2\n--- Audit End ---\n", None).unwrap();
        assert!(csv2.contains("\"a,b\""));
        assert!(csv2.contains("\"Rule1,Rule2\""));
    }

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

    #[test]
    fn test_console_explanation() {
        let txt = append_console_explanation(AUDIT_SAMPLE);
        assert!(txt.contains("problem(s) detected"));
        assert!(txt.contains("1 critical(s)"));
        assert!(txt.contains("1 informational(s)"));
        // We no longer check for the absence of 'test-nomatch' as the original text is preserved
    }

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

    #[test]
    fn test_export_english_only_non_regression() {
        let english = r#"
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
"#;
        // CSV
        let csv_en = export_csv(english, None).unwrap();
        assert!(csv_en.contains("test-high"));
        // HTML
        let html_en = export_html(english, None).unwrap();
        assert!(html_en.contains("test-high"));
        // JSON
        let json_en = export_json(english, None).unwrap();
        assert!(json_en.contains("test-high"));
    }
}
