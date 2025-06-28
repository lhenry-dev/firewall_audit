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
        if line.starts_with("Règle d'audit: ") {
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
            current.id = line[15..].trim().to_string();
        } else if let Some(desc) = line.strip_prefix("Description: ") {
            current.description = desc.trim().to_string();
        } else if let Some(sev) = line.strip_prefix("Sévérité: ") {
            current.severity = sev.trim().to_string();
        } else if line.trim_start().starts_with("- ") {
            current.matches.push(line.trim_start()[2..].to_string());
        } else if line.contains("Aucune règle du firewall ne correspond") {
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

/// Exporte le résultat d'audit (String) au format CSV dans un fichier ou retourne le CSV sous forme de String
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

/// Exporte le résultat d'audit (String) au format HTML dans un fichier ou retourne le HTML sous forme de String
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
            "<div class='synth'>{} problème(s) détecté(s) : <span class='sev-high-txt'>{} critique(s)</span>, <span class='sev-medium-txt'>{} important(s)</span>, <span class='sev-low-txt'>{} mineur(s)</span>, <span class='sev-info-txt'>{} informatif(s)</span>.</div>",
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
            "{} problème(s) détecté(s) : {} critique(s), {} important(s), {} mineur(s), {} informatif(s).\n",
            total, high, medium, low, info
        ));
    } else {
        out.push_str("Aucun problème détecté selon les critères d'audit.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT_SAMPLE: &str = r#"
Règle d'audit: test-high
Description: Critique
Sévérité: high
  ✅ 2 correspondance(s) trouvée(s):
    - Rule1
    - Rule2
Règle d'audit: test-info
Description: Info
Sévérité: info
  ✅ 1 correspondance(s) trouvée(s):
    - Rule3
Règle d'audit: test-nomatch
Description: Pas de match
Sévérité: low
  ❌ Aucune règle du firewall ne correspond à cette règle d'audit
--- Fin de l'audit ---
"#;

    #[test]
    fn test_export_csv_format() {
        let csv = export_csv(AUDIT_SAMPLE, None).unwrap();
        // Doit contenir l'en-tête et deux lignes (pas la règle sans match)
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines[0], "regle_id,description,severite,match");
        assert!(lines[1].contains(",Critique,high,"));
        assert!(lines[2].contains(",Info,info,"));
        assert_eq!(lines.len(), 3); // header + 2
        // Vérifie l'échappement CSV si besoin
        let csv2 = export_csv("Règle d'audit: test\nDescription: a,b\nSévérité: high\n  ✅ 1 correspondance(s) trouvée(s):\n    - Rule1,Rule2\n--- Fin de l'audit ---\n", None).unwrap();
        assert!(csv2.contains("\"a,b\""));
        assert!(csv2.contains("\"Rule1,Rule2\""));
    }

    #[test]
    fn test_export_html_format() {
        let html = export_html(AUDIT_SAMPLE, None).unwrap();
        // Doit contenir la phrase de synthèse, les deux règles avec correspondance, et pas la règle sans match
        assert!(html.contains("problème(s) détecté(s)"));
        assert!(html.contains("test-high"));
        assert!(html.contains("test-info"));
        assert!(!html.contains("test-nomatch"));
        // Doit contenir les couleurs de sévérité
        assert!(html.contains("sev-high-txt"));
        assert!(html.contains("sev-info-txt"));
    }

    #[test]
    fn test_console_explanation() {
        let txt = append_console_explanation(AUDIT_SAMPLE);
        assert!(txt.contains("problème(s) détecté(s)"));
        assert!(txt.contains("1 critique(s)"));
        assert!(txt.contains("1 informatif(s)"));
        // On ne vérifie plus l'absence de 'test-nomatch' car le texte d'origine est conservé
    }
}
