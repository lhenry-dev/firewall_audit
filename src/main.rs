use clap::{Parser, ValueEnum};
use firewall_audit::{append_console_explanation, export_csv, export_html, export_json};

/// Outil d'audit des règles Windows Firewall
#[derive(Parser, Debug)]
#[command(author, version, about = "Audit avancé des règles Windows Firewall", long_about = None, 
    after_help = "\
EXAMPLES :
  Audit simple avec un fichier YAML :
    firewall_audit --criteria rules.yaml
  Audit avec plusieurs fichiers YAML/JSON :
    firewall_audit --criteria rules1.yaml rules2.json
  Export CSV :
    firewall_audit --criteria rules.yaml --export csv --output result.csv
  Export HTML :
    firewall_audit --criteria rules.yaml --export html --output result.html
  Export JSON :
    firewall_audit --criteria rules.yaml --export json --output result.json
")]
pub struct Cli {
    /// Fichiers de critères d'audit (YAML ou JSON)
    #[arg(short, long, required = true)]
    criteria: Vec<String>,
    /// Format d'export (csv, html, json)
    #[arg(short, long, value_enum)]
    export: Option<ExportFmt>,
    /// Fichier de sortie (sinon affiche dans la console)
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum ExportFmt {
    Csv,
    Html,
    Json,
}

fn main() {
    let cli = Cli::parse();
    let audit_rules = firewall_audit::load_audit_rules_multi(&cli.criteria);
    println!("Loaded {} audit rules.", audit_rules.len());
    let output = firewall_audit::run_audit_multi(&audit_rules);
    match cli.export {
        Some(ExportFmt::Csv) => {
            let res = export_csv(&output, cli.output.as_deref());
            match res {
                Ok(csv) if cli.output.is_none() => print!("{}", csv),
                Ok(_) => println!("Export CSV completed."),
                Err(e) => eprintln!("CSV export error: {}", e),
            }
        }
        Some(ExportFmt::Html) => {
            let res = export_html(&output, cli.output.as_deref());
            match res {
                Ok(html) if cli.output.is_none() => print!("{}", html),
                Ok(_) => println!("Export HTML completed."),
                Err(e) => eprintln!("HTML export error: {}", e),
            }
        }
        Some(ExportFmt::Json) => {
            let res = export_json(&output, cli.output.as_deref());
            match res {
                Ok(json) if cli.output.is_none() => print!("{}", json),
                Ok(_) => println!("Export JSON completed."),
                Err(e) => eprintln!("JSON export error: {}", e),
            }
        }
        None => {
            print!("{}", append_console_explanation(&output));
        }
    }
    // Only print the summary line in the console for all export modes
    let summary = firewall_audit::export::append_console_explanation(&output);
    if let Some(ExportFmt::Csv) | Some(ExportFmt::Html) | Some(ExportFmt::Json) = cli.export {
        if let Some(line) = summary.lines().find(|l| l.contains("problem(s) detected")) {
            println!("{}", line.trim());
        }
    }
}
