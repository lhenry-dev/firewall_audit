use firewall_audit::{
    ExportFormat, append_console_explanation, export_csv, export_html, run_audit,
};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let yaml_path = if args.len() > 1 {
        &args[1]
    } else {
        "rules_cursor.yaml"
    };
    let output = run_audit(yaml_path);
    // Option d'export : --export csv|html [--output fichier]
    let mut export_format = None;
    let mut output_path = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--export" if i + 1 < args.len() => {
                export_format = match args[i + 1].to_lowercase().as_str() {
                    "csv" => Some(ExportFormat::Csv),
                    "html" => Some(ExportFormat::Html),
                    _ => None,
                };
                i += 2;
            }
            "--output" if i + 1 < args.len() => {
                output_path = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    match export_format {
        Some(ExportFormat::Csv) => {
            let res = export_csv(&output, output_path.as_deref());
            match res {
                Ok(csv) if output_path.is_none() => print!("{}", csv),
                Ok(_) => println!("Export CSV terminé."),
                Err(e) => eprintln!("Erreur export CSV: {}", e),
            }
        }
        Some(ExportFormat::Html) => {
            let res = export_html(&output, output_path.as_deref());
            match res {
                Ok(html) if output_path.is_none() => print!("{}", html),
                Ok(_) => println!("Export HTML terminé."),
                Err(e) => eprintln!("Erreur export HTML: {}", e),
            }
        }
        None => {
            print!("{}", append_console_explanation(&output));
        }
    }
}
