use clap::Parser;
use firewall_audit::{run_firewall_audit, Args};
use tracing::warn;

fn main() {
    let args = Args::parse();

    if !args.quiet {
        tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .init();
    }

    if let Err(e) = run_firewall_audit(args) {
        warn!("Error while running shellshot: {e}");
    }
}
