# firewall_audit

[![Crates.io](https://img.shields.io/crates/v/firewall_audit.svg)](https://crates.io/crates/firewall_audit)
[![Docs.rs](https://docs.rs/firewall_audit/badge.svg)](https://docs.rs/firewall_audit)
[![CI](https://github.com/<user>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<user>/<repo>/actions)

A cross-platform firewall audit tool and library.

- Audit firewall rules against user-defined criteria (YAML/JSON)
- Export results in CSV, HTML, or JSON
- Usable as a CLI or as a library

## Usage

```sh
firewall_audit --rules rules.yaml --export csv --output result.csv
```

## Features

- Multi-format rules (YAML/JSON)
- Export CSV, HTML, JSON
- Cross-platform (Windows/Linux)
- Extensible criteria language
- CLI and library usage

## Limitations

- **Platform support:**
  - Full firewall rule listing and audit is implemented for **Windows** (using Windows Firewall APIs).
  - On **Linux**, only partial or stub support is available (rule listing may not be implemented).
  - Not tested on macOS.
- **System dependencies:**
  - On Windows, the tool may require administrative privileges to list all firewall rules.
  - The `sc` command is used for service existence checks (Windows only).
- **Rule format:**
  - Only YAML and JSON rule files are supported.
- **Export:**
  - CSV, HTML, and JSON export are supported. Other formats require custom implementation.
- **Internationalization:**
  - All messages and output are in English.
- **Other:**
  - The tool does not modify firewall rules, it only audits and reports.
  - Some advanced criteria may require extending the code (see `CriteriaOperator`).

## License
MIT OR Apache-2.0 