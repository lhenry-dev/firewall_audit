# firewall_audit

[![Crates.io](https://img.shields.io/crates/v/firewall_audit.svg)](https://crates.io/crates/firewall_audit)
[![Docs.rs](https://docs.rs/firewall_audit/badge.svg)](https://docs.rs/firewall_audit)
[![CI](https://github.com/<user>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<user>/<repo>/actions)

**firewall_audit** is a cross-platform command-line tool and for auditing firewall rules against user-defined security criteria. It helps security professionals, system administrators, and auditors automatically check firewall configurations for misconfigurations, policy violations, and best practices.

- Audit firewall rules using flexible, extensible criteria (YAML/JSON)
- Export audit results in HTML, JSON, CSV, or plain text
- Use as a command-line tool or as a Rust library
- Supports Windows (full), Linux (partial), and is extensible

---

## Quick Start (CLI)

Audit your firewall rules using a YAML or JSON criteria file and export the results:

```sh
firewall_audit --criteria audit_criteria.yaml --export html --output result.html
```

- `--criteria`: Path to your audit criteria file (YAML or JSON)
- `--export`: Output format (`csv`, `html`, or `json`). If omitted, results are printed as plain text.
- `--output`: Output file path (optional; auto-generated if omitted)

---

## What Does It Do?

- Loads firewall rules from the local system (Windows Firewall or Linux iptables)
- Loads user-defined audit criteria (YAML or JSON)
- Evaluates each firewall rule against all criteria
- Reports all rules that match any problematic criteria
- Exports results in your chosen format (HTML, JSON, CSV, or text)

---

## Example: Audit Criteria (YAML)

Below is a sample of what an audit criteria file can look like. Each rule defines a security check, its logic, and severity:

```yaml
- id: block-rdp-from-anywhere
  description: Block RDP (3389) from any source (should not be open to the world)
  criteria:
    and:
      - field: local_ports
        operator: matches
        value: 3389
      - field: protocol
        operator: equals
        value: "TCP"
      - field: action
        operator: equals
        value: "Allow"
      - field: remote_addresses
        operator: contains
        value: "0.0.0.0/0"
  severity: critical

- id: block-any-rule-without-description
  description: Detect any rule without a description (should be documented)
  criteria:
    and:
      - field: description
        operator: is_null
  severity: medium
```

You can also use JSON for your criteria files.

For more examples, see `docs/EXAMPLES.md`. For a complete reference of all supported fields and operators, see `docs/CRITERIA_REFERENCE.md`.

---

## Platform Support & Limitations

- **Windows:** Full support (uses Windows Firewall APIs; admin rights may be required)
- **Linux:** Partial support (parses `iptables` rules; some fields may be missing or incomplete)
- **macOS:** Not supported/tested

- **Criteria File Format:** Only YAML and JSON are supported for criteria files.
- **Firewall Modification:** This tool does **not** modify firewall rules; it only audits and reports.

---

## Example: CLI Usage

```sh
firewall_audit --criteria audit_criteria.yaml --export csv --output result.csv
firewall_audit --criteria audit_criteria.yaml --export html
firewall_audit --criteria audit_criteria.yaml
```

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or pull request on GitHub.

---

## License

MIT OR Apache-2.0 