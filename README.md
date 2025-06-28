# firewall_audit

Rust tool for advanced audit of Windows Firewall rules, inspired by Sigma, with expressive YAML/JSON criteria, export CSV/HTML/JSON, and parallel audit.

## Installation

```sh
# Prerequisites: Rust >= 1.70
cargo build --release
```

## Quick Usage

```sh
# Simple Audit
firewall_audit --criteria rules.yaml

# Audit multi-files YAML/JSON
firewall_audit --criteria rules1.yaml rules2.json

# Export CSV
firewall_audit --criteria rules.yaml --export csv --output result.csv

# Export HTML
firewall_audit --criteria rules.yaml --export html --output result.html

# Export JSON
firewall_audit --criteria rules.yaml --export json --output result.json
```

## Example Rules
See [docs/EXAMPLES.md](EXAMPLES.md)

## FAQ
- **Which operators are supported?**
  - equals, contains, startswith, endswith, in_range, matches, is_null, regex, wildcard, lt, lte, gt, gte, cidr, application_exists, service_exists, and/or/not
- **How to add a custom criterion?**
  - Add an operator in `CriteriaOperator` and implement the logic in `eval_condition`.
- **How to test the tool?**
  - `cargo test` runs all unit and integration tests.

## License
MIT 