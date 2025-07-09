# Criteria Reference

This document lists all the fields and operators you can use to write audit criteria for firewall rules. Use it as a reference when creating your YAML or JSON criteria files.

---

## How to Combine Conditions

- You can use `and`, `or`, and `not` to build complex logic:
  - `and`: All sub-conditions must match
  - `or`: At least one sub-condition must match
  - `not`: The sub-condition must NOT match
- You can nest these groups to express any logic you need.

---

## Supported Fields

You can write criteria on any of the following firewall rule fields:

- `name` (string)
- `direction` ("In"/"Out")
- `enabled` (bool)
- `action` ("Allow"/"Deny")
- `description` (string)
- `application_name` (string)
- `service_name` (string)
- `protocol` (string)
- `local_ports` (list of numbers)
- `remote_ports` (list of numbers)
- `local_addresses` (list of IPs)
- `remote_addresses` (list of IPs)
- `icmp_types_and_codes` (string)
- `interfaces` (list of strings)
- `interface_types` (list of strings)
- `grouping` (string)
- `profiles` (string)
- `edge_traversal` (bool)
- `os` ("windows"/"linux")

> **Note:** Not all fields are available on all platforms. For example, some fields may be missing on Linux. See the README for platform-specific notes.

---

## Supported Operators

You can use the following operators in your criteria:

- `equals` / `not` — equality/inequality
- `matches` — value is in a list
- `starts_with` / `ends_with` / `contains` — string operations
- `regex` / `wildcard` — pattern matching
- `in_range` — number is in a range (list of 2 numbers)
- `lt` / `lte` / `gt` / `gte` — numeric comparisons
- `cidr` — IP/network CIDR match
- `is_null` — field is missing or null
- `application_exists` / `service_exists` — check if referenced application/service exists (Windows only)