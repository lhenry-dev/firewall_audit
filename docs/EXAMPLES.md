# Examples of YAML audit rules

## 1. Allow SSH from anywhere (simple AND group)
```yaml
- id: allow-ssh-from-anywhere
  description: Permits SSH from anywhere
  criteria:
    and:
      - field: name
        operator: contains
        value: "SSH"
      - field: local_ports
        operator: matches
        value: 22
      - field: protocol
        operator: equals
        value: "TCP"
      - field: remote_addresses
        operator: contains
        value: "0.0.0.0/0"
      - field: action
        operator: equals
        value: "ALLOW"
  severity: high
```

## 2. Detect rules with missing description (field: description, is_null)
```yaml
- id: missing-description
  description: Detect any rule without a description
  criteria:
    and:
      - field: description
        operator: is_null
  severity: medium
```

## 3. Detect rules for HTTP or HTTPS open to the world (OR group)
```yaml
- id: open-web-to-anywhere
  description: Detect rules that allow HTTP or HTTPS from any source
  criteria:
    or:
      - and:
          - field: local_ports
            operator: matches
            value: 80
          - field: protocol
            operator: equals
            value: "TCP"
          - field: action
            operator: equals
            value: "Allow"
          - field: remote_addresses
            operator: contains
            value: "0.0.0.0/0"
      - and:
          - field: local_ports
            operator: matches
            value: 443
          - field: protocol
            operator: equals
            value: "TCP"
          - field: action
            operator: equals
            value: "Allow"
          - field: remote_addresses
            operator: contains
            value: "0.0.0.0/0"
  severity: high
```

## 4. Detect rules that allow any port except DNS (NOT group)
```yaml
- id: allow-any-except-dns
  description: Detect rules that allow any port except DNS (53)
  criteria:
    and:
      - field: action
        operator: equals
        value: "Allow"
      - not:
          field: local_ports
          operator: matches
          value: 53
  severity: low
```

## 5. Detect rules for a specific OS (field: os)
```yaml
- id: windows-rule-without-description
  description: Detect any rule without a description (Windows only)
  criteria:
    and:
      - field: description
        operator: is_null
  severity: medium
  os: ["windows"]
```

## 6. Detect rules missing both application and service (multiple fields, AND)
```yaml
- id: missing-app-and-service
  description: Detect rules not tied to an application or service
  criteria:
    and:
      - field: application_name
        operator: is_null
      - field: service_name
        operator: is_null
  severity: medium
```

# Examples of JSON audit rules

```json
[
  {
    "id": "open-web-to-anywhere",
    "description": "Detect rules that allow HTTP or HTTPS from any source",
    "criteria": {
      "or": [
        {
          "and": [
            {"field": "local_ports", "operator": "matches", "value": 80},
            {"field": "protocol", "operator": "equals", "value": "TCP"},
            {"field": "action", "operator": "equals", "value": "Allow"},
            {"field": "remote_addresses", "operator": "contains", "value": "0.0.0.0/0"}
          ]
        },
        {
          "and": [
            {"field": "local_ports", "operator": "matches", "value": 443},
            {"field": "protocol", "operator": "equals", "value": "TCP"},
            {"field": "action", "operator": "equals", "value": "Allow"},
            {"field": "remote_addresses", "operator": "contains", "value": "0.0.0.0/0"}
          ]
        }
      ]
    },
    "severity": "high"
  },
  {
    "id": "missing-app-and-service",
    "description": "Detect rules not tied to an application or service",
    "criteria": {
      "and": [
        {"field": "application_name", "operator": "is_null"},
        {"field": "service_name", "operator": "is_null"}
      ]
    },
    "severity": "medium"
  }
]
```
