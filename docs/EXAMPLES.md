# Examples of YAML audit rules

```yaml
- id: allow-ssh-from-anywhere
  description: Permits SSH from anywhere
  criterias:
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

- id: check-app-exists
  description: Checks if the referenced application exists
  criterias:
    and:
      - field: application_name
        operator: application_exists
  severity: medium

- id: check-service-exists
  description: Checks if the referenced service exists
  criterias:
    and:
      - field: service_name
        operator: service_exists
  severity: medium
```

# Examples of JSON audit rules

```json
[
  {
    "id": "allow-ssh-from-anywhere",
    "description": "Permits SSH from anywhere",
    "criterias": {
      "and": [
        {"field": "name", "operator": "contains", "value": "SSH"},
        {"field": "local_ports", "operator": "matches", "value": 22},
        {"field": "protocol", "operator": "equals", "value": "TCP"},
        {"field": "remote_addresses", "operator": "contains", "value": "0.0.0.0/0"},
        {"field": "action", "operator": "equals", "value": "ALLOW"}
      ]
    },
    "severity": "high"
  },
  {
    "id": "check-app-exists",
    "description": "Checks if the referenced application exists",
    "criterias": {
      "and": [
        {"field": "application_name", "operator": "application_exists"}
      ]
    },
    "severity": "medium"
  },
  {
    "id": "check-service-exists",
    "description": "Checks if the referenced service exists",
    "criterias": {
      "and": [
        {"field": "service_name", "operator": "service_exists"}
      ]
    },
    "severity": "medium"
  }
] 