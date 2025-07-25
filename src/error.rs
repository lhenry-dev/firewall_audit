/// Error type for `firewall_audit` operations.
#[derive(Debug, thiserror::Error)]
pub enum FirewallAuditError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing error
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    /// JSON parsing error
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    /// Invalid rule structure
    #[error("Invalid rule structure at index {index}: {message}")]
    InvalidRuleStructure {
        /// Index of the rule
        index: usize,
        /// Error message
        message: String,
    },

    /// Unknown operator
    #[error("Unknown operator '{operator}' at {path}")]
    UnknownOperator {
        /// Operator name
        operator: String,
        /// Path in the rule
        path: String,
    },

    /// Unknown field
    #[error("Unknown field '{field}' at {path}")]
    UnknownField {
        /// Field name
        field: String,
        /// Path in the rule
        path: String,
    },

    /// Invalid operator value
    #[error("Invalid value for operator '{operator}' at {path}: {message}")]
    InvalidOperatorValue {
        /// Operator name
        operator: String,
        /// Path in the rule
        path: String,
        /// Error message
        message: String,
    },

    /// Unsupported file format
    #[error("Unsupported file format: {path}")]
    UnsupportedFileFormat {
        /// File path
        path: String,
    },

    /// Windows Firewall error
    #[error("Windows Firewall error: {0}")]
    WindowsFirewallError(String),

    /// Export error
    #[error("Export error: {0}")]
    ExportError(String),

    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl FirewallAuditError {
    /// Create an `InvalidRuleStructure` error
    pub fn invalid_rule_structure(index: usize, message: impl Into<String>) -> Self {
        Self::InvalidRuleStructure {
            index,
            message: message.into(),
        }
    }

    /// Create an `UnknownOperator` error
    pub fn unknown_operator(operator: impl Into<String>, path: impl Into<String>) -> Self {
        Self::UnknownOperator {
            operator: operator.into(),
            path: path.into(),
        }
    }

    /// Create an `UnknownField` error
    pub fn unknown_field(field: impl Into<String>, path: impl Into<String>) -> Self {
        Self::UnknownField {
            field: field.into(),
            path: path.into(),
        }
    }

    /// Create an `InvalidOperatorValue` error
    pub fn invalid_operator_value(
        operator: impl Into<String>,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidOperatorValue {
            operator: operator.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_rule_structure_constructor() {
        let err = FirewallAuditError::invalid_rule_structure(42, "bad struct");
        match err {
            FirewallAuditError::InvalidRuleStructure { index, ref message } => {
                assert_eq!(index, 42);
                assert_eq!(message, "bad struct");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_unknown_operator_constructor() {
        let err = FirewallAuditError::unknown_operator("foo", "path");
        match err {
            FirewallAuditError::UnknownOperator {
                ref operator,
                ref path,
            } => {
                assert_eq!(operator, "foo");
                assert_eq!(path, "path");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_unknown_field_constructor() {
        let err = FirewallAuditError::unknown_field("bar", "path2");
        match err {
            FirewallAuditError::UnknownField {
                ref field,
                ref path,
            } => {
                assert_eq!(field, "bar");
                assert_eq!(path, "path2");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_invalid_operator_value_constructor() {
        let err = FirewallAuditError::invalid_operator_value("baz", "p", "msg");
        match err {
            FirewallAuditError::InvalidOperatorValue {
                ref operator,
                ref path,
                ref message,
            } => {
                assert_eq!(operator, "baz");
                assert_eq!(path, "p");
                assert_eq!(message, "msg");
            }
            _ => panic!("Wrong variant"),
        }
    }
}
