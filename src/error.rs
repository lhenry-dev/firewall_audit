use thiserror::Error;

#[derive(Error, Debug)]
pub enum FirewallAuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parsing error: {0}")]
    YamlParse(#[from] serde_yaml::Error),

    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Rule at index {index} has invalid structure: {message}")]
    InvalidRuleStructure { index: usize, message: String },

    #[error("Unknown operator '{operator}' at {path}")]
    UnknownOperator { operator: String, path: String },

    #[error("Unknown field '{field}' at {path}")]
    UnknownField { field: String, path: String },

    #[error("Invalid value for operator '{operator}' at {path}: {message}")]
    InvalidOperatorValue {
        operator: String,
        path: String,
        message: String,
    },

    #[error("Unsupported file format or parsing failed for: {path}")]
    UnsupportedFileFormat { path: String },

    #[error("Failed to retrieve Windows Firewall rules: {0}")]
    WindowsFirewallError(String),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

pub type Result<T> = std::result::Result<T, FirewallAuditError>;

impl FirewallAuditError {
    pub fn invalid_rule_structure(index: usize, message: impl Into<String>) -> Self {
        Self::InvalidRuleStructure {
            index,
            message: message.into(),
        }
    }

    pub fn unknown_operator(operator: impl Into<String>, path: impl Into<String>) -> Self {
        Self::UnknownOperator {
            operator: operator.into(),
            path: path.into(),
        }
    }

    pub fn unknown_field(field: impl Into<String>, path: impl Into<String>) -> Self {
        Self::UnknownField {
            field: field.into(),
            path: path.into(),
        }
    }

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
