use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use strum_macros;

/// Represents a single audit rule loaded from a YAML or JSON file.
#[derive(Debug, Deserialize, Clone)]
pub struct AuditRule {
    /// Unique identifier for the rule
    pub id: String,
    /// Description of the rule
    pub description: String,
    /// Criteria expression for the rule
    pub criteria: CriteriaExpr,
    /// Severity level (e.g., info, low, medium, high)
    pub severity: String,
    /// List of OS (e.g., `linux`, `windows`) this rule applies to. If None or empty, applies to all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<Vec<String>>,
}

/// Supported operators for criteria evaluation.
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    strum_macros::EnumString,
    strum_macros::AsRefStr,
    strum_macros::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum CriteriaOperator {
    /// Equality operator
    Equals,
    /// Not equal operator
    Not,
    /// Matches any value in a list
    Matches,
    /// String starts with
    StartsWith,
    /// String ends with
    EndsWith,
    /// String contains
    Contains,
    /// Regex match
    Regex,
    /// Wildcard match
    Wildcard,
    /// Number in range (list of 2 numbers)
    InRange,
    /// Less than
    Lt,
    /// Less than or equal
    Lte,
    /// Greater than
    Gt,
    /// Greater than or equal
    Gte,
    /// IP/network CIDR match
    Cidr,
    /// Is null
    IsNull,
    /// Application exists (Windows only)
    ApplicationExists,
    /// Service exists (Windows only)
    ServiceExists,
}

/// Criteria expression (group, or, not, or condition)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum CriteriaExpr {
    /// AND group
    Group {
        /// List of sub-expressions (all must match)
        and: Vec<CriteriaExpr>,
    },
    /// OR group
    OrGroup {
        /// List of sub-expressions (any must match)
        or: Vec<CriteriaExpr>,
    },
    /// NOT group
    NotGroup {
        /// Sub-expression to negate
        not: Box<CriteriaExpr>,
    },
    /// Single condition
    Condition(CriteriaCondition),
}

/// A single condition in a criteria expression.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CriteriaCondition {
    /// Field name to test
    pub field: String,
    /// Operator as raw string (parsed to `CriteriaOperator`)
    #[serde(rename = "operator")]
    pub operator_raw: String,
    /// Value to compare (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Parsed operator (set by `parse_operator`)
    #[serde(skip)]
    pub operator: Option<CriteriaOperator>,
}

impl CriteriaCondition {
    /// Parse the `operator_raw` string into the operator enum.
    pub fn parse_operator(&mut self) {
        self.operator = self.operator_raw.parse::<CriteriaOperator>().ok();
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use crate::CriteriaOperator;

    #[test]
    fn test_expected_type_all_variants() {
        for op in CriteriaOperator::iter() {
            let t = op.expected_type();
            assert!(
                !t.is_empty(),
                "expected_type for {:?} should not be empty",
                op
            );
        }
    }
}
