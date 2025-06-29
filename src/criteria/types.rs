use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Debug, Deserialize)]
pub struct AuditRule {
    pub id: String,
    pub description: String,
    pub criterias: CriteriaExpr,
    pub severity: String,
}

#[derive(Debug, Clone, Copy, strum_macros::EnumString, strum_macros::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum CriteriaOperator {
    // Any type
    Equals,
    Not,
    Matches, // any (true if any value matches any in the list)
    // String operators
    StartsWith,
    EndsWith,
    Contains,
    Regex,
    Wildcard,
    // Number operators
    InRange, // number, list of 2 numbers
    Lt,
    Lte,
    Gt,
    Gte,
    // IP/network operators
    Cidr, // string (IP or CIDR)
    // Boolean/null
    IsNull,
    // Existence
    ApplicationExists,
    ServiceExists,
}

impl CriteriaCondition {
    pub fn parse_operator(&mut self) {
        self.operator = self.operator_raw.parse::<CriteriaOperator>().ok();
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum CriteriaExpr {
    Group { and: Vec<CriteriaExpr> },
    OrGroup { or: Vec<CriteriaExpr> },
    NotGroup { not: Box<CriteriaExpr> },
    Condition(CriteriaCondition),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CriteriaCondition {
    pub field: String,
    #[serde(rename = "operator")]
    pub operator_raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip)]
    pub operator: Option<CriteriaOperator>,
}
