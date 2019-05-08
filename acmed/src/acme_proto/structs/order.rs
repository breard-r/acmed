use crate::acme_proto::structs::{ApiError, HttpApiError};
use acme_common::error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Serialize)]
pub struct NewOrder {
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl NewOrder {
    pub fn new(domains: &[String]) -> Self {
        NewOrder {
            identifiers: domains.iter().map(|n| Identifier::new_dns(n)).collect(),
            not_before: None,
            not_after: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub error: Option<HttpApiError>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

impl ApiError for Order {
    fn get_error(&self) -> Option<Error> {
        self.error.to_owned().map(Error::from)
    }
}

deserialize_from_str!(Order);

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            OrderStatus::Pending => "pending",
            OrderStatus::Ready => "ready",
            OrderStatus::Processing => "processing",
            OrderStatus::Valid => "valid",
            OrderStatus::Invalid => "invalid",
        };
        write!(f, "{}", s)
    }
}

#[derive(Deserialize, Serialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub id_type: IdentifierType,
    pub value: String,
}

impl Identifier {
    pub fn new_dns(value: &str) -> Self {
        Identifier {
            id_type: IdentifierType::Dns,
            value: value.to_string(),
        }
    }
}

deserialize_from_str!(Identifier);

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.id_type, self.value)
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum IdentifierType {
    #[serde(rename = "dns")]
    Dns,
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            IdentifierType::Dns => "dns",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::{Identifier, IdentifierType};
    use std::str::FromStr;

    #[test]
    fn id_serialize() {
        let reference = "{\"type\":\"dns\",\"value\":\"test.example.org\"}";
        let id = Identifier {
            id_type: IdentifierType::Dns,
            value: "test.example.org".to_string(),
        };
        let id_json = serde_json::to_string(&id);
        assert!(id_json.is_ok());
        let id_json = id_json.unwrap();
        assert_eq!(id_json, reference.to_string());
    }

    #[test]
    fn id_deserialize_valid() {
        let id_str = "{\"type\":\"dns\",\"value\":\"test.example.org\"}";
        let id = Identifier::from_str(id_str);
        assert!(id.is_ok());
        let id = id.unwrap();
        assert_eq!(id.id_type, IdentifierType::Dns);
        assert_eq!(id.value, "test.example.org".to_string());
    }

    #[test]
    fn id_deserialize_invalid_type() {
        let id_str = "{\"type\":\"trololo\",\"value\":\"test.example.org\"}";
        let id = Identifier::from_str(id_str);
        assert!(id.is_err());
    }
}
