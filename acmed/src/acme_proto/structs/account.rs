use crate::certificate::Certificate;
use crate::endpoint::Endpoint;
use acme_common::error::Error;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub contact: Vec<String>,
    pub terms_of_service_agreed: bool,
    pub only_return_existing: bool,
}

impl Account {
    pub fn new(cert: &Certificate, endpoint: &Endpoint) -> Self {
        Account {
            contact: vec![format!("mailto:{}", cert.account.email)],
            terms_of_service_agreed: endpoint.tos_agreed,
            only_return_existing: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub status: String,
    pub contact: Option<Vec<String>>,
    pub terms_of_service_agreed: Option<bool>,
    pub external_account_binding: Option<String>,
    pub orders: Option<String>,
}

deserialize_from_str!(AccountResponse);

// TODO: implement account update
#[allow(dead_code)]
#[derive(Serialize)]
pub struct AccountUpdate {
    pub contact: Vec<String>,
}

impl AccountUpdate {
    #[allow(dead_code)]
    pub fn new(contact: &[String]) -> Self {
        AccountUpdate {
            contact: contact.into(),
        }
    }
}

// TODO: implement account deactivation
#[allow(dead_code)]
#[derive(Serialize)]
pub struct AccountDeactivation {
    pub status: String,
}

impl AccountDeactivation {
    #[allow(dead_code)]
    pub fn new() -> Self {
        AccountDeactivation {
            status: "deactivated".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_new() {
        let emails = vec![
            "mailto:derp@example.com".to_string(),
            "mailto:derp.derpson@example.com".to_string(),
        ];
        let a = Account {
            contact: emails,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        assert_eq!(a.contact.len(), 2);
        assert_eq!(a.terms_of_service_agreed, true);
        assert_eq!(a.only_return_existing, false);
        let a_str = serde_json::to_string(&a);
        assert!(a_str.is_ok());
        let a_str = a_str.unwrap();
        assert!(a_str.starts_with("{"));
        assert!(a_str.ends_with("}"));
        assert!(a_str.contains("\"contact\""));
        assert!(a_str.contains("\"mailto:derp@example.com\""));
        assert!(a_str.contains("\"mailto:derp.derpson@example.com\""));
        assert!(a_str.contains("\"termsOfServiceAgreed\""));
        assert!(a_str.contains("\"onlyReturnExisting\""));
        assert!(a_str.contains("true"));
        assert!(a_str.contains("false"));
    }

    #[test]
    fn test_account_response() {
        let data = "{
  \"status\": \"valid\",
  \"contact\": [
    \"mailto:cert-admin@example.org\",
    \"mailto:admin@example.org\"
  ],
  \"termsOfServiceAgreed\": true,
  \"orders\": \"https://example.com/acme/orders/rzGoeA\"
}";
        let account_resp = AccountResponse::from_str(data);
        assert!(account_resp.is_ok());
        let account_resp = account_resp.unwrap();
        assert_eq!(account_resp.status, "valid");
        assert!(account_resp.contact.is_some());
        let contacts = account_resp.contact.unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0], "mailto:cert-admin@example.org");
        assert_eq!(contacts[1], "mailto:admin@example.org");
        assert!(account_resp.external_account_binding.is_none());
        assert!(account_resp.terms_of_service_agreed.is_some());
        assert!(account_resp.terms_of_service_agreed.unwrap());
        assert_eq!(
            account_resp.orders,
            Some("https://example.com/acme/orders/rzGoeA".into())
        );
    }

    #[test]
    fn test_account_update() {
        let emails = vec![
            "mailto:derp@example.com".to_string(),
            "mailto:derp.derpson@example.com".to_string(),
        ];
        let au = AccountUpdate::new(&emails);
        assert_eq!(au.contact.len(), 2);
        let au_str = serde_json::to_string(&au);
        assert!(au_str.is_ok());
        let au_str = au_str.unwrap();
        assert!(au_str.starts_with("{"));
        assert!(au_str.ends_with("}"));
        assert!(au_str.contains("\"contact\""));
        assert!(au_str.contains("\"mailto:derp@example.com\""));
        assert!(au_str.contains("\"mailto:derp.derpson@example.com\""));
    }

    #[test]
    fn test_account_deactivation() {
        let ad = AccountDeactivation::new();
        assert_eq!(ad.status, "deactivated");
        let ad_str = serde_json::to_string(&ad);
        assert!(ad_str.is_ok());
        let ad_str = ad_str.unwrap();
        assert!(ad_str.starts_with("{"));
        assert!(ad_str.ends_with("}"));
        assert!(ad_str.contains("\"status\""));
        assert!(ad_str.contains("\"deactivated\""));
    }
}
