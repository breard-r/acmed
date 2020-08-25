use acme_common::crypto::{JwsSignatureAlgorithm, KeyType};
use acme_common::error::Error;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Account {
    pub name: String,
    pub email: String,
    pub key_type: KeyType,
    pub signature_algorithm: JwsSignatureAlgorithm,
}

impl Account {
    pub fn new(
        name: &str,
        email: &str,
        key_type: &Option<String>,
        signature_algorithm: &Option<String>,
    ) -> Result<Self, Error> {
        let key_type = match key_type {
            Some(kt) => KeyType::from_str(&kt)?,
            None => crate::DEFAULT_ACCOUNT_KEY_TYPE,
        };
        let signature_algorithm = match signature_algorithm {
            Some(sa) => JwsSignatureAlgorithm::from_str(&sa)?,
            None => key_type.get_default_signature_alg(),
        };
        Ok(crate::account::Account {
            name: name.to_string(),
            email: email.to_string(),
            key_type,
            signature_algorithm,
        })
    }
}
