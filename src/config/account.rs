use serde::{de, Deserialize, Deserializer};
use serde_derive::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct Account {
	pub(in crate::config) contacts: Vec<AccountContact>,
	#[serde(default)]
	pub(in crate::config) env: HashMap<String, String>,
	pub(in crate::config) external_account: Option<ExternalAccount>,
	#[serde(default)]
	pub(in crate::config) hooks: Vec<String>,
	#[serde(default)]
	pub(in crate::config) key_type: AccountKeyType,
	pub(in crate::config) name: String,
	#[serde(default)]
	pub(in crate::config) signature_algorithm: Option<AccountSignatureAlgorithm>,
}

impl<'de> Deserialize<'de> for Account {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = Account::deserialize(deserializer)?;
		if unchecked.contacts.is_empty() {
			return Err(de::Error::custom("at least one contact must be specified"));
		}
		Ok(unchecked)
	}
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccountContact {
	pub(in crate::config) mailto: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExternalAccount {
	pub(in crate::config) identifier: String,
	pub(in crate::config) key: String,
	#[serde(default)]
	pub(in crate::config) signature_algorithm: ExternalAccountSignatureAlgorithm,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum AccountKeyType {
	Ed25519,
	Ed448,
	#[default]
	EcDsaP256,
	EcDsaP384,
	EcDsaP521,
	Rsa2048,
	Rsa4096,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum AccountSignatureAlgorithm {
	Hs256,
	Hs384,
	Hs512,
	Rs256,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum ExternalAccountSignatureAlgorithm {
	#[default]
	Hs256,
	Hs384,
	Hs512,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty_account() {
		let res = load_str::<Account>("");
		assert!(res.is_err());
	}

	#[test]
	fn account_minimal() {
		let cfg = r#"
name = "test"
contacts = [
	{ mailto = "acme@example.org" }
]
"#;

		let a: Account = load_str(cfg).unwrap();
		assert_eq!(
			a.contacts,
			vec![AccountContact {
				mailto: "acme@example.org".to_string()
			}]
		);
		assert!(a.env.is_empty());
		assert!(a.external_account.is_none());
		assert!(a.hooks.is_empty());
		assert_eq!(a.key_type, AccountKeyType::EcDsaP256);
		assert_eq!(a.name, "test");
		assert!(a.signature_algorithm.is_none());
	}

	#[test]
	fn account_full() {
		let cfg = r#"
name = "test"
contacts = [
	{ mailto = "acme@example.org" }
]
env.TEST = "Test"
external_account.identifier = "toto"
external_account.key = "VGhpcyBpcyBhIHRlc3Q="
hooks = ["hook name"]
key_type = "rsa2048"
signature_algorithm = "HS512"
"#;
		let mut env = HashMap::with_capacity(2);
		env.insert("test".to_string(), "Test".to_string());
		let ea = ExternalAccount {
			identifier: "toto".to_string(),
			key: "VGhpcyBpcyBhIHRlc3Q=".to_string(),
			signature_algorithm: ExternalAccountSignatureAlgorithm::Hs256,
		};
		let a: Account = load_str(cfg).unwrap();
		assert_eq!(
			a.contacts,
			vec![AccountContact {
				mailto: "acme@example.org".to_string()
			}]
		);
		assert_eq!(a.env, env);
		assert_eq!(a.external_account, Some(ea));
		assert_eq!(a.hooks, vec!["hook name".to_string()]);
		assert_eq!(a.key_type, AccountKeyType::Rsa2048);
		assert_eq!(a.name, "test");
		assert_eq!(
			a.signature_algorithm,
			Some(AccountSignatureAlgorithm::Hs512)
		);
	}

	#[test]
	fn account_missing_name() {
		let cfg = r#"
contacts = [
	{ mailto = "acme@example.org" }
]
"#;
		let res = load_str::<Account>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn account_missing_contact() {
		let cfg = r#"name = "test""#;
		let res = load_str::<Account>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn account_empty_contact() {
		let cfg = r#"
name = "test"
contacts = []
"#;
		let res = load_str::<Account>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn empty_account_contact() {
		let res = load_str::<AccountContact>("");
		assert!(res.is_err());
	}

	#[test]
	fn account_contact_mailto() {
		let cfg = r#"mailto = "test.acme@example.org""#;
		let ac: AccountContact = load_str(cfg).unwrap();
		assert_eq!(ac.mailto, "test.acme@example.org");
	}

	#[test]
	fn empty_external_account() {
		let res = load_str::<ExternalAccount>("");
		assert!(res.is_err());
	}

	#[test]
	fn external_account_minimal() {
		let cfg = r#"
identifier = "toto"
key = "VGhpcyBpcyBhIHRlc3Q="
"#;
		let ea: ExternalAccount = load_str(cfg).unwrap();
		assert_eq!(ea.identifier, "toto");
		assert_eq!(ea.key, "VGhpcyBpcyBhIHRlc3Q=");
		assert_eq!(
			ea.signature_algorithm,
			ExternalAccountSignatureAlgorithm::Hs256
		);
	}

	#[test]
	fn external_account_full() {
		let cfg = r#"
identifier = "toto"
key = "VGhpcyBpcyBhIHRlc3Q="
signature_algorithm = "HS384"
"#;
		let ea: ExternalAccount = load_str(cfg).unwrap();
		assert_eq!(ea.identifier, "toto");
		assert_eq!(ea.key, "VGhpcyBpcyBhIHRlc3Q=");
		assert_eq!(
			ea.signature_algorithm,
			ExternalAccountSignatureAlgorithm::Hs384
		);
	}

	#[test]
	fn external_account_missing_identifier() {
		let cfg = r#"key = "VGhpcyBpcyBhIHRlc3Q=""#;
		let res = load_str::<ExternalAccount>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn external_account_missing_key() {
		let cfg = r#"identifier = "toto""#;
		let res = load_str::<ExternalAccount>(cfg);
		assert!(res.is_err());
	}
}
