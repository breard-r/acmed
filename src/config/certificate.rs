use crate::config::Duration;
use anyhow::Result;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct Certificate {
	pub(in crate::config) account: String,
	#[serde(default)]
	pub(in crate::config) csr_digest: CsrDigest,
	pub(in crate::config) directory: Option<PathBuf>,
	pub(in crate::config) endpoint: String,
	#[serde(default)]
	pub(in crate::config) env: HashMap<String, String>,
	pub(in crate::config) file_name_format: Option<String>,
	pub(in crate::config) hooks: Vec<String>,
	pub(in crate::config) identifiers: Vec<Identifier>,
	#[serde(default)]
	pub(in crate::config) key_type: KeyType,
	#[serde(default)]
	pub(in crate::config) kp_reuse: bool,
	pub(in crate::config) name: Option<String>,
	pub(in crate::config) random_early_renew: Option<Duration>,
	pub(in crate::config) renew_delay: Option<Duration>,
	#[serde(default)]
	pub(in crate::config) subject_attributes: SubjectAttributes,
}

impl<'de> Deserialize<'de> for Certificate {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = Certificate::deserialize(deserializer)?;
		if unchecked.hooks.is_empty() {
			return Err(de::Error::custom("at least one hook must be specified"));
		}
		if unchecked.identifiers.is_empty() {
			return Err(de::Error::custom(
				"at least one identifier must be specified",
			));
		}
		Ok(unchecked)
	}
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum CsrDigest {
	#[default]
	Sha256,
	Sha384,
	Sha512,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct Identifier {
	pub(in crate::config) challenge: AcmeChallenge,
	pub(in crate::config) dns: Option<String>,
	#[serde(default)]
	pub(in crate::config) env: HashMap<String, String>,
	pub(in crate::config) ip: Option<String>,
}

impl<'de> Deserialize<'de> for Identifier {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = Identifier::deserialize(deserializer)?;
		let filled_nb: u8 = [unchecked.dns.is_some(), unchecked.ip.is_some()]
			.iter()
			.copied()
			.map(u8::from)
			.sum();
		if filled_nb != 1 {
			return Err(de::Error::custom(
				"one and only one of `dns` or `ip` must be specified",
			));
		}
		Ok(unchecked)
	}
}

impl fmt::Display for Identifier {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let s = String::new();
		let msg = self.dns.as_ref().or(self.ip.as_ref()).unwrap_or(&s);
		write!(f, "{msg}")
	}
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum AcmeChallenge {
	#[serde(rename = "dns-01")]
	Dns01,
	#[serde(rename = "http-01")]
	Http01,
	#[serde(rename = "tls-alpn-01")]
	TlsAlpn01,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum KeyType {
	#[serde(rename = "ed25519")]
	Ed25519,
	#[serde(rename = "ed448")]
	Ed448,
	#[serde(rename = "ecdsa_p256")]
	EcDsaP256,
	#[serde(rename = "ecdsa_p384")]
	EcDsaP384,
	#[serde(rename = "ecdsa_p521")]
	EcDsaP521,
	#[default]
	#[serde(rename = "rsa2048")]
	Rsa2048,
	#[serde(rename = "rsa4096")]
	Rsa4096,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectAttributes {
	pub(in crate::config) country_name: Option<String>,
	pub(in crate::config) generation_qualifier: Option<String>,
	pub(in crate::config) given_name: Option<String>,
	pub(in crate::config) initials: Option<String>,
	pub(in crate::config) locality_name: Option<String>,
	pub(in crate::config) name: Option<String>,
	pub(in crate::config) organization_name: Option<String>,
	pub(in crate::config) organizational_unit_name: Option<String>,
	pub(in crate::config) pkcs9_email_address: Option<String>,
	pub(in crate::config) postal_address: Option<String>,
	pub(in crate::config) postal_code: Option<String>,
	pub(in crate::config) state_or_province_name: Option<String>,
	pub(in crate::config) street: Option<String>,
	pub(in crate::config) surname: Option<String>,
	pub(in crate::config) title: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty_certificate() {
		let res = load_str::<Certificate>("");
		assert!(res.is_err());
	}

	#[test]
	fn cert_minimal() {
		let cfg = r#"
account = "test"
endpoint = "dummy"
hooks = ["hook 01"]
identifiers = [
	{ dns = "example.org", challenge = "http-01"},
]
"#;
		let c = load_str::<Certificate>(cfg).unwrap();
		assert_eq!(c.account, "test");
		assert_eq!(c.csr_digest, CsrDigest::Sha256);
		assert!(c.directory.is_none());
		assert_eq!(c.endpoint, "dummy");
		assert!(c.env.is_empty());
		assert!(c.file_name_format.is_none());
		assert_eq!(c.hooks, vec!["hook 01".to_string()]);
		assert_eq!(c.identifiers.len(), 1);
		assert_eq!(c.key_type, KeyType::Rsa2048);
		assert_eq!(c.kp_reuse, false);
		assert!(c.name.is_none());
		assert!(c.random_early_renew.is_none());
		assert!(c.renew_delay.is_none());
	}

	#[test]
	fn cert_full() {
		let cfg = r#"
account = "test"
csr_digest = "sha512"
directory = "/tmp/certs"
endpoint = "dummy"
env.TEST = "some env"
file_name_format = "test.pem"
hooks = ["hook 01"]
identifiers = [
	{ dns = "example.org", challenge = "http-01"},
]
key_type = "ecdsa_p256"
kp_reuse = true
name = "test"
random_early_renew = "1d"
renew_delay = "30d"
subject_attributes.country_name = "FR"
subject_attributes.organization_name = "ACME Inc."
"#;
		let c = load_str::<Certificate>(cfg).unwrap();
		assert_eq!(c.account, "test");
		assert_eq!(c.csr_digest, CsrDigest::Sha512);
		assert_eq!(c.directory, Some(PathBuf::from("/tmp/certs")));
		assert_eq!(c.endpoint, "dummy");
		assert_eq!(c.env.len(), 1);
		assert_eq!(c.file_name_format, Some("test.pem".to_string()));
		assert_eq!(c.hooks, vec!["hook 01".to_string()]);
		assert_eq!(c.identifiers.len(), 1);
		assert_eq!(c.key_type, KeyType::EcDsaP256);
		assert_eq!(c.kp_reuse, true);
		assert_eq!(c.name, Some("test".to_string()));
		assert_eq!(c.random_early_renew, Some(Duration::from_days(1)));
		assert_eq!(c.renew_delay, Some(Duration::from_days(30)));
		assert_eq!(c.subject_attributes.country_name, Some("FR".to_string()));
		assert!(c.subject_attributes.generation_qualifier.is_none());
		assert!(c.subject_attributes.given_name.is_none());
		assert!(c.subject_attributes.initials.is_none());
		assert!(c.subject_attributes.locality_name.is_none());
		assert!(c.subject_attributes.name.is_none());
		assert_eq!(
			c.subject_attributes.organization_name,
			Some("ACME Inc.".to_string())
		);
		assert!(c.subject_attributes.organizational_unit_name.is_none());
		assert!(c.subject_attributes.pkcs9_email_address.is_none());
		assert!(c.subject_attributes.postal_address.is_none());
		assert!(c.subject_attributes.postal_code.is_none());
		assert!(c.subject_attributes.state_or_province_name.is_none());
		assert!(c.subject_attributes.street.is_none());
		assert!(c.subject_attributes.surname.is_none());
		assert!(c.subject_attributes.title.is_none());
	}

	#[test]
	fn cert_empty_hooks() {
		let cfg = r#"
account = "test"
endpoint = "dummy"
hooks = []
identifiers = [
	{ dns = "example.org", challenge = "http-01"},
]
"#;
		let res = load_str::<Certificate>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn cert_empty_identifiers() {
		let cfg = r#"
account = "test"
endpoint = "dummy"
hooks = ["hook 01"]
identifiers = []
"#;
		let res = load_str::<Certificate>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn empty_identifier() {
		let res = load_str::<Identifier>("");
		assert!(res.is_err());
	}

	#[test]
	fn identifier_dns() {
		let cfg = r#"
challenge = "dns-01"
dns = "example.org"
"#;
		let i = load_str::<Identifier>(cfg).unwrap();
		assert_eq!(i.challenge, AcmeChallenge::Dns01);
		assert_eq!(i.dns, Some("example.org".to_string()));
		assert!(i.env.is_empty());
		assert!(i.ip.is_none());
	}

	#[test]
	fn identifier_ipv4() {
		let cfg = r#"
challenge = "http-01"
ip = "203.0.113.42"
"#;
		let i = load_str::<Identifier>(cfg).unwrap();
		assert_eq!(i.challenge, AcmeChallenge::Http01);
		assert!(i.dns.is_none());
		assert!(i.env.is_empty());
		assert_eq!(i.ip, Some("203.0.113.42".to_string()));
	}

	#[test]
	fn identifier_ipv6() {
		let cfg = r#"
challenge = "tls-alpn-01"
ip = "2001:db8::42"
"#;
		let i = load_str::<Identifier>(cfg).unwrap();
		assert_eq!(i.challenge, AcmeChallenge::TlsAlpn01);
		assert!(i.dns.is_none());
		assert!(i.env.is_empty());
		assert_eq!(i.ip, Some("2001:db8::42".to_string()));
	}

	#[test]
	fn identifier_dns_and_ip() {
		let cfg = r#"
challenge = "http-01"
dns = "example.org"
ip = "203.0.113.42"
"#;
		let res = load_str::<Identifier>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn identifier_missing_challenge() {
		let cfg = r#"ip = "2001:db8::42""#;
		let res = load_str::<Identifier>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn identifier_missing_dns_and_ip() {
		let cfg = r#"challenge = "http-01""#;
		let res = load_str::<Identifier>(cfg);
		assert!(res.is_err());
	}
}
