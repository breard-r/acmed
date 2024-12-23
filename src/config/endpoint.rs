use serde_derive::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
	pub file_name_format: Option<String>,
	pub name: String,
	pub random_early_renew: Option<String>,
	#[serde(default)]
	pub rate_limits: Vec<String>,
	pub renew_delay: Option<String>,
	#[serde(default)]
	pub root_certificates: Vec<PathBuf>,
	#[serde(default)]
	pub tos_agreed: bool,
	pub url: String,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty() {
		let res = load_str::<Endpoint>("");
		assert!(res.is_err());
	}

	#[test]
	fn minimal() {
		let cfg = r#"
name = "test"
url = "https://acme-v02.api.example.com/directory"
"#;

		let e: Endpoint = load_str(cfg).unwrap();
		assert!(e.file_name_format.is_none());
		assert_eq!(e.name, "test");
		assert!(e.random_early_renew.is_none());
		assert!(e.rate_limits.is_empty());
		assert!(e.renew_delay.is_none());
		assert!(e.root_certificates.is_empty());
		assert_eq!(e.tos_agreed, false);
		assert_eq!(e.url, "https://acme-v02.api.example.com/directory");
	}

	#[test]
	fn full() {
		let cfg = r#"
name = "test"
url = "https://acme-v02.api.example.com/directory"
file_name_format = "{{ key_type }} {{ file_type }} {{ name }}.{{ ext }}"
random_early_renew = "1d"
rate_limits = ["rl 1", "rl 2"]
renew_delay = "21d"
root_certificates = ["root_cert.pem"]
tos_agreed = true
"#;

		let e: Endpoint = load_str(cfg).unwrap();
		assert_eq!(
			e.file_name_format,
			Some("{{ key_type }} {{ file_type }} {{ name }}.{{ ext }}".to_string())
		);
		assert_eq!(e.name, "test");
		assert_eq!(e.random_early_renew, Some("1d".to_string()));
		assert_eq!(e.rate_limits, vec!["rl 1", "rl 2"]);
		assert_eq!(e.renew_delay, Some("21d".to_string()));
		assert_eq!(e.root_certificates, vec![PathBuf::from("root_cert.pem")]);
		assert_eq!(e.tos_agreed, true);
		assert_eq!(e.url, "https://acme-v02.api.example.com/directory");
	}

	#[test]
	fn missing_name() {
		let cfg = r#""#;

		let res = load_str::<Endpoint>(cfg);
		assert!(res.is_err());
	}
}
