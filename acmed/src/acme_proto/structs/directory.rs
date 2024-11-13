use acme_common::error::Error;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DirectoryMeta {
	pub terms_of_service: Option<String>,
	pub website: Option<String>,
	pub caa_identities: Option<Vec<String>>,
	pub external_account_required: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
	#[allow(dead_code)]
	pub meta: Option<DirectoryMeta>,
	pub new_nonce: String,
	pub new_account: String,
	pub new_order: String,
	#[allow(dead_code)]
	pub new_authz: Option<String>,
	#[allow(dead_code)]
	pub revoke_cert: String,
	pub key_change: String,
}

deserialize_from_str!(Directory);

#[cfg(test)]
mod tests {
	use super::Directory;
	use std::str::FromStr;

	#[test]
	fn test_directory() {
		let data = "{
	\"newAccount\": \"https://example.org/acme/new-acct\",
	\"newNonce\": \"https://example.org/acme/new-nonce\",
	\"newOrder\": \"https://example.org/acme/new-order\",
	\"revokeCert\": \"https://example.org/acme/revoke-cert\",
	\"newAuthz\": \"https://example.org/acme/new-authz\",
	\"keyChange\": \"https://example.org/acme/key-change\"
}";
		let parsed_dir = Directory::from_str(data);
		assert!(parsed_dir.is_ok());
		let parsed_dir = parsed_dir.unwrap();
		assert_eq!(parsed_dir.new_nonce, "https://example.org/acme/new-nonce");
		assert_eq!(parsed_dir.new_account, "https://example.org/acme/new-acct");
		assert_eq!(parsed_dir.new_order, "https://example.org/acme/new-order");
		assert_eq!(
			parsed_dir.new_authz,
			Some("https://example.org/acme/new-authz".to_string())
		);
		assert_eq!(
			parsed_dir.revoke_cert,
			"https://example.org/acme/revoke-cert"
		);
		assert_eq!(parsed_dir.key_change, "https://example.org/acme/key-change");
		assert!(parsed_dir.meta.is_none());
	}

	#[test]
	fn test_directory_no_authz() {
		let data = "{
	\"newAccount\": \"https://example.org/acme/new-acct\",
	\"newNonce\": \"https://example.org/acme/new-nonce\",
	\"newOrder\": \"https://example.org/acme/new-order\",
	\"revokeCert\": \"https://example.org/acme/revoke-cert\",
	\"keyChange\": \"https://example.org/acme/key-change\"
}";
		let parsed_dir = Directory::from_str(data);
		assert!(parsed_dir.is_ok());
		let parsed_dir = parsed_dir.unwrap();
		assert_eq!(parsed_dir.new_nonce, "https://example.org/acme/new-nonce");
		assert_eq!(parsed_dir.new_account, "https://example.org/acme/new-acct");
		assert_eq!(parsed_dir.new_order, "https://example.org/acme/new-order");
		assert!(parsed_dir.new_authz.is_none());
		assert_eq!(
			parsed_dir.revoke_cert,
			"https://example.org/acme/revoke-cert"
		);
		assert_eq!(parsed_dir.key_change, "https://example.org/acme/key-change");
		assert!(parsed_dir.meta.is_none());
	}

	#[test]
	fn test_directory_meta() {
		let data = "{
	\"keyChange\": \"https://example.org/acme/key-change\",
	\"meta\": {
		\"caaIdentities\": [
			\"example.org\"
		],
		\"termsOfService\": \"https://example.org/documents/tos.pdf\",
		\"website\": \"https://example.org/\"
	},
	\"newAccount\": \"https://example.org/acme/new-acct\",
	\"newNonce\": \"https://example.org/acme/new-nonce\",
	\"newOrder\": \"https://example.org/acme/new-order\",
	\"revokeCert\": \"https://example.org/acme/revoke-cert\"
}";
		let parsed_dir = Directory::from_str(&data);
		assert!(parsed_dir.is_ok());
		let parsed_dir = parsed_dir.unwrap();
		assert!(parsed_dir.meta.is_some());
		let meta = parsed_dir.meta.unwrap();
		assert_eq!(
			meta.terms_of_service,
			Some("https://example.org/documents/tos.pdf".to_string())
		);
		assert_eq!(meta.website, Some("https://example.org/".to_string()));
		assert!(meta.caa_identities.is_some());
		let caa_identities = meta.caa_identities.unwrap();
		assert_eq!(caa_identities.len(), 1);
		assert_eq!(caa_identities.first(), Some(&"example.org".to_string()));
		assert!(meta.external_account_required.is_none());
	}

	#[test]
	fn test_directory_extra_fields() {
		let data = "{
	\"foo\": \"bar\",
	\"keyChange\": \"https://example.org/acme/key-change\",
	\"newAccount\": \"https://example.org/acme/new-acct\",
	\"baz\": \"quz\",
	\"newNonce\": \"https://example.org/acme/new-nonce\",
	\"newAuthz\": \"https://example.org/acme/new-authz\",
	\"newOrder\": \"https://example.org/acme/new-order\",
	\"revokeCert\": \"https://example.org/acme/revoke-cert\"
}";
		let parsed_dir = Directory::from_str(&data);
		assert!(parsed_dir.is_ok());
		let parsed_dir = parsed_dir.unwrap();
		assert_eq!(parsed_dir.new_nonce, "https://example.org/acme/new-nonce");
		assert_eq!(parsed_dir.new_account, "https://example.org/acme/new-acct");
		assert_eq!(parsed_dir.new_order, "https://example.org/acme/new-order");
		assert_eq!(
			parsed_dir.new_authz,
			Some("https://example.org/acme/new-authz".to_string())
		);
		assert_eq!(
			parsed_dir.revoke_cert,
			"https://example.org/acme/revoke-cert"
		);
		assert_eq!(parsed_dir.key_change, "https://example.org/acme/key-change");
		assert!(parsed_dir.meta.is_none());
	}
}
