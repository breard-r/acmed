use serde_derive::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalOptions {
	#[serde(default = "get_default_accounts_directory")]
	pub(in crate::config) accounts_directory: PathBuf,
	pub(in crate::config) cert_file_group: Option<String>,
	pub(in crate::config) cert_file_mode: Option<u32>,
	pub(in crate::config) cert_file_user: Option<String>,
	#[serde(default = "get_default_cert_file_ext")]
	pub(in crate::config) cert_file_ext: String,
	#[serde(default = "get_default_certificates_directory")]
	pub(in crate::config) certificates_directory: PathBuf,
	#[serde(default)]
	pub(in crate::config) env: HashMap<String, String>,
	#[serde(default = "get_default_file_name_format")]
	pub(in crate::config) file_name_format: String,
	pub(in crate::config) pk_file_group: Option<String>,
	pub(in crate::config) pk_file_mode: Option<u32>,
	pub(in crate::config) pk_file_user: Option<String>,
	#[serde(default = "get_default_pk_file_ext")]
	pub(in crate::config) pk_file_ext: String,
	pub(in crate::config) random_early_renew: Option<String>,
	#[serde(default = "get_default_renew_delay")]
	pub(in crate::config) renew_delay: String,
	#[serde(default)]
	pub(in crate::config) root_certificates: Vec<PathBuf>,
}

fn get_default_lib_dir() -> PathBuf {
	let mut path = match option_env!("VARLIBDIR") {
		Some(s) => PathBuf::from(s),
		None => PathBuf::from("/var/lib"),
	};
	path.push("acmed");
	path
}

fn get_default_accounts_directory() -> PathBuf {
	let mut path = get_default_lib_dir();
	path.push("accounts");
	path
}

fn get_default_cert_file_ext() -> String {
	"pem".to_string()
}

fn get_default_certificates_directory() -> PathBuf {
	let mut path = get_default_lib_dir();
	path.push("certs");
	path
}

fn get_default_file_name_format() -> String {
	"{{ name }}_{{ key_type }}.{{ file_type }}.{{ ext }}".to_string()
}

fn get_default_pk_file_ext() -> String {
	"pem".to_string()
}

fn get_default_renew_delay() -> String {
	"30d".to_string()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty() {
		let go: GlobalOptions = load_str("").unwrap();
		assert_eq!(go.accounts_directory, get_default_accounts_directory());
		assert!(go.cert_file_group.is_none());
		assert!(go.cert_file_mode.is_none());
		assert!(go.cert_file_user.is_none());
		assert_eq!(go.cert_file_ext, get_default_cert_file_ext());
		assert_eq!(
			go.certificates_directory,
			get_default_certificates_directory()
		);
		assert!(go.env.is_empty());
		assert_eq!(go.file_name_format, get_default_file_name_format());
		assert!(go.pk_file_group.is_none());
		assert!(go.pk_file_mode.is_none());
		assert!(go.pk_file_user.is_none());
		assert_eq!(go.pk_file_ext, get_default_pk_file_ext());
		assert!(go.random_early_renew.is_none());
		assert_eq!(go.renew_delay, get_default_renew_delay());
		assert!(go.root_certificates.is_empty());
	}

	#[test]
	fn full() {
		let cfg = r#"
accounts_directory = "/tmp/accounts"
cert_file_group = "acme_test"
cert_file_mode = 0o644
cert_file_user = "acme_test"
cert_file_ext = "pem.txt"
certificates_directory = "/tmp/certs"
env.HTTP_ROOT = "/srv/http"
env.TEST = "Test"
file_name_format = "{{ key_type }} {{ file_type }} {{ name }}.{{ ext }}"
pk_file_group = "acme_test"
pk_file_mode = 0o644
pk_file_user = "acme_test"
pk_file_ext = "pem.txt"
random_early_renew = "2d"
renew_delay = "21d"
root_certificates = ["root_cert.pem"]
"#;

		let mut env = HashMap::with_capacity(2);
		env.insert("test".to_string(), "Test".to_string());
		env.insert("http_root".to_string(), "/srv/http".to_string());
		let go: GlobalOptions = load_str(cfg).unwrap();
		assert_eq!(go.accounts_directory, PathBuf::from("/tmp/accounts"));
		assert_eq!(go.cert_file_group, Some("acme_test".to_string()));
		assert_eq!(go.cert_file_mode, Some(0o644));
		assert_eq!(go.cert_file_user, Some("acme_test".to_string()));
		assert_eq!(go.cert_file_ext, "pem.txt");
		assert_eq!(go.certificates_directory, PathBuf::from("/tmp/certs"));
		assert_eq!(go.env, env);
		assert_eq!(
			go.file_name_format,
			"{{ key_type }} {{ file_type }} {{ name }}.{{ ext }}"
		);
		assert_eq!(go.pk_file_group, Some("acme_test".to_string()));
		assert_eq!(go.pk_file_mode, Some(0o644));
		assert_eq!(go.pk_file_user, Some("acme_test".to_string()));
		assert_eq!(go.pk_file_ext, "pem.txt");
		assert_eq!(go.random_early_renew, Some("2d".to_string()));
		assert_eq!(go.renew_delay, "21d");
		assert_eq!(go.root_certificates, vec![PathBuf::from("root_cert.pem")]);
	}
}
