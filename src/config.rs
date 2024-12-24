mod account;
mod certificate;
mod duration;
mod endpoint;
mod global;
mod hook;
mod rate_limit;

pub use account::*;
pub use certificate::*;
pub use duration::*;
pub use endpoint::*;
pub use global::*;
pub use hook::*;
pub use rate_limit::*;

use anyhow::{Context, Result};
use config::{Config, File};
use serde::{de, Deserialize, Deserializer};
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const ALLOWED_FILE_EXT: &[&str] = &["toml"];

#[derive(Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct AcmedConfig {
	pub(in crate::config) global: Option<GlobalOptions>,
	#[serde(default)]
	pub(in crate::config) endpoint: HashMap<String, Endpoint>,
	#[serde(default, rename = "rate-limit")]
	pub(in crate::config) rate_limit: HashMap<String, RateLimit>,
	#[serde(default)]
	pub(in crate::config) hook: HashMap<String, Hook>,
	#[serde(default)]
	pub(in crate::config) group: HashMap<String, Vec<String>>,
	#[serde(default)]
	pub(in crate::config) account: HashMap<String, Account>,
	#[serde(default)]
	pub(in crate::config) certificate: Vec<Certificate>,
}

impl<'de> Deserialize<'de> for AcmedConfig {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = AcmedConfig::deserialize(deserializer)?;
		for key in unchecked.hook.keys() {
			if key.starts_with(crate::INTERNAL_HOOK_PREFIX) {
				return Err(de::Error::custom(format!("{key}: invalid hook name")));
			}
		}
		for key in unchecked.group.keys() {
			if key.starts_with(crate::INTERNAL_HOOK_PREFIX) {
				return Err(de::Error::custom(format!("{key}: invalid group name")));
			}
		}
		Ok(unchecked)
	}
}

pub fn load<P: AsRef<Path>>(config_dir: P) -> Result<AcmedConfig> {
	let config_dir = config_dir.as_ref();
	tracing::debug!("loading config directory: {config_dir:?}");
	let settings = Config::builder()
		.add_source(
			get_files(config_dir)?
				.iter()
				.map(|path| File::from(path.as_path()))
				.collect::<Vec<_>>(),
		)
		.build()?;
	tracing::trace!("loaded config: {settings:?}");
	let config: AcmedConfig = settings.try_deserialize().context("invalid setting")?;
	tracing::debug!("computed config: {config:?}");
	Ok(config)
}

fn get_files(config_dir: &Path) -> Result<Vec<PathBuf>> {
	let mut file_lst = Vec::new();
	for entry in WalkDir::new(config_dir).follow_links(true) {
		let path = entry?.path().to_path_buf();
		if path.is_file() {
			if let Some(ext) = path.extension() {
				if ALLOWED_FILE_EXT.iter().any(|&e| e == ext) {
					std::fs::File::open(&path).with_context(|| path.display().to_string())?;
					file_lst.push(path);
				}
			}
		}
	}
	file_lst.sort();
	tracing::debug!("configuration files found: {file_lst:?}");
	Ok(file_lst)
}

#[cfg(test)]
fn load_str<'de, T: serde::de::Deserialize<'de>>(config_str: &str) -> Result<T> {
	let settings = Config::builder()
		.add_source(File::from_str(config_str, config::FileFormat::Toml))
		.build()?;
	let config: T = settings.try_deserialize().context("invalid setting")?;
	Ok(config)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty() {
		let cfg = load("tests/config/empty").unwrap();
		assert!(cfg.global.is_none());
		assert!(cfg.rate_limit.is_empty());
		assert!(cfg.endpoint.is_empty());
		assert!(cfg.hook.is_empty());
		assert!(cfg.group.is_empty());
		assert!(cfg.account.is_empty());
		assert!(cfg.certificate.is_empty());
	}

	#[test]
	fn simple() {
		let cfg = load("tests/config/simple").unwrap();
		assert!(cfg.global.is_some());
		let global = cfg.global.unwrap();
		assert_eq!(
			global.accounts_directory,
			PathBuf::from("/tmp/example/account/dir")
		);
		assert_eq!(
			global.certificates_directory,
			PathBuf::from("/tmp/example/cert/dir")
		);
		assert_eq!(cfg.rate_limit.len(), 1);
		let rl = cfg.rate_limit.get("my-ca-limit").unwrap();
		assert_eq!(rl.number, 20);
		assert_eq!(rl.period, Duration::from_secs(1));
		assert_eq!(cfg.endpoint.len(), 1);
		let ep = cfg.endpoint.get("my-ca").unwrap();
		assert_eq!(ep.url, "https://acme-v02.ac1.example.org/directory");
		assert_eq!(ep.rate_limits, vec!["my-ca-limit".to_string()]);
		assert_eq!(ep.tos_agreed, true);
		assert_eq!(cfg.hook.len(), 2);
		let h1 = cfg.hook.get("hook-1").unwrap();
		assert_eq!(h1.cmd, "cat");
		assert!(h1.args.is_empty());
		assert_eq!(h1.hook_type, vec![HookType::FilePreEdit]);
		let h2 = cfg.hook.get("hook-2").unwrap();
		assert_eq!(h2.cmd, "cat");
		assert_eq!(h2.args, vec!["-e".to_string()]);
		assert_eq!(h2.hook_type, vec![HookType::FilePreEdit]);
		assert_eq!(cfg.group.len(), 1);
		let g1 = cfg.group.get("super-hook").unwrap();
		assert_eq!(*g1, vec!["hook-1".to_string(), "hook-2".to_string()]);
		assert_eq!(cfg.account.len(), 1);
		let account = cfg.account.get("toto").unwrap();
		assert_eq!(account.contacts.len(), 1);
		assert!(account.env.is_empty());
		assert!(account.external_account.is_none());
		assert!(account.hooks.is_empty());
		assert_eq!(account.key_type, AccountKeyType::EcDsaP256);
		assert_eq!(
			account.signature_algorithm,
			Some(AccountSignatureAlgorithm::Hs384)
		);
		assert_eq!(cfg.certificate.len(), 1);
		let c = cfg.certificate.first().unwrap();
		assert_eq!(c.account, "toto");
		assert_eq!(c.endpoint, "my-ca");
		assert_eq!(c.identifiers.len(), 1);
		let i = c.identifiers.first().unwrap();
		assert_eq!(i.dns, Some("example.org".to_string()));
		assert_eq!(i.challenge, AcmeChallenge::Http01);
		assert_eq!(c.hooks, vec!["super-hook".to_string()]);
	}

	#[test]
	fn setting_override() {
		let cfg = load("tests/config/override").unwrap();
		assert!(cfg.global.is_some());
		let global = cfg.global.unwrap();
		assert_eq!(
			global.accounts_directory,
			PathBuf::from("/tmp/other/account/dir")
		);
		assert_eq!(
			global.certificates_directory,
			PathBuf::from("/tmp/example/cert/dir")
		);
		assert!(cfg.rate_limit.is_empty());
		assert_eq!(cfg.endpoint.len(), 2);
		println!("Debug: cfg.endpoint: {:?}", cfg.endpoint);
		let ac1 = cfg.endpoint.get("test ac 1").unwrap();
		assert_eq!(ac1.url, "https://acme-v02.ac1.example.org/directory");
		assert_eq!(ac1.tos_agreed, true);
		assert!(ac1.random_early_renew.is_none());
		assert!(ac1.root_certificates.is_empty());
		let ac2 = cfg.endpoint.get("test ac 2").unwrap();
		assert_eq!(ac2.url, "https://acme-v02.ac2.example.org/directory");
		assert_eq!(ac2.tos_agreed, false);
		assert_eq!(ac2.random_early_renew, Some(Duration::from_secs(10)));
		assert_eq!(ac2.root_certificates, vec![PathBuf::from("test.pem")]);
		assert!(cfg.hook.is_empty());
		assert!(cfg.group.is_empty());
		assert_eq!(cfg.account.len(), 1);
		let account = cfg.account.get("example").unwrap();
		assert_eq!(account.contacts.len(), 1);
		assert!(account.env.is_empty());
		assert!(account.external_account.is_none());
		assert!(account.hooks.is_empty());
		assert_eq!(account.key_type, AccountKeyType::EcDsaP256);
		assert!(account.signature_algorithm.is_none());
		assert!(cfg.certificate.is_empty());
	}

	#[test]
	fn invalid_hook_name() {
		let cfg = r#"
[hook."internal:hook"]
cmd = "cat"
type = ["file-pre-edit"]
"#;
		let res = load_str::<AcmedConfig>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn invalid_group_name() {
		let cfg = r#"
[hook."test"]
cmd = "cat"
type = ["file-pre-edit"]
[group]
internal:grp = ["test"]
"#;
		let res = load_str::<AcmedConfig>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn valid_group_name() {
		let cfg = r#"
[hook."internaltest"]
cmd = "cat"
type = ["file-pre-edit"]
[group]
internal-grp = ["internaltest"]
"#;
		let res = load_str::<AcmedConfig>(cfg);
		assert!(res.is_ok());
	}
}
