use serde::{de, Deserialize, Deserializer};
use serde_derive::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct Hook {
	#[serde(default)]
	pub allow_failure: bool,
	#[serde(default)]
	pub args: Vec<String>,
	pub cmd: String,
	pub name: String,
	pub stderr: Option<PathBuf>,
	pub stdin: Option<PathBuf>,
	pub stdin_str: Option<String>,
	pub stdout: Option<PathBuf>,
	#[serde(rename = "type")]
	pub hook_type: Vec<HookType>,
}

impl<'de> Deserialize<'de> for Hook {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = Hook::deserialize(deserializer)?;
		if unchecked.hook_type.is_empty() {
			return Err(de::Error::custom(
				"at least one hook type must be specified",
			));
		}
		if unchecked.stdin.is_some() && unchecked.stdin_str.is_some() {
			return Err(de::Error::custom(
				"the `stdin` and `stdin_str` directives cannot be both specified within the same hook",
			));
		}
		Ok(unchecked)
	}
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookType {
	FilePreCreate,
	FilePostCreate,
	FilePreEdit,
	FilePostEdit,
	#[serde(rename = "challenge-http-01")]
	ChallengeHttp01,
	#[serde(rename = "challenge-http-01-clean")]
	ChallengeHttp01Clean,
	#[serde(rename = "challenge-dns-01")]
	ChallengeDns01,
	#[serde(rename = "challenge-dns-01-clean")]
	ChallengeDns01Clean,
	#[serde(rename = "challenge-tls-alpn-01")]
	ChallengeTlsAlpn01,
	#[serde(rename = "challenge-tls-alpn-01-clean")]
	ChallengeTlsAlpn01Clean,
	PostOperation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
	pub hooks: Vec<String>,
	pub name: String,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty_group() {
		let res = load_str::<Group>("");
		assert!(res.is_err());
	}

	#[test]
	fn valid_group() {
		let cfg = r#"
name = "test"
hooks = ["h1", "H 2"]
"#;
		let rl: Group = load_str(cfg).unwrap();
		assert_eq!(rl.name, "test");
		assert_eq!(rl.hooks, vec!["h1".to_string(), "H 2".to_string()]);
	}

	#[test]
	fn empty_hook() {
		let res = load_str::<Hook>("");
		assert!(res.is_err());
	}

	#[test]
	fn hook_minimal() {
		let cfg = r#"
name = "test"
cmd = "cat"
type = ["file-pre-edit"]
"#;
		let h = load_str::<Hook>(cfg).unwrap();
		assert_eq!(h.allow_failure, false);
		assert!(h.args.is_empty());
		assert_eq!(h.cmd, "cat");
		assert_eq!(h.name, "test");
		assert!(h.stderr.is_none());
		assert!(h.stdin.is_none());
		assert!(h.stdin_str.is_none());
		assert!(h.stdout.is_none());
		assert_eq!(h.hook_type, vec![HookType::FilePreEdit]);
	}

	#[test]
	fn hook_full() {
		let cfg = r#"
name = "test"
cmd = "cat"
args = ["-e"]
type = ["file-pre-edit"]
allow_failure = true
stdin = "/tmp/in.txt"
stdout = "/tmp/out.log"
stderr = "/tmp/err.log"
"#;
		let h = load_str::<Hook>(cfg).unwrap();
		assert_eq!(h.allow_failure, true);
		assert_eq!(h.args, vec!["-e".to_string()]);
		assert_eq!(h.cmd, "cat");
		assert_eq!(h.name, "test");
		assert_eq!(h.stderr, Some(PathBuf::from("/tmp/err.log")));
		assert_eq!(h.stdin, Some(PathBuf::from("/tmp/in.txt")));
		assert!(h.stdin_str.is_none());
		assert_eq!(h.stdout, Some(PathBuf::from("/tmp/out.log")));
		assert_eq!(h.hook_type, vec![HookType::FilePreEdit]);
	}

	#[test]
	fn hook_both_stdin() {
		let cfg = r#"
name = "test"
cmd = "cat"
type = ["file-pre-edit"]
stdin = "/tmp/in.txt"
stdin_str = "some input"
"#;
		let res = load_str::<Hook>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn hook_missing_name() {
		let cfg = r#"
cmd = "cat"
type = ["file-pre-edit"]
"#;
		let res = load_str::<Hook>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn hook_missing_cmd() {
		let cfg = r#"
name = "test"
type = ["file-pre-edit"]
"#;
		let res = load_str::<Hook>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn hook_missing_type() {
		let cfg = r#"
name = "test"
cmd = "cat"
"#;
		let res = load_str::<Hook>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn hook_empty_type() {
		let cfg = r#"
name = "test"
cmd = "cat"
type = []
"#;
		let res = load_str::<Hook>(cfg);
		assert!(res.is_err());
	}
}
