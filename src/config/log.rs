use anyhow::Result;
use serde::{de, Deserialize, Deserializer};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingFacility {
	pub output: Facility,
	#[serde(default)]
	pub format: LogFormat,
	#[serde(default)]
	pub(in crate::config) level: Level,
	pub(in crate::config) ansi: Option<bool>,
}

impl LoggingFacility {
	pub fn is_ansi(&self) -> bool {
		self.ansi.unwrap_or_else(|| self.output.default_ansi())
	}

	pub fn get_level(&self) -> tracing::Level {
		self.level.clone().into()
	}
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(remote = "Self")]
pub enum Facility {
	File(PathBuf),
	StdErr,
	StdOut,
	SysLog,
}

impl Facility {
	fn default_ansi(&self) -> bool {
		match self {
			Self::File(_) | Self::SysLog => false,
			Self::StdErr | Self::StdOut => true,
		}
	}
}

impl<'de> Deserialize<'de> for Facility {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let unchecked = PathBuf::deserialize(deserializer)?;
		if unchecked.components().count() == 0 {
			return Err(de::Error::custom(
				"the logging facility output must not be empty",
			));
		}
		if unchecked == PathBuf::from("stderr") {
			return Ok(Facility::StdErr);
		}
		if unchecked == PathBuf::from("stdout") {
			return Ok(Facility::StdOut);
		}
		if unchecked == PathBuf::from("syslog") {
			return Ok(Facility::SysLog);
		}
		Ok(Facility::File(unchecked))
	}
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
	Compact,
	#[default]
	Full,
	Json,
	Pretty,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(in crate::config) enum Level {
	Error,
	Warn,
	#[default]
	Info,
	Debug,
	Trace,
}

impl From<Level> for tracing::Level {
	fn from(lvl: Level) -> Self {
		match lvl {
			Level::Error => tracing::Level::ERROR,
			Level::Warn => tracing::Level::WARN,
			Level::Info => tracing::Level::INFO,
			Level::Debug => tracing::Level::DEBUG,
			Level::Trace => tracing::Level::TRACE,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty_logging_facility() {
		let res = load_str::<LoggingFacility>("");
		assert!(res.is_err());
	}

	#[test]
	fn empty_output() {
		let cfg = r#"output = """#;
		let res = load_str::<LoggingFacility>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn logging_facility_minimal() {
		let cfg = r#"output = "test.log""#;
		let c = load_str::<LoggingFacility>(cfg).unwrap();
		assert_eq!(c.output, Facility::File(PathBuf::from("test.log")));
		assert_eq!(c.format, LogFormat::Full);
		assert_eq!(c.level, Level::Info);
		assert_eq!(c.is_ansi(), false);
	}

	#[test]
	fn logging_facility_stderr() {
		let cfg = r#"output = "stderr""#;
		let c = load_str::<LoggingFacility>(cfg).unwrap();
		assert_eq!(c.output, Facility::StdErr);
		assert_eq!(c.format, LogFormat::Full);
		assert_eq!(c.level, Level::Info);
		assert_eq!(c.is_ansi(), true);
	}

	#[test]
	fn logging_facility_stdout() {
		let cfg = r#"output = "stdout""#;
		let c = load_str::<LoggingFacility>(cfg).unwrap();
		assert_eq!(c.output, Facility::StdOut);
		assert_eq!(c.format, LogFormat::Full);
		assert_eq!(c.level, Level::Info);
		assert_eq!(c.is_ansi(), true);
	}

	#[test]
	fn logging_facility_syslog() {
		let cfg = r#"output = "syslog""#;
		let c = load_str::<LoggingFacility>(cfg).unwrap();
		assert_eq!(c.output, Facility::SysLog);
		assert_eq!(c.format, LogFormat::Full);
		assert_eq!(c.level, Level::Info);
		assert_eq!(c.is_ansi(), false);
	}

	#[test]
	fn logging_facility_full() {
		let cfg = r#"
output = "test.log"
format = "json"
level = "warn"
ansi = true
"#;
		let c = load_str::<LoggingFacility>(cfg).unwrap();
		assert_eq!(c.output, Facility::File(PathBuf::from("test.log")));
		assert_eq!(c.format, LogFormat::Json);
		assert_eq!(c.level, Level::Warn);
		assert_eq!(c.is_ansi(), true);
	}
}
