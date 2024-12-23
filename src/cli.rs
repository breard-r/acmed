use crate::log::Level;
use clap::{Args, Parser};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CliArgs {
	/// Path to the main configuration directory
	#[arg(short, long, value_name = "DIR", default_value = get_default_config_dir().into_os_string())]
	pub config: PathBuf,

	/// Specify the log level
	#[arg(long, value_name = "LEVEL", value_enum, default_value_t = crate::DEFAULT_LOG_LEVEL)]
	pub log_level: Level,

	#[command(flatten)]
	pub log: Log,

	/// Runs in the foreground
	#[arg(short, long, default_value_t = false)]
	pub foreground: bool,

	#[command(flatten)]
	pub pid: Pid,

	/// Add a root certificate to the trust store (can be set multiple times)
	#[arg(long, value_name = "FILE")]
	pub root_cert: Vec<PathBuf>,
}

#[derive(Args, Debug)]
#[group(multiple = false)]
pub struct Log {
	/// Sends log messages via syslog
	#[arg(long)]
	pub log_syslog: bool,

	/// Prints log messages to the standard error output
	#[arg(long)]
	pub log_stderr: bool,
}

#[derive(Args, Debug)]
#[group(multiple = false)]
pub struct Pid {
	/// Path to the PID file
	#[arg(long, value_name = "FILE", default_value = get_default_pid_file().into_os_string())]
	pid_file: PathBuf,

	/// Do not create any PID file
	#[arg(long)]
	no_pid_file: bool,
}

impl Pid {
	pub fn get_pid_file(&self) -> Option<&Path> {
		if !self.no_pid_file {
			Some(self.pid_file.as_path())
		} else {
			None
		}
	}
}

fn get_default_config_dir() -> PathBuf {
	let mut path = match option_env!("SYSCONFDIR") {
		Some(s) => PathBuf::from(s),
		None => PathBuf::from("/etc"),
	};
	path.push("acmed");
	path.push("conf-enabled");
	path
}

fn get_default_pid_file() -> PathBuf {
	let mut path = match option_env!("RUNSTATEDIR") {
		Some(s) => PathBuf::from(s),
		None => PathBuf::from("/run"),
	};
	path.push("acmed.pid");
	path
}

#[cfg(test)]
mod tests {
	use super::*;
	use clap::CommandFactory;

	#[test]
	fn verify_cli() {
		CliArgs::command().debug_assert();
	}

	#[test]
	fn no_args() {
		let args: &[&str] = &[];
		let pa = CliArgs::try_parse_from(args).unwrap();
		assert_eq!(pa.config, get_default_config_dir());
		assert_eq!(pa.log_level, Level::Warn);
		assert_eq!(pa.log.log_syslog, false);
		assert_eq!(pa.log.log_stderr, false);
		assert_eq!(pa.foreground, false);
		assert_eq!(pa.pid.pid_file, get_default_pid_file());
		assert_eq!(pa.pid.no_pid_file, false);
		assert_eq!(
			pa.pid.get_pid_file(),
			Some(get_default_pid_file().as_path())
		);
		assert!(pa.root_cert.is_empty());
	}

	#[test]
	fn all_args_long_1() {
		let argv: &[&str] = &[
			"acmed",
			"--config",
			"/tmp/test.toml",
			"--log-level",
			"debug",
			"--log-syslog",
			"--foreground",
			"--pid-file",
			"/tmp/debug/acmed.pid",
			"--root-cert",
			"/tmp/certs/root_01.pem",
			"--root-cert",
			"/tmp/certs/root_02.pem",
			"--root-cert",
			"/tmp/certs/root_03.pem",
		];
		let pa = CliArgs::try_parse_from(argv).unwrap();
		assert_eq!(pa.config, PathBuf::from("/tmp/test.toml"));
		assert_eq!(pa.log_level, Level::Debug);
		assert_eq!(pa.log.log_syslog, true);
		assert_eq!(pa.log.log_stderr, false);
		assert_eq!(pa.foreground, true);
		assert_eq!(
			pa.pid.get_pid_file(),
			Some(PathBuf::from("/tmp/debug/acmed.pid").as_path())
		);
		assert_eq!(
			pa.root_cert,
			vec![
				PathBuf::from("/tmp/certs/root_01.pem"),
				PathBuf::from("/tmp/certs/root_02.pem"),
				PathBuf::from("/tmp/certs/root_03.pem")
			]
		);
	}

	#[test]
	fn all_args_long_2() {
		let argv: &[&str] = &[
			"acmed",
			"--config",
			"/tmp/test.toml",
			"--log-level",
			"debug",
			"--log-stderr",
			"--foreground",
			"--no-pid-file",
			"--root-cert",
			"/tmp/certs/root_01.pem",
			"--root-cert",
			"/tmp/certs/root_02.pem",
			"--root-cert",
			"/tmp/certs/root_03.pem",
		];
		let pa = CliArgs::try_parse_from(argv).unwrap();
		assert_eq!(pa.config, PathBuf::from("/tmp/test.toml"));
		assert_eq!(pa.log_level, Level::Debug);
		assert_eq!(pa.log.log_syslog, false);
		assert_eq!(pa.log.log_stderr, true);
		assert_eq!(pa.foreground, true);
		assert_eq!(pa.pid.get_pid_file(), None);
		assert_eq!(
			pa.root_cert,
			vec![
				PathBuf::from("/tmp/certs/root_01.pem"),
				PathBuf::from("/tmp/certs/root_02.pem"),
				PathBuf::from("/tmp/certs/root_03.pem")
			]
		);
	}

	#[test]
	fn all_args_short_1() {
		let argv: &[&str] = &[
			"acmed",
			"-c",
			"/tmp/test.toml",
			"--log-level",
			"debug",
			"--log-syslog",
			"-f",
			"--pid-file",
			"/tmp/debug/acmed.pid",
			"--root-cert",
			"/tmp/certs/root_01.pem",
			"--root-cert",
			"/tmp/certs/root_02.pem",
			"--root-cert",
			"/tmp/certs/root_03.pem",
		];
		let pa = CliArgs::try_parse_from(argv).unwrap();
		assert_eq!(pa.config, PathBuf::from("/tmp/test.toml"));
		assert_eq!(pa.log_level, Level::Debug);
		assert_eq!(pa.log.log_syslog, true);
		assert_eq!(pa.log.log_stderr, false);
		assert_eq!(pa.foreground, true);
		assert_eq!(
			pa.pid.get_pid_file(),
			Some(PathBuf::from("/tmp/debug/acmed.pid").as_path())
		);
		assert_eq!(
			pa.root_cert,
			vec![
				PathBuf::from("/tmp/certs/root_01.pem"),
				PathBuf::from("/tmp/certs/root_02.pem"),
				PathBuf::from("/tmp/certs/root_03.pem")
			]
		);
	}

	#[test]
	fn all_args_short_2() {
		let argv: &[&str] = &[
			"acmed",
			"-c",
			"/tmp/test.toml",
			"--log-level",
			"debug",
			"--log-stderr",
			"-f",
			"--no-pid-file",
			"--root-cert",
			"/tmp/certs/root_01.pem",
			"--root-cert",
			"/tmp/certs/root_02.pem",
			"--root-cert",
			"/tmp/certs/root_03.pem",
		];
		let pa = CliArgs::try_parse_from(argv).unwrap();
		assert_eq!(pa.config, PathBuf::from("/tmp/test.toml"));
		assert_eq!(pa.log_level, Level::Debug);
		assert_eq!(pa.log.log_syslog, false);
		assert_eq!(pa.log.log_stderr, true);
		assert_eq!(pa.foreground, true);
		assert_eq!(pa.pid.get_pid_file(), None);
		assert_eq!(
			pa.root_cert,
			vec![
				PathBuf::from("/tmp/certs/root_01.pem"),
				PathBuf::from("/tmp/certs/root_02.pem"),
				PathBuf::from("/tmp/certs/root_03.pem")
			]
		);
	}

	#[test]
	fn err_log_output() {
		let argv: &[&str] = &["acmed", "--log-stderr", "--log-syslog"];
		let pa = CliArgs::try_parse_from(argv);
		assert!(pa.is_err());
	}

	#[test]
	fn err_pid_file() {
		let argv: &[&str] = &[
			"acmed",
			"--pid-file",
			"/tmp/debug/acmed.pid",
			"--no-pid-file",
		];
		let pa = CliArgs::try_parse_from(argv);
		assert!(pa.is_err());
	}
}
