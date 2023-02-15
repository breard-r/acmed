use crate::main_event_loop::MainEventLoop;
use acme_common::crypto::{
	get_lib_name, get_lib_version, HashFunction, JwsSignatureAlgorithm, KeyType,
};
use acme_common::logs::{set_log_system, DEFAULT_LOG_LEVEL};
use acme_common::{clean_pid_file, init_server};
use async_lock::RwLock;
use clap::{Arg, ArgAction, Command};
use log::error;
use std::sync::Arc;
use tokio::runtime::Builder;

mod account;
mod acme_proto;
mod certificate;
mod config;
mod duration;
mod endpoint;
mod hooks;
mod http;
mod identifier;
mod jws;
mod logs;
mod main_event_loop;
mod storage;
mod template;

pub const APP_NAME: &str = "ACMEd";
pub const APP_THREAD_NAME: &str = "acmed-runtime";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_ACCOUNTS_DIR: &str = env!("ACMED_DEFAULT_ACCOUNTS_DIR");
pub const DEFAULT_CERT_DIR: &str = env!("ACMED_DEFAULT_CERT_DIR");
pub const DEFAULT_CERT_FORMAT: &str = env!("ACMED_DEFAULT_CERT_FORMAT");
pub const DEFAULT_CONFIG_FILE: &str = env!("ACMED_DEFAULT_CONFIG_FILE");
pub const DEFAULT_PID_FILE: &str = env!("ACMED_DEFAULT_PID_FILE");
pub const DEFAULT_SLEEP_TIME: u64 = 3600;
pub const DEFAULT_POOL_TIME: u64 = 5000;
pub const DEFAULT_CSR_DIGEST: HashFunction = HashFunction::Sha256;
pub const DEFAULT_CERT_KEY_TYPE: KeyType = KeyType::Rsa2048;
pub const DEFAULT_CERT_FILE_MODE: u32 = 0o644;
pub const DEFAULT_CERT_RENEW_DELAY: u64 = 1_814_400; // 1_814_400 is 3 weeks (3 * 7 * 24 * 60 * 60)
pub const DEFAULT_PK_FILE_MODE: u32 = 0o600;
pub const DEFAULT_ACCOUNT_FILE_MODE: u32 = 0o600;
pub const DEFAULT_KP_REUSE: bool = false;
pub const DEFAULT_ACCOUNT_KEY_TYPE: KeyType = KeyType::EcdsaP256;
pub const DEFAULT_EXTERNAL_ACCOUNT_JWA: JwsSignatureAlgorithm = JwsSignatureAlgorithm::Hs256;
pub const DEFAULT_POOL_NB_TRIES: usize = 20;
pub const DEFAULT_POOL_WAIT_SEC: u64 = 5;
pub const DEFAULT_HTTP_FAIL_NB_RETRY: usize = 10;
pub const DEFAULT_HTTP_FAIL_WAIT_SEC: u64 = 1;
pub const DEFAULT_HOOK_ALLOW_FAILURE: bool = false;
pub const MAX_RATE_LIMIT_SLEEP_MILISEC: u64 = 3_600_000;
pub const MIN_RATE_LIMIT_SLEEP_MILISEC: u64 = 100;

type AccountSync = Arc<RwLock<account::Account>>;
type EndpointSync = Arc<RwLock<endpoint::Endpoint>>;

fn main() {
	Builder::new_multi_thread()
		.enable_all()
		.thread_name(APP_THREAD_NAME)
		.build()
		.unwrap()
		.block_on(inner_main());
}

async fn inner_main() {
	let full_version = format!(
		"{APP_VERSION} built for {}\n\nCryptographic library:\n - {} {}\nHTTP client library:\n - {} {}",
		env!("ACMED_TARGET"),
		get_lib_name(),
		get_lib_version(),
		env!("ACMED_HTTP_LIB_NAME"),
		env!("ACMED_HTTP_LIB_VERSION")
	);
	let default_log_level = DEFAULT_LOG_LEVEL.to_string().to_lowercase();
	let matches = Command::new(APP_NAME)
		.version(APP_VERSION)
		.long_version(full_version)
		.arg(
			Arg::new("config")
				.short('c')
				.long("config")
				.help("Path to the main configuration file")
				.num_args(1)
				.value_name("FILE")
				.default_value(DEFAULT_CONFIG_FILE),
		)
		.arg(
			Arg::new("log-level")
				.long("log-level")
				.help("Specify the log level")
				.num_args(1)
				.value_name("LEVEL")
				.value_parser(["error", "warn", "info", "debug", "trace"])
				.default_value(default_log_level),
		)
		.arg(
			Arg::new("to-syslog")
				.long("log-syslog")
				.help("Sends log messages via syslog")
				.conflicts_with("to-stderr")
				.action(ArgAction::SetTrue),
		)
		.arg(
			Arg::new("to-stderr")
				.long("log-stderr")
				.help("Prints log messages to the standard error output")
				.conflicts_with("to-syslog")
				.action(ArgAction::SetTrue),
		)
		.arg(
			Arg::new("foreground")
				.short('f')
				.long("foreground")
				.help("Runs in the foreground")
				.action(ArgAction::SetTrue),
		)
		.arg(
			Arg::new("pid-file")
				.long("pid-file")
				.help("Path to the PID file")
				.num_args(1)
				.value_name("FILE")
				.default_value(DEFAULT_PID_FILE)
				.default_value_if("no-pid-file", clap::builder::ArgPredicate::IsPresent, None)
				.conflicts_with("no-pid-file"),
		)
		.arg(
			Arg::new("no-pid-file")
				.long("no-pid-file")
				.help("Do not create any PID file")
				.conflicts_with("pid-file")
				.action(ArgAction::SetTrue),
		)
		.arg(
			Arg::new("root-cert")
				.long("root-cert")
				.help("Add a root certificate to the trust store (can be set multiple times)")
				.num_args(1)
				.action(ArgAction::Append)
				.value_name("FILE"),
		)
		.get_matches();

	match set_log_system(
		matches.get_one::<String>("log-level").map(|e| e.as_str()),
		matches.get_flag("to-syslog"),
		matches.get_flag("to-stderr"),
	) {
		Ok(_) => {}
		Err(e) => {
			eprintln!("Error: {e}");
			std::process::exit(2);
		}
	};

	let root_certs = match matches.get_many::<String>("root-cert") {
		Some(v) => v.map(|e| e.as_str()).collect(),
		None => vec![],
	};

	let config_file = matches
		.get_one::<String>("config")
		.map(|e| e.as_str())
		.unwrap_or(DEFAULT_CONFIG_FILE);
	let pid_file = matches.get_one::<String>("pid-file").map(|e| e.as_str());

	init_server(matches.get_flag("foreground"), pid_file);

	let mut srv = match MainEventLoop::new(config_file, &root_certs) {
		Ok(s) => s,
		Err(e) => {
			error!("{e}");
			let _ = clean_pid_file(pid_file);
			std::process::exit(1);
		}
	};
	srv.run().await;
}
