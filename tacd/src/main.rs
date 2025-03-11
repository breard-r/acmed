#[cfg(feature = "crypto_openssl")]
mod openssl_server;

#[cfg(feature = "crypto_openssl")]
use crate::openssl_server::start as server_start;
use acme_common::crypto::{get_lib_name, get_lib_version, HashFunction, KeyType, X509Certificate};
use acme_common::logs::{set_log_system, DEFAULT_LOG_LEVEL};
use acme_common::{clean_pid_file, to_idna};
use anyhow::{anyhow, Result};
use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use log::{debug, error, info};
use std::fs::File;
use std::io::{self, Read};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PID_FILE: &str = env!("TACD_DEFAULT_PID_FILE");
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:5001";
const DEFAULT_CRT_KEY_TYPE: KeyType = KeyType::EcdsaP256;
const DEFAULT_CRT_DIGEST: HashFunction = HashFunction::Sha256;
const ALPN_ACME_PROTO_NAME: &[u8] = b"\x0aacme-tls/1";

fn read_line(path: Option<&String>) -> Result<String> {
	let mut input = String::new();
	match path {
		Some(p) => File::open(p)?.read_to_string(&mut input)?,
		None => io::stdin().read_line(&mut input)?,
	};
	let line = input.trim().to_string();
	Ok(line)
}

fn get_acme_value(cnf: &ArgMatches, opt: &str, opt_file: &str) -> Result<String> {
	match cnf.get_one::<String>(opt) {
		Some(v) => Ok(v.to_string()),
		None => {
			debug!(
				"reading {opt} from {}",
				cnf.get_one::<String>(opt_file)
					.map(|e| e.as_str())
					.unwrap_or("stdin")
			);
			read_line(cnf.get_one::<String>(opt_file))
		}
	}
}

fn init(cnf: &ArgMatches) -> Result<()> {
	acme_common::init_server(
		cnf.get_flag("foreground"),
		cnf.get_one::<String>("pid-file").map(|e| e.as_str()),
	);
	let domain = get_acme_value(cnf, "domain", "domain-file")?;
	let domain = to_idna(&domain).map_err(|e| anyhow!(e))?;
	let ext = get_acme_value(cnf, "acme-ext", "acme-ext-file")?;
	let listen_addr = cnf
		.get_one::<String>("listen")
		.map(|e| e.as_str())
		.unwrap_or(DEFAULT_LISTEN_ADDR);
	let crt_signature_alg = match cnf.get_one::<String>("crt-signature-alg") {
		Some(alg) => alg
			.parse()
			.map_err(|e: acme_common::error::Error| anyhow!(e))?,
		None => DEFAULT_CRT_KEY_TYPE,
	};
	let crt_digest = match cnf.get_one::<String>("crt-digest") {
		Some(alg) => alg
			.parse()
			.map_err(|e: acme_common::error::Error| anyhow!(e))?,
		None => DEFAULT_CRT_DIGEST,
	};
	let (pk, cert) = X509Certificate::from_acme_ext(&domain, &ext, crt_signature_alg, crt_digest)
		.map_err(|e| anyhow!(e))?;
	info!("starting {APP_NAME} on {listen_addr} for {domain}");
	server_start(listen_addr, &cert, &pk)?;
	Ok(())
}

fn main() {
	let full_version = format!(
		"{APP_VERSION} built for {}\n\nCryptographic library:\n - {} {}",
		env!("TACD_TARGET"),
		get_lib_name(),
		get_lib_version(),
	);
	let default_crt_key_type = DEFAULT_CRT_KEY_TYPE.to_string();
	let default_crt_digest = DEFAULT_CRT_DIGEST.to_string();
	let default_log_level = DEFAULT_LOG_LEVEL.to_string().to_lowercase();
	let matches = Command::new(APP_NAME)
		.version(APP_VERSION)
		.long_version(full_version)
		.arg(
			Arg::new("listen")
				.long("listen")
				.short('l')
				.help("Host and port to listen on")
				.num_args(1)
				.value_name("host:port|unix:path")
				.default_value(DEFAULT_LISTEN_ADDR),
		)
		.arg(
			Arg::new("domain")
				.long("domain")
				.short('d')
				.help("The domain that is being validated")
				.num_args(1)
				.value_name("STRING")
				.conflicts_with("domain-file"),
		)
		.arg(
			Arg::new("domain-file")
				.long("domain-file")
				.help("File from which is read the domain that is being validated")
				.num_args(1)
				.value_name("FILE")
				.conflicts_with("domain"),
		)
		.arg(
			Arg::new("acme-ext")
				.long("acme-ext")
				.short('e')
				.help("The acmeIdentifier extension to set in the self-signed certificate")
				.num_args(1)
				.value_name("STRING")
				.conflicts_with("acme-ext-file"),
		)
		.arg(
			Arg::new("acme-ext-file")
				.long("acme-ext-file")
				.help("File from which is read the acmeIdentifier extension to set in the self-signed certificate")
				.num_args(1)
				.value_name("FILE")
				.conflicts_with("acme-ext"),
		)
		.arg(
			Arg::new("crt-signature-alg")
				.long("crt-signature-alg")
				.help("The certificate's signature algorithm")
				.num_args(1)
				.value_name("STRING")
				.value_parser(PossibleValuesParser::new(KeyType::list_possible_values()))
				.default_value(default_crt_key_type),
		)
		.arg(
			Arg::new("crt-digest")
				.long("crt-digest")
				.help("The certificate's digest algorithm")
				.num_args(1)
				.value_name("STRING")
				.value_parser(PossibleValuesParser::new(HashFunction::list_possible_values()))
				.default_value(default_crt_digest),
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
				.long("foreground")
				.short('f')
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

	match init(&matches) {
		Ok(_) => {}
		Err(e) => {
			error!("{e}");
			let pid_file = matches.get_one::<String>("pid-file").map(|e| e.as_str());
			let _ = clean_pid_file(pid_file);
			std::process::exit(1);
		}
	};
}
