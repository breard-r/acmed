mod openssl_server;

use crate::openssl_server::start as server_start;
use acme_common::crypto::{HashFunction, KeyType, X509Certificate};
use acme_common::error::Error;
use acme_common::logs::{set_log_system, DEFAULT_LOG_LEVEL};
use acme_common::{clean_pid_file, to_idna};
use clap::{App, Arg, ArgMatches};
use log::{debug, error, info};
use std::fs::File;
use std::io::{self, Read};

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PID_FILE: &str = "/var/run/tacd.pid";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:5001";
const DEFAULT_CRT_KEY_TYPE: KeyType = KeyType::EcdsaP256;
const DEFAULT_CRT_DIGEST: HashFunction = HashFunction::Sha256;
const ALPN_ACME_PROTO_NAME: &[u8] = b"\x0aacme-tls/1";

fn read_line(path: Option<&str>) -> Result<String, Error> {
    let mut input = String::new();
    match path {
        Some(p) => File::open(p)?.read_to_string(&mut input)?,
        None => io::stdin().read_line(&mut input)?,
    };
    let line = input.trim().to_string();
    Ok(line)
}

fn get_acme_value(cnf: &ArgMatches, opt: &str, opt_file: &str) -> Result<String, Error> {
    match cnf.value_of(opt) {
        Some(v) => Ok(v.to_string()),
        None => {
            debug!(
                "Reading {} from {}",
                opt,
                cnf.value_of(opt_file).unwrap_or("stdin")
            );
            read_line(cnf.value_of(opt_file))
        }
    }
}

fn init(cnf: &ArgMatches) -> Result<(), Error> {
    acme_common::init_server(
        cnf.is_present("foreground"),
        cnf.value_of("pid-file"),
        DEFAULT_PID_FILE,
    );
    let domain = get_acme_value(cnf, "domain", "domain-file")?;
    let domain = to_idna(&domain)?;
    let ext = get_acme_value(cnf, "acme-ext", "acme-ext-file")?;
    let listen_addr = cnf.value_of("listen").unwrap_or(DEFAULT_LISTEN_ADDR);
    let crt_signature_alg = match cnf.value_of("crt-signature-alg") {
        Some(alg) => alg.parse()?,
        None => DEFAULT_CRT_KEY_TYPE,
    };
    let crt_digest = match cnf.value_of("crt-digest") {
        Some(alg) => alg.parse()?,
        None => DEFAULT_CRT_DIGEST,
    };
    let (pk, cert) = X509Certificate::from_acme_ext(&domain, &ext, crt_signature_alg, crt_digest)?;
    info!("Starting {} on {} for {}", APP_NAME, listen_addr, domain);
    server_start(listen_addr, &cert, &pk)?;
    Ok(())
}

fn main() {
    let default_crt_key_type = DEFAULT_CRT_KEY_TYPE.to_string();
    let default_crt_digest = DEFAULT_CRT_DIGEST.to_string();
    let default_log_level = DEFAULT_LOG_LEVEL.to_string().to_lowercase();
    let matches = App::new(APP_NAME)
        .version(APP_VERSION)
        .arg(
            Arg::with_name("listen")
                .long("listen")
                .short("l")
                .help("Host and port to listen on")
                .takes_value(true)
                .value_name("host:port|unix:path")
                .default_value(&DEFAULT_LISTEN_ADDR)
        )
        .arg(
            Arg::with_name("domain")
                .long("domain")
                .short("d")
                .help("The domain that is being validated")
                .takes_value(true)
                .value_name("STRING")
                .conflicts_with("domain-file")
        )
        .arg(
            Arg::with_name("domain-file")
                .long("domain-file")
                .help("File from which is read the domain that is being validated")
                .takes_value(true)
                .value_name("FILE")
                .conflicts_with("domain")
        )
        .arg(
            Arg::with_name("acme-ext")
                .long("acme-ext")
                .short("e")
                .help("The acmeIdentifier extension to set in the self-signed certificate")
                .takes_value(true)
                .value_name("STRING")
                .conflicts_with("acme-ext-file")
        )
        .arg(
            Arg::with_name("acme-ext-file")
                .long("acme-ext-file")
                .help("File from which is read the acmeIdentifier extension to set in the self-signed certificate")
                .takes_value(true)
                .value_name("FILE")
                .conflicts_with("acme-ext")
        )
        .arg(
            Arg::with_name("crt-signature-alg")
                .long("crt-signature-alg")
                .help("The certificate's signature algorithm")
                .takes_value(true)
                .value_name("STRING")
                .possible_values(&KeyType::list_possible_values())
                .default_value(&default_crt_key_type)
        )
        .arg(
            Arg::with_name("crt-digest")
                .long("crt-digest")
                .help("The certificate's digest algorithm")
                .takes_value(true)
                .value_name("STRING")
                .possible_values(&HashFunction::list_possible_values())
                .default_value(&default_crt_digest)
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .help("Specify the log level")
                .takes_value(true)
                .value_name("LEVEL")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value(&default_log_level)
        )
        .arg(
            Arg::with_name("to-syslog")
                .long("log-syslog")
                .help("Sends log messages via syslog")
                .conflicts_with("to-stderr"),
        )
        .arg(
            Arg::with_name("to-stderr")
                .long("log-stderr")
                .help("Prints log messages to the standard error output")
                .conflicts_with("to-syslog"),
        )
        .arg(
            Arg::with_name("foreground")
                .long("foreground")
                .short("f")
                .help("Runs in the foreground")
        )
        .arg(
            Arg::with_name("pid-file")
                .long("pid-file")
                .help("Path to the PID file")
                .takes_value(true)
                .value_name("FILE")
                .default_value(&DEFAULT_PID_FILE)
        )
        .get_matches();

    match set_log_system(
        matches.value_of("log-level"),
        matches.is_present("log-syslog"),
        matches.is_present("to-stderr"),
    ) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    };

    match init(&matches) {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e);
            let _ = clean_pid_file(matches.value_of("pid-file"));
            std::process::exit(1);
        }
    };
}
