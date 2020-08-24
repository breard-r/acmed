use crate::main_event_loop::MainEventLoop;
use acme_common::{clean_pid_file, crypto, init_server};
use clap::{App, Arg};
use log::error;

mod acme_proto;
mod certificate;
mod config;
mod duration;
mod endpoint;
mod hooks;
mod http;
mod jws;
mod main_event_loop;
mod storage;

pub const APP_NAME: &str = "ACMEd";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_PID_FILE: &str = "/var/run/acmed.pid";
pub const DEFAULT_CONFIG_FILE: &str = "/etc/acmed/acmed.toml";
pub const DEFAULT_ACCOUNTS_DIR: &str = "/etc/acmed/accounts";
pub const DEFAULT_CERT_DIR: &str = "/etc/acmed/certs";
pub const DEFAULT_CERT_FORMAT: &str = "{{name}}_{{algo}}.{{file_type}}.{{ext}}";
pub const DEFAULT_SLEEP_TIME: u64 = 3600;
pub const DEFAULT_POOL_TIME: u64 = 5000;
pub const DEFAULT_CERT_FILE_MODE: u32 = 0o644;
pub const DEFAULT_CERT_RENEW_DELAY: u64 = 1_814_400; // 1_814_400 is 3 weeks (3 * 7 * 24 * 60 * 60)
pub const DEFAULT_PK_FILE_MODE: u32 = 0o600;
pub const DEFAULT_ACCOUNT_FILE_MODE: u32 = 0o600;
pub const DEFAULT_KP_REUSE: bool = false;
pub const DEFAULT_ACCOUNT_KEY_TYPE: crypto::KeyType = crypto::KeyType::EcdsaP256;
pub const DEFAULT_POOL_NB_TRIES: usize = 20;
pub const DEFAULT_POOL_WAIT_SEC: u64 = 5;
pub const DEFAULT_HTTP_FAIL_NB_RETRY: usize = 10;
pub const DEFAULT_HTTP_FAIL_WAIT_SEC: u64 = 1;
pub const DEFAULT_HOOK_ALLOW_FAILURE: bool = false;
pub const MAX_RATE_LIMIT_SLEEP_MILISEC: u64 = 3_600_000;
pub const MIN_RATE_LIMIT_SLEEP_MILISEC: u64 = 100;

fn main() {
    let full_version = format!(
        "{} {}\n\nCompiled with:\n  {} {}\n  {} {}",
        APP_VERSION,
        env!("ACMED_TARGET"),
        crypto::TLS_LIB_NAME,
        crypto::TLS_LIB_VERSION,
        env!("ACMED_HTTP_LIB_NAME"),
        env!("ACMED_HTTP_LIB_VERSION")
    );
    let matches = App::new(APP_NAME)
        .version(APP_VERSION)
        .long_version(full_version.as_str())
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help("Specify an alternative configuration file")
                .takes_value(true)
                .value_name("FILE"),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .help("Specify the log level")
                .takes_value(true)
                .value_name("LEVEL")
                .possible_values(&["error", "warn", "info", "debug", "trace"]),
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
                .conflicts_with("log-syslog"),
        )
        .arg(
            Arg::with_name("foreground")
                .short("f")
                .long("foreground")
                .help("Runs in the foreground"),
        )
        .arg(
            Arg::with_name("pid-file")
                .long("pid-file")
                .help("Specifies the location of the PID file")
                .takes_value(true)
                .value_name("FILE"),
        )
        .arg(
            Arg::with_name("root-cert")
                .long("root-cert")
                .help("Add a root certificate to the trust store")
                .takes_value(true)
                .multiple(true)
                .value_name("FILE"),
        )
        .get_matches();

    match acme_common::logs::set_log_system(
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

    let root_certs = match matches.values_of("root-cert") {
        Some(v) => v.collect(),
        None => vec![],
    };

    init_server(
        matches.is_present("foreground"),
        matches.value_of("pid-file"),
        DEFAULT_PID_FILE,
    );

    let config_file = matches.value_of("config").unwrap_or(DEFAULT_CONFIG_FILE);
    let mut srv = match MainEventLoop::new(&config_file, &root_certs) {
        Ok(s) => s,
        Err(e) => {
            error!("{}", e);
            let _ = clean_pid_file(matches.value_of("pid-file"));
            std::process::exit(1);
        }
    };
    srv.run();
}
