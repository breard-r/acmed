use clap::{App, Arg};
use log::{error, LevelFilter};

mod acmed;
mod config;
mod encoding;
mod errors;
mod hooks;
mod logs;
mod storage;

pub const APP_NAME: &str = "acmed";
pub const DEFAULT_CONFIG_FILE: &str = "/etc/acmed/acmed.toml";
pub const DEFAULT_ACCOUNTS_DIR: &str = "/etc/acmed/accounts";
pub const DEFAULT_CERT_DIR: &str = "/etc/acmed/certs";
pub const DEFAULT_CERT_FORMAT: &str = "{name}_{algo}.{kind}.{ext}";
pub const DEFAULT_ALGO: &str = "rsa2048";
pub const DEFAULT_FMT: acmed::Format = acmed::Format::Pem;
pub const DEFAULT_SLEEP_TIME: u64 = 3600;
pub const DEFAULT_POOL_TIME: u64 = 5000;
pub const DEFAULT_CERT_FILE_MODE: u32 = 0o644;
pub const DEFAULT_PK_FILE_MODE: u32 = 0o600;
pub const DEFAULT_KP_REUSE: bool = false;
pub const DEFAULT_LOG_SYSTEM: logs::LogSystem = logs::LogSystem::SysLog;
pub const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Warn;

fn main() {
    let matches = App::new("acmed")
        .version("0.1.0")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help("Specify an alternative configuration file.")
                .takes_value(true)
                .value_name("FILE"),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .help("Specify the log level.")
                .takes_value(true)
                .value_name("LEVEL")
                .possible_values(&["error", "warn", "info", "debug", "trace"]),
        )
        .arg(
            Arg::with_name("to-syslog")
                .long("log-syslog")
                .help("Send log messages via syslog.")
                .conflicts_with("to-stderr"),
        )
        .arg(
            Arg::with_name("to-stderr")
                .long("log-stderr")
                .help("Print log messages to the standard error output.")
                .conflicts_with("log-syslog"),
        )
        .get_matches();

    match logs::set_log_system(
        matches.value_of("log-level"),
        matches.is_present("log-syslog"),
        matches.is_present("to-stderr"),
    ) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let config_file = matches.value_of("config").unwrap_or(DEFAULT_CONFIG_FILE);
    let mut srv = match acmed::Acmed::new(&config_file) {
        Ok(s) => s,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };
    srv.run();
}
