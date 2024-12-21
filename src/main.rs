mod cli;
mod log;

use clap::Parser;

pub const APP_IDENTITY: &[u8] = b"acmed\0";
pub const APP_THREAD_NAME: &str = "acmed-runtime";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/acmed/acmed.toml";
pub const DEFAULT_LOG_LEVEL: log::Level = log::Level::Warn;
pub const DEFAULT_PID_FILE: &str = "/run/acmed.pid";

fn main() {
	// CLI
	let args = cli::CliArgs::parse();
	println!("Debug: args: {args:?}");

	// Initialize the logging system
	log::init(args.log_level, args.log.log_syslog);

	// Starting ACMEd
	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.thread_name(APP_THREAD_NAME)
		.build()
		.unwrap()
		.block_on(start());
}

async fn start() {
	tracing::info!("Starting ACMEd.");
}
