mod cli;
mod log;

use anyhow::{Context, Result};
use clap::Parser;
use daemonize::Daemonize;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

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
	log::init(args.log_level, !args.log.log_stderr);

	// Initialize the server (PID file and daemon)
	init_server(args.foreground, args.pid.get_pid_file());

	// Starting ACMEd
	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.thread_name(APP_THREAD_NAME)
		.build()
		.unwrap()
		.block_on(start());
}

async fn start() {
	tracing::info!("starting ACMEd");
}

fn init_server(foreground: bool, pid_file: Option<&Path>) {
	if !foreground {
		let mut daemonize = Daemonize::new();
		if let Some(f) = pid_file {
			daemonize = daemonize.pid_file(f);
		}
		if let Err(e) = daemonize.start() {
			tracing::error!("error: {e:#}");
			std::process::exit(3);
		}
	} else if let Some(f) = pid_file {
		if let Err(e) = write_pid_file(f) {
			tracing::error!("error: {e:#}");
			std::process::exit(3);
		}
	}
}

fn write_pid_file(pid_file: &Path) -> Result<()> {
	let data = format!("{}\n", process::id()).into_bytes();
	let mut file = File::create(pid_file).with_context(|| format!("{}", pid_file.display()))?;
	file.write_all(&data)
		.with_context(|| format!("{}", pid_file.display()))?;
	file.sync_all()
		.with_context(|| format!("{}", pid_file.display()))?;
	Ok(())
}
