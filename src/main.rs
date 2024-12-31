mod cli;
mod config;
mod http;
mod log;

use crate::config::AcmedConfig;
use crate::http::HttpRoutine;
use anyhow::Result;
use clap::Parser;
use daemonize::Daemonize;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

pub const APP_IDENTITY: &[u8] = b"acmed\0";
pub const APP_THREAD_NAME: &str = "acmed-runtime";
pub const DEFAULT_LOG_LEVEL: log::Level = log::Level::Warn;
pub const INTERNAL_HOOK_PREFIX: &str = "internal:";

fn main() {
	// CLI
	let args = cli::CliArgs::parse();

	// Initialize the logging system
	log::init(args.log_level, !args.log.log_stderr);
	tracing::trace!("computed args" = ?args);

	// Load the configuration
	let cfg = match config::load(args.config.as_path()) {
		Ok(cfg) => cfg,
		Err(_) => std::process::exit(3),
	};

	// Initialize the server (PID file and daemon)
	if init_server(args.foreground, args.pid.get_pid_file()).is_err() {
		std::process::exit(3);
	}

	// Starting ACMEd
	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.thread_name(APP_THREAD_NAME)
		.build()
		.unwrap()
		.block_on(start(cfg));
}

async fn start(cnf: AcmedConfig) {
	tracing::info!("starting ACMEd");

	// Start the HTTP routine
	let http_routine = HttpRoutine::new(&cnf);
	let http_client = http_routine.get_client();
	tokio::spawn(async move {
		http_routine.run().await;
	});

	// TODO: REMOVE ME
	debug_remove_me(http_client).await;
}

#[tracing::instrument(skip_all, level = "trace")]
async fn debug_remove_me(http_client: crate::http::HttpClient) {
	use reqwest::{Method, Request, Url};

	let rsp = http_client
		.send(
			"my-ca",
			Request::new(Method::GET, Url::parse("https://example.invalid").unwrap()),
		)
		.await;
	tracing::debug!("response received" = ?rsp);
	let rsp = http_client
		.send(
			"my-ca",
			Request::new(
				Method::GET,
				Url::parse("https://example.com/directory/").unwrap(),
			),
		)
		.await;
	tracing::debug!("response received" = ?rsp);
}

#[tracing::instrument(level = "trace", err(Debug))]
fn init_server(foreground: bool, pid_file: Option<&Path>) -> Result<()> {
	if !foreground {
		let mut daemonize = Daemonize::new();
		if let Some(f) = pid_file {
			daemonize = daemonize.pid_file(f);
		}
		daemonize.start()?
	} else if let Some(f) = pid_file {
		write_pid_file(f)?
	}
	Ok(())
}

fn write_pid_file(pid_file: &Path) -> Result<()> {
	let data = format!("{}\n", process::id()).into_bytes();
	let mut file = File::create(pid_file)?;
	file.write_all(&data)?;
	file.sync_all()?;
	Ok(())
}
