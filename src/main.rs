mod cli;
mod config;
mod http;
mod log;

use crate::config::AcmedConfig;
use crate::http::HttpRoutine;
use anyhow::Result;
use clap::Parser;
use fork::{daemon, Fork};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

pub const APP_IDENTITY: &[u8] = b"acmed\0";
pub const APP_THREAD_NAME: &str = "acmed-runtime";
pub const INTERNAL_HOOK_PREFIX: &str = "internal:";

macro_rules! run_server {
	($cfg: ident, $args: ident) => {
		if let Some(pid_file_path) = $args.pid.get_pid_file() {
			let _ = write_pid_file(pid_file_path);
		}
		let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.thread_name(APP_THREAD_NAME)
			.build()
			.unwrap()
			.block_on(start($cfg));
	};
}

fn main() {
	// Load the command-line interface
	let args = cli::CliArgs::parse();

	// Load the configuration
	let cfg = match config::load(args.config.as_path()) {
		Ok(cfg) => cfg,
		Err(e) => {
			eprintln!("error while loading the configuration: {e:#}");
			std::process::exit(2)
		}
	};

	// Initialize the logging system
	if let Err(e) = log::init(&cfg) {
		eprintln!("error while initializing the logging system: {e:#}");
		std::process::exit(3)
	}

	// Starting ACMEd
	if args.foreground {
		run_server!(cfg, args);
	} else {
		if let Ok(Fork::Child) = daemon(false, false) {
			run_server!(cfg, args);
		}
	}
}

async fn start(cnf: AcmedConfig) {
	tracing::info!("starting ACMEd");

	// Start the HTTP routine
	let http_routine = HttpRoutine::new(&cnf).expect("unable to load the http client");
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

#[tracing::instrument(err)]
fn write_pid_file(pid_file: &Path) -> Result<()> {
	let data = format!("{}\n", process::id()).into_bytes();
	let mut file = File::create(pid_file)?;
	file.write_all(&data)?;
	file.sync_all()?;
	Ok(())
}
