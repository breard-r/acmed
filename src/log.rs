use crate::config::{AcmedConfig, Facility, LogFormat};
use anyhow::{Context, Result};
use std::fs::File;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter, Registry};

macro_rules! add_output {
	($vec: ident, $facility: ident, $writer: expr) => {{
		let layer = tracing_subscriber::fmt::layer()
			.with_ansi($facility.is_ansi())
			.with_writer($writer);
		match $facility.format {
			LogFormat::Compact => push_output!($vec, $facility, layer.compact()),
			LogFormat::Full => push_output!($vec, $facility, layer),
			LogFormat::Json => push_output!($vec, $facility, layer.json()),
			LogFormat::Pretty => push_output!($vec, $facility, layer.pretty()),
		};
	}};
}

macro_rules! push_output {
	($vec: ident, $facility: ident, $layer: expr) => {{
		let level = $facility.get_level();
		let layer = $layer.with_filter(filter::filter_fn(move |metadata| {
			metadata.target().starts_with("acmed") && *metadata.level() <= level
		}));
		$vec.push(layer.boxed());
	}};
}

pub fn init(config: &AcmedConfig) -> Result<()> {
	let mut layers = Vec::new();

	for lf in &config.logging_facility {
		match &lf.output {
			Facility::File(path) => {
				let file = File::options()
					.create(true)
					.append(true)
					.open(path)
					.context(path.display().to_string())?;
				add_output!(layers, lf, file)
			}
			Facility::StdErr => add_output!(layers, lf, std::io::stderr),
			Facility::StdOut => add_output!(layers, lf, std::io::stdout),
			Facility::SysLog => {
				let identity = std::ffi::CStr::from_bytes_with_nul(crate::APP_IDENTITY).unwrap();
				let options = Default::default();
				let facility = syslog_tracing::Facility::Daemon;
				let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
				add_output!(layers, lf, syslog)
			}
		}
	}

	let subscriber = Registry::default().with(layers);
	tracing::subscriber::set_global_default(subscriber).unwrap();

	Ok(())
}
