use clap::ValueEnum;
use tracing_subscriber::FmtSubscriber;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Level {
	Error,
	Warn,
	Info,
	Debug,
	Trace,
}

impl Level {
	fn tracing(&self) -> tracing::Level {
		match self {
			Self::Error => tracing::Level::ERROR,
			Self::Warn => tracing::Level::WARN,
			Self::Info => tracing::Level::INFO,
			Self::Debug => tracing::Level::DEBUG,
			Self::Trace => tracing::Level::TRACE,
		}
	}
}

pub fn init(level: Level, is_syslog: bool) {
	if is_syslog {
		let identity = std::ffi::CStr::from_bytes_with_nul(crate::APP_IDENTITY).unwrap();
		let (options, facility) = Default::default();
		let syslog = syslog_tracing::Syslog::new(identity, options, facility)
			.expect("building syslog subscriber failed");
		tracing_subscriber::fmt().with_writer(syslog).init();
	} else {
		let subscriber = FmtSubscriber::builder()
			.with_max_level(level.tracing())
			.finish();
		tracing::subscriber::set_global_default(subscriber)
			.expect("setting default subscriber failed");
	}
}
