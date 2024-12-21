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
	let subscriber = FmtSubscriber::builder()
		.with_max_level(level.tracing())
		.finish();
	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}
