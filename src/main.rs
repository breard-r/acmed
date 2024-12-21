use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub const APP_THREAD_NAME: &str = "acmed-runtime";

fn main() {
	let subscriber = FmtSubscriber::builder()
		.with_max_level(Level::TRACE)
		.finish();
	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
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
