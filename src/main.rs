pub const APP_THREAD_NAME: &str = "acmed-runtime";

fn main() {
	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.thread_name(APP_THREAD_NAME)
		.build()
		.unwrap()
		.block_on(start());
}

async fn start() {
}
