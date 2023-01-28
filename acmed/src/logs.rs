pub trait HasLogger {
	fn warn(&self, msg: &str);
	fn info(&self, msg: &str);
	fn debug(&self, msg: &str);
	fn trace(&self, msg: &str);
}
