use crate::config::Duration;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
	pub(in crate::config) number: usize,
	pub(in crate::config) period: Duration,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::load_str;

	#[test]
	fn empty() {
		let res = load_str::<RateLimit>("");
		assert!(res.is_err());
	}

	#[test]
	fn ok() {
		let cfg = r#"
number = 20
period = "20s"
"#;

		let rl: RateLimit = load_str(cfg).unwrap();
		assert_eq!(rl.number, 20);
		assert_eq!(rl.period, Duration::from_secs(20));
	}

	#[test]
	fn missing_number() {
		let cfg = r#"
period = "20s"
"#;

		let res = load_str::<RateLimit>(cfg);
		assert!(res.is_err());
	}

	#[test]
	fn missing_period() {
		let cfg = r#"
number = 20
"#;

		let res = load_str::<RateLimit>(cfg);
		assert!(res.is_err());
	}
}
