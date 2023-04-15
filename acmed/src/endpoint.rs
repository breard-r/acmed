use crate::acme_proto::structs::Directory;
use crate::duration::parse_duration;
use acme_common::error::Error;
use std::cmp;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct Endpoint {
	pub name: String,
	pub url: String,
	pub tos_agreed: bool,
	pub nonce: Option<String>,
	pub rl: RateLimit,
	pub dir: Directory,
	pub root_certificates: Vec<String>,
}

impl Endpoint {
	pub fn new(
		name: &str,
		url: &str,
		tos_agreed: bool,
		limits: &[(usize, String)],
		root_certs: &[String],
	) -> Result<Self, Error> {
		Ok(Self {
			name: name.to_string(),
			url: url.to_string(),
			tos_agreed,
			nonce: None,
			rl: RateLimit::new(limits)?,
			dir: Directory {
				meta: None,
				new_nonce: String::new(),
				new_account: String::new(),
				new_order: String::new(),
				new_authz: None,
				revoke_cert: String::new(),
				key_change: String::new(),
			},
			root_certificates: root_certs.to_vec(),
		})
	}
}

#[derive(Clone, Debug)]
pub struct RateLimit {
	limits: Vec<(usize, Duration)>,
	query_log: Vec<Instant>,
}

impl RateLimit {
	pub fn new(raw_limits: &[(usize, String)]) -> Result<Self, Error> {
		let mut limits = vec![];
		for (nb, raw_duration) in raw_limits.iter() {
			let parsed_duration = parse_duration(raw_duration)?;
			limits.push((*nb, parsed_duration));
		}
		limits.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
		limits.reverse();
		Ok(Self {
			limits,
			query_log: vec![],
		})
	}

	pub async fn block_until_allowed(&mut self) {
		if self.limits.is_empty() {
			return;
		}
		let mut sleep_duration = self.get_sleep_duration();
		loop {
			sleep(sleep_duration).await;
			self.prune_log();
			if self.request_allowed() {
				self.query_log.push(Instant::now());
				return;
			}
			sleep_duration = self.get_sleep_duration();
		}
	}

	fn get_sleep_duration(&self) -> Duration {
		let (nb_req, min_duration) = match self.limits.last() {
			Some((n, d)) => (*n as u64, *d),
			None => {
				return Duration::from_millis(0);
			}
		};
		let nb_mili = match min_duration.as_secs() {
			0 | 1 => crate::MIN_RATE_LIMIT_SLEEP_MILISEC,
			n => {
				let a = n * 200 / nb_req;
				let a = cmp::min(a, crate::MAX_RATE_LIMIT_SLEEP_MILISEC);
				cmp::max(a, crate::MIN_RATE_LIMIT_SLEEP_MILISEC)
			}
		};
		Duration::from_millis(nb_mili)
	}

	fn request_allowed(&self) -> bool {
		for (max_allowed, duration) in self.limits.iter() {
			match Instant::now().checked_sub(*duration) {
				Some(max_date) => {
					let nb_req = self
						.query_log
						.iter()
						.filter(move |x| **x > max_date)
						.count();
					if nb_req >= *max_allowed {
						return false;
					}
				}
				None => {
					return false;
				}
			};
		}
		true
	}

	fn prune_log(&mut self) {
		if let Some((_, max_limit)) = self.limits.first() {
			if let Some(prune_date) = Instant::now().checked_sub(*max_limit) {
				self.query_log.retain(move |&d| d > prune_date);
			}
		}
	}
}
