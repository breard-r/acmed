use crate::config::NamedAcmeResource;
use crate::duration::parse_duration;
use crate::{acme_proto::structs::Directory, config};
use acme_common::error::Error;
use governor::{
	clock::DefaultClock,
	state::{direct::NotKeyed, InMemoryState},
	Quota, RateLimiter,
};
use itertools::Itertools;
use regex::Regex;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

#[derive(Debug)]
pub struct Endpoint {
	pub name: String,
	pub url: String,
	pub tos_agreed: bool,
	pub nonce: Option<String>,
	pub rl: RateLimits,
	pub dir: Directory,
	pub root_certificates: Vec<String>,
}

impl Endpoint {
	pub fn new(
		name: &str,
		url: &str,
		tos_agreed: bool,
		limits: &[config::RateLimit],
		root_certs: &[String],
	) -> Result<Self, Error> {
		Ok(Self {
			name: name.to_string(),
			url: url.to_string(),
			tos_agreed,
			nonce: None,
			rl: RateLimits::new(limits)?,
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

#[derive(Debug)]
pub struct RateLimits {
	limits: Vec<RateLimit>,
}

impl RateLimits {
	pub fn new(raw_limits: &[config::RateLimit]) -> Result<Self, Error> {
		let limits: Result<Vec<RateLimit>, Error> = raw_limits
			.iter()
			.sorted_by(rate_limit_cmp)
			// We're reverting the comparison here, as we want to get the strongest limits (those
			// with the highest waiting period per request) first.
			.rev()
			.map(|raw| raw.try_into())
			.collect();
		Ok(Self { limits: limits? })
	}

	pub async fn block_until_allowed(&mut self, resource: Option<NamedAcmeResource>, path: &str) {
		for limit in &self.limits {
			if limit.matches(resource, path) {
				limit.until_ready().await
			}
		}
	}
}

fn rate_limit_cmp(a: &&config::RateLimit, b: &&config::RateLimit) -> std::cmp::Ordering {
	let a_dur = parse_duration(&a.period).unwrap_or(Duration::ZERO) / u32::from(a.number);
	let b_dur = parse_duration(&b.period).unwrap_or(Duration::ZERO) / u32::from(b.number);

	// A limit is "stronger" if it's period is long. The duration calculated here is the time
	// per request. A shorter duration to wait, hence more requests, is *less* of a limit, so
	// directly using the result of the comparison of the two calculated durations is correct.
	Ord::cmp(&a_dur, &b_dur)
}

#[derive(Debug)]
pub struct RateLimit {
	limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
	resources: Vec<NamedAcmeResource>,
	path: Option<Regex>,
}

impl RateLimit {
	fn matches(&self, resource: Option<NamedAcmeResource>, path: &str) -> bool {
		let resource_matches = resource
			.map(|resource| self.resources.contains(&resource))
			.unwrap_or(false);
		let path_matches = self
			.path
			.as_ref()
			.map(|matcher| matcher.is_match(path))
			.unwrap_or(false);
		resource_matches || path_matches
	}
	async fn until_ready(&self) {
		self.limiter.until_ready().await
	}
}

impl TryFrom<&config::RateLimit> for RateLimit {
	type Error = Error;

	fn try_from(value: &config::RateLimit) -> Result<Self, Self::Error> {
		let period = parse_duration(&value.period)?;
		let amount = value.number;
		let quota = Quota::with_period(period / u32::from(amount))
			.ok_or("rate-limit period was passed as zero, which is illegal")?
			.allow_burst(amount);
		let limiter = RateLimiter::direct(quota);
		let path = match &value.path {
			Some(path) => Some(Regex::new(path).map_err(|e| e.to_string())?),
			None => None,
		};
		Ok(Self {
			limiter,
			resources: value.acme_resources.clone(),
			path,
		})
	}
}

#[cfg(test)]
mod tests {
	use std::{cmp::Ordering, num::NonZeroU32};

	use crate::config;

	#[test]
	fn check_ratelimit_ordering() {
		let sixty_per_hour = cfg_ratelimit_helper(NonZeroU32::new(60).unwrap(), "1h".into());
		let one_per_minute = cfg_ratelimit_helper(NonZeroU32::new(1).unwrap(), "1m".into());
		let one_per_second = cfg_ratelimit_helper(NonZeroU32::new(1).unwrap(), "1s".into());
		assert_eq!(
			super::rate_limit_cmp(&&sixty_per_hour, &&one_per_minute),
			Ordering::Equal
		);
		assert_eq!(
			super::rate_limit_cmp(&&one_per_second, &&one_per_minute),
			Ordering::Less
		);
		assert_eq!(
			super::rate_limit_cmp(&&sixty_per_hour, &&one_per_second),
			Ordering::Greater
		);
	}

	fn cfg_ratelimit_helper(number: NonZeroU32, period: String) -> config::RateLimit {
		config::RateLimit {
			name: String::new(),
			number,
			period,
			acme_resources: vec![],
			path: None,
		}
	}
}
