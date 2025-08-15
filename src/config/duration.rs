use nom::bytes::complete::take_while_m_n;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::multi::fold_many1;
use nom::{IResult, Parser};
use serde::{de, Deserialize, Deserializer};

type StdDuration = std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Duration(StdDuration);

impl Duration {
	pub(in crate::config) fn from_secs(nb_secs: u64) -> Self {
		Self(std::time::Duration::from_secs(nb_secs))
	}

	pub(in crate::config) fn from_days(nb_days: u64) -> Self {
		Self(std::time::Duration::from_secs(nb_days * 24 * 60 * 60))
	}

	pub(in crate::config) fn get_std(&self) -> StdDuration {
		self.0
	}
}

impl<'de> Deserialize<'de> for Duration {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let (_, duration) =
			parse_duration(&s).map_err(|_| de::Error::custom("invalid duration"))?;
		Ok(duration)
	}
}

fn is_duration_chr(c: char) -> bool {
	c == 's' || c == 'm' || c == 'h' || c == 'd' || c == 'w'
}

fn get_multiplicator(input: &str) -> IResult<&str, u64> {
	let (input, nb) = take_while_m_n(1, 1, is_duration_chr)(input)?;
	let mult = match nb.chars().next() {
		Some('s') => 1,
		Some('m') => 60,
		Some('h') => 3_600,
		Some('d') => 86_400,
		Some('w') => 604_800,
		_ => 0,
	};
	Ok((input, mult))
}

fn get_duration_part(input: &str) -> IResult<&str, StdDuration> {
	let mut parse_u64 = map_res(digit1, |s: &str| s.parse::<u64>());
	let (input, nb) = parse_u64.parse(input)?;
	let (input, mult) = get_multiplicator(input)?;
	Ok((input, StdDuration::from_secs(nb * mult)))
}

fn parse_duration(input: &str) -> IResult<&str, Duration> {
	let (input, std_duration) = fold_many1(
		get_duration_part,
		|| StdDuration::new(0, 0),
		|mut acc: StdDuration, item| {
			acc += item;
			acc
		},
	)
	.parse(input)?;
	Ok((input, Duration(std_duration)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty_duration() {
		let res = parse_duration("");
		assert!(res.is_err());
	}

	#[test]
	fn single_second() {
		let (_, d) = parse_duration("1s").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(1));
	}

	#[test]
	fn single_minute() {
		let (_, d) = parse_duration("123m").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(123 * 60));
	}

	#[test]
	fn single_hour() {
		let (_, d) = parse_duration("10h").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(10 * 60 * 60));
	}

	#[test]
	fn single_day() {
		let (_, d) = parse_duration("3d").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(3 * 24 * 60 * 60));
	}

	#[test]
	fn single_week() {
		let (_, d) = parse_duration("1w").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(7 * 24 * 60 * 60));
	}

	#[test]
	fn mixed() {
		let (_, d) = parse_duration("1d42s").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(24 * 60 * 60 + 42));
	}

	#[test]
	fn duplicated() {
		let (_, d) = parse_duration("40s20h4h2s").unwrap();
		assert_eq!(d.get_std(), StdDuration::from_secs(24 * 60 * 60 + 42));
	}
}
