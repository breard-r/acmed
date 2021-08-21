use acme_common::error::Error;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::multi::fold_many1;
use nom::IResult;
use std::time::Duration;

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

fn get_duration_part(input: &str) -> IResult<&str, Duration> {
    let (input, nb) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, mult) = get_multiplicator(input)?;
    Ok((input, Duration::from_secs(nb * mult)))
}

fn get_duration(input: &str) -> IResult<&str, Duration> {
    fold_many1(
        get_duration_part,
        || Duration::new(0, 0),
        |mut acc: Duration, item| {
            acc += item;
            acc
        },
    )(input)
}

pub fn parse_duration(input: &str) -> Result<Duration, Error> {
    match get_duration(input) {
        Ok((r, d)) => match r.len() {
            0 => Ok(d),
            _ => Err(format!("{}: invalid duration", input).into()),
        },
        Err(_) => Err(format!("{}: invalid duration", input).into()),
    }
}
