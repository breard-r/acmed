use crate::acme_proto::structs::Directory;
use acme_common::crypto::{JwsSignatureAlgorithm, KeyType};
use acme_common::error::Error;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::multi::fold_many1;
use nom::IResult;
use std::cmp;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
    pub tos_agreed: bool,
    pub nonce: Option<String>,
    pub rl: RateLimit,
    pub dir: Directory,
    pub key_type: KeyType,
    pub signature_algorithm: JwsSignatureAlgorithm,
}

impl Endpoint {
    pub fn new(
        name: &str,
        url: &str,
        tos_agreed: bool,
        limits: &[(usize, String)],
        key_type: &Option<String>,
        signature_algorithm: &Option<String>,
    ) -> Result<Self, Error> {
        let rl = RateLimit::new(limits)?;
        let key_type = match key_type {
            Some(kt) => KeyType::from_str(&kt)?,
            None => crate::DEFAULT_ACCOUNT_KEY_TYPE,
        };
        let signature_algorithm = match signature_algorithm {
            Some(sa) => JwsSignatureAlgorithm::from_str(&sa)?,
            None => key_type.get_default_signature_alg(),
        };
        let _ = key_type.check_alg_compatibility(&signature_algorithm)?;
        Ok(Self {
            name: name.to_string(),
            url: url.to_string(),
            tos_agreed,
            nonce: None,
            rl,
            dir: Directory {
                meta: None,
                new_nonce: String::new(),
                new_account: String::new(),
                new_order: String::new(),
                new_authz: None,
                revoke_cert: String::new(),
                key_change: String::new(),
            },
            key_type,
            signature_algorithm,
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

    pub fn block_until_allowed(&mut self) {
        if self.limits.is_empty() {
            return;
        }
        let sleep_duration = self.get_sleep_duration();
        loop {
            self.prune_log();
            if self.request_allowed() {
                self.query_log.push(Instant::now());
                return;
            }
            // TODO: find a better sleep duration
            thread::sleep(sleep_duration);
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
            let max_date = Instant::now() - *duration;
            let nb_req = self
                .query_log
                .iter()
                .filter(move |x| **x > max_date)
                .count();
            if nb_req >= *max_allowed {
                return false;
            }
        }
        true
    }

    fn prune_log(&mut self) {
        if let Some((_, max_limit)) = self.limits.first() {
            let prune_date = Instant::now() - *max_limit;
            self.query_log.retain(move |&d| d > prune_date);
        }
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

fn get_duration_part(input: &str) -> IResult<&str, Duration> {
    let (input, nb) = map_res(digit1, |s: &str| s.parse::<u64>())(input)?;
    let (input, mult) = get_multiplicator(input)?;
    Ok((input, Duration::from_secs(nb * mult)))
}

fn get_duration(input: &str) -> IResult<&str, Duration> {
    fold_many1(
        get_duration_part,
        Duration::new(0, 0),
        |mut acc: Duration, item| {
            acc += item;
            acc
        },
    )(input)
}

fn parse_duration(input: &str) -> Result<Duration, Error> {
    match get_duration(input) {
        Ok((r, d)) => match r.len() {
            0 => Ok(d),
            _ => Err(format!("{}: invalid duration", input).into()),
        },
        Err(_) => Err(format!("{}: invalid duration", input).into()),
    }
}
