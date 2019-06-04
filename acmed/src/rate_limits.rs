use acme_common::error::Error;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::multi::fold_many1;
use nom::IResult;
use std::cmp;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub enum Request {
    HttpsRequest,
}

pub struct RateLimit {
    limits: Vec<(usize, Duration)>,
    sender: mpsc::SyncSender<Request>,
    receiver: mpsc::Receiver<Request>,
    log: Vec<Instant>,
}

impl RateLimit {
    pub fn new(limits: &[(usize, String)]) -> Result<Self, Error> {
        let mut max_size = 0;
        let mut parsed_limits = Vec::new();
        for (nb, raw_duration) in limits.iter() {
            if *nb > max_size {
                max_size = *nb;
            }
            let parsed_duration = parse_duration(raw_duration)?;
            parsed_limits.push((*nb, parsed_duration));
        }
        parsed_limits.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        parsed_limits.reverse();
        let (sender, receiver) = mpsc::sync_channel::<Request>(0);
        Ok(RateLimit {
            limits: parsed_limits,
            sender,
            receiver,
            log: Vec::with_capacity(max_size),
        })
    }

    pub fn get_sender(&self) -> mpsc::SyncSender<Request> {
        self.sender.clone()
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let sleep_duration = self.get_sleep_duration();
        loop {
            self.prune_log();
            if self.request_allowed() {
                match self.receiver.recv()? {
                    Request::HttpsRequest => {
                        if !self.limits.is_empty() {
                            self.log.push(Instant::now());
                        }
                    }
                }
            } else {
                // TODO: find a better sleep duration
                thread::sleep(sleep_duration);
            }
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
            let nb_req = self.log.iter().filter(move |x| **x > max_date).count();
            if nb_req >= *max_allowed {
                return false;
            }
        }
        true
    }

    fn prune_log(&mut self) {
        if let Some((_, max_limit)) = self.limits.first() {
            let prune_date = Instant::now() - *max_limit;
            self.log.retain(move |&d| d > prune_date);
        }
    }
}

fn is_duration_chr(c: char) -> bool {
    c == 's' || c == 'm' || c == 'h' || c == 'd' || c == 'w'
}

fn get_multiplicator(input: &str) -> IResult<&str, u64> {
    let (input, nb) = take_while_m_n(1, 1, is_duration_chr)(input)?;
    let mult = match nb.chars().nth(0) {
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

#[cfg(test)]
mod tests {
    use super::{parse_duration, RateLimit};

    #[test]
    fn test_rate_limit_build() {
        let l = vec![
            (5, String::from("5s")),
            (12, String::from("2m")),
            (8, String::from("5m")),
            (1, String::from("1s")),
            (2, String::from("1m")),
        ];
        let rl = RateLimit::new(l.as_slice()).unwrap();
        let ref_t = (8_usize, parse_duration("5m").unwrap());
        assert_eq!(rl.limits.first(), Some(&ref_t));
        assert_eq!(rl.log.len(), 0);
        assert_eq!(rl.log.capacity(), 12);
    }

    #[test]
    fn test_parse_duration() {
        let lst = [
            ("42s", 42),
            ("21m", 1_260),
            ("3h", 10_800),
            ("2d", 172_800),
            ("1w", 604_800),
            ("42m30s", 2_550),
            ("30s42m", 2_550),
            ("3h5m12s", 11_112),
            ("40s2s", 42),
        ];
        for (fmt, ref_sec) in lst.iter() {
            let d = parse_duration(fmt);
            assert!(d.is_ok());
            assert_eq!(d.unwrap().as_secs(), *ref_sec);
        }
    }
}
