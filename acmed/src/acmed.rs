use acme_lib::{Directory, DirectoryUrl};
use crate::config::{self, Hook};
use crate::errors::Error;
use crate::storage::Storage;
use handlebars::Handlebars;
use log::{debug, info, warn};
use openssl;
use serde::Serialize;
use std::{fmt, thread};
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use x509_parser::parse_x509_der;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum Format {
    Der,
    Pem,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Format::Der => "der",
            Format::Pem => "pem",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug)]
pub enum Challenge {
    Http01,
    Dns01,
}

impl Challenge {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "http-01" => Ok(Challenge::Http01),
            "dns-01" => Ok(Challenge::Dns01),
            _ => Err(Error::new(&format!("{}: unknown challenge.", s))),
        }
    }
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Challenge::Http01 => "http-01",
            Challenge::Dns01 => "dns-01",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug)]
pub enum Algorithm {
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

impl Algorithm {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "rsa2048" => Ok(Algorithm::Rsa2048),
            "rsa4096" => Ok(Algorithm::Rsa4096),
            "ecdsa_p256" => Ok(Algorithm::EcdsaP256),
            "ecdsa_p384" => Ok(Algorithm::EcdsaP384),
            _ => Err(Error::new(&format!("{}: unknown algorithm.", s))),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Algorithm::Rsa2048 => "rsa2048",
            Algorithm::Rsa4096 => "rsa4096",
            Algorithm::EcdsaP256 => "ecdsa-p256",
            Algorithm::EcdsaP384 => "ecdsa-p384",
        };
        write!(f, "{}", s)
    }
}

#[derive(Serialize)]
struct HookData {
    // Common
    domains: Vec<String>,
    algorithm: String,
    challenge: String,
    status: String,
    // Challenge hooks
    current_domain: String,
    token: String,
    proof: String,
}

macro_rules! get_hook_output {
    ($out: expr, $reg: ident, $data: expr) => {{
        match $out {
            Some(path) => {
                let path = $reg.render_template(path, $data)?;
                let file = File::create(path)?;
                Stdio::from(file)
            }
            None => Stdio::null(),
        }
    }};
}

impl HookData {
    pub fn call(&self, hook: &Hook) -> Result<(), Error> {
        let reg = Handlebars::new();
        let mut v = vec![];
        let args = match &hook.args {
            Some(lst) => {
                for fmt in lst.iter() {
                    let s = reg.render_template(fmt, &self)?;
                    v.push(s);
                }
                v.as_slice()
            }
            None => &[],
        };
        let mut cmd = Command::new(&hook.cmd)
            .args(args)
            .stdout(get_hook_output!(&hook.stdout, reg, &self))
            .stderr(get_hook_output!(&hook.stderr, reg, &self))
            .stdin(match &hook.stdin {
                Some(_) => Stdio::piped(),
                None => Stdio::null(),
            })
            .spawn()?;
        if hook.stdin.is_some() {
            let data_in = reg.render_template(&hook.stdin.to_owned().unwrap(), &self)?;
            let stdin = cmd.stdin.as_mut().ok_or("stdin not found")?;
            stdin.write_all(data_in.as_bytes())?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Certificate {
    domains: Vec<String>,
    algo: Algorithm,
    kp_reuse: bool,
    storage: Storage,
    email: String,
    remote_url: String,
    challenge: Challenge,
    challenge_hooks: Vec<Hook>,
    post_operation_hooks: Vec<Hook>,
}

impl Certificate {
    fn should_renew(&self) -> bool {
        let domain = self.domains.first().unwrap();
        let raw_cert = match self.storage.get_certificate(&Format::Der) {
            Ok(c) => match c {
                Some(d) => d,
                None => {
                    debug!(
                        "{} certificate for {} is empty or does not exists",
                        self.algo, domain
                    );
                    return true;
                }
            },
            Err(e) => {
                warn!("{}", e);
                return true;
            }
        };
        match parse_x509_der(&raw_cert) {
            Ok((_, cert)) => {
                // TODO: allow a custom duration (using time-parse ?)
                let renewal_time =
                    cert.tbs_certificate.validity.not_after - time::Duration::weeks(3);
                debug!(
                    "{} certificate for {}: not after: {}",
                    self.algo,
                    domain,
                    cert.tbs_certificate.validity.not_after.asctime()
                );
                debug!(
                    "{} certificate for {}: renew on: {}",
                    self.algo,
                    domain,
                    renewal_time.asctime()
                );
                time::now_utc() > renewal_time
            }
            Err(_) => true,
        }
    }

    fn call_challenge_hooks(&self, token: &str, proof: &str, domain: &str) -> Result<(), Error> {
        let hook_data = HookData {
            domains: self.domains.to_owned(),
            algorithm: self.algo.to_string(),
            challenge: self.challenge.to_string(),
            status: format!("Validation pending for {}", domain),
            current_domain: domain.to_string(),
            token: token.to_string(),
            proof: proof.to_string(),
        };
        for hook in self.challenge_hooks.iter() {
            hook_data.call(&hook)?;
        }
        Ok(())
    }

    fn call_post_operation_hooks(&self, status: &str) -> Result<(), Error> {
        let hook_data = HookData {
            domains: self.domains.to_owned(),
            algorithm: self.algo.to_string(),
            challenge: self.challenge.to_string(),
            status: status.to_string(),
            current_domain: "".to_string(),
            token: "".to_string(),
            proof: "".to_string(),
        };
        for hook in self.post_operation_hooks.iter() {
            hook_data.call(&hook)?;
        }
        Ok(())
    }

    fn renew(&mut self) -> Result<(), Error> {
        // TODO: do it in a separated thread since it may take a while
        let (name, alt_names_str) = self.domains.split_first().unwrap();
        let mut alt_names = vec![];
        for n in alt_names_str.iter() {
            alt_names.push(n.as_str());
        }
        info!("Renewing the {} certificate for {}", self.algo, name);
        let url = DirectoryUrl::Other(&self.remote_url);
        let dir = Directory::from_url(self.storage.to_owned(), url)?;
        let acc = dir.account(&self.email)?;
        let mut ord_new = acc.new_order(name, &alt_names)?;
        let ord_csr = loop {
            if let Some(ord_csr) = ord_new.confirm_validations() {
                break ord_csr;
            }
            let auths = ord_new.authorizations()?;
            for auth in auths.iter() {
                match self.challenge {
                    Challenge::Http01 => {
                        let chall = auth.http_challenge();
                        let token = chall.http_token();
                        let proof = chall.http_proof();
                        self.call_challenge_hooks(&token, &proof, auth.domain_name())?;
                        chall.validate(crate::DEFAULT_POOL_TIME)?;
                    }
                    Challenge::Dns01 => {
                        let chall = auth.dns_challenge();
                        let proof = chall.dns_proof();
                        self.call_challenge_hooks("", &proof, auth.domain_name())?;
                        chall.validate(crate::DEFAULT_POOL_TIME)?;
                    }
                };
            }
            ord_new.refresh()?;
        };

        let mut raw_crt = vec![];
        let mut raw_pk = vec![];
        if self.kp_reuse {
            raw_crt = self.storage
                .get_certificate(&Format::Der)?
                .unwrap_or_else(|| vec![]);
            raw_pk = self.storage
                .get_private_key(&Format::Der)?
                .unwrap_or_else(|| vec![]);
        };
        let (pkey_pri, pkey_pub) = if !raw_crt.is_empty() && !raw_pk.is_empty() {
            (
                openssl::pkey::PKey::private_key_from_der(&raw_pk)?,
                openssl::x509::X509::from_der(&raw_crt)?.public_key()?,
            )
        } else {
            match self.algo {
                Algorithm::Rsa2048 => acme_lib::create_rsa_key(2048),
                Algorithm::Rsa4096 => acme_lib::create_rsa_key(4096),
                Algorithm::EcdsaP256 => acme_lib::create_p256_key(),
                Algorithm::EcdsaP384 => acme_lib::create_p384_key(),
            }
        };
        let ord_cert = ord_csr.finalize_pkey(pkey_pri, pkey_pub, crate::DEFAULT_POOL_TIME)?;
        ord_cert.download_and_save_cert()?;
        Ok(())
    }
}

pub struct Acmed {
    certs: Vec<Certificate>,
}

impl Acmed {
    pub fn new(config_file: &str) -> Result<Self, Error> {
        let cnf = config::from_file(config_file)?;

        let mut certs = Vec::new();
        for crt in cnf.certificate.iter() {
            let cert = Certificate {
                domains: crt.domains.to_owned(),
                algo: crt.get_algorithm()?,
                kp_reuse: crt.get_kp_reuse(),
                storage: Storage {
                    account_directory: cnf.get_account_dir(),
                    account_name: crt.email.to_owned(),
                    crt_directory: crt.get_crt_dir(&cnf),
                    crt_name: crt.get_crt_name(),
                    crt_name_format: crt.get_crt_name_format(),
                    formats: crt.get_formats()?,
                    algo: crt.get_algorithm()?,
                    cert_file_mode: cnf.get_cert_file_mode(),
                    cert_file_owner: cnf.get_cert_file_user(),
                    cert_file_group: cnf.get_cert_file_group(),
                    pk_file_mode: cnf.get_pk_file_mode(),
                    pk_file_owner: cnf.get_pk_file_user(),
                    pk_file_group: cnf.get_pk_file_group(),
                },
                email: crt.email.to_owned(),
                remote_url: crt.get_remote_url(&cnf)?,
                challenge: crt.get_challenge()?,
                challenge_hooks: crt.get_challenge_hooks(&cnf)?,
                post_operation_hooks: crt.get_post_operation_hook(&cnf)?,
            };
            certs.push(cert);
        }

        Ok(Acmed { certs })
    }

    pub fn run(&mut self) {
        loop {
            for crt in self.certs.iter_mut() {
                debug!("{:?}", crt);
                if crt.should_renew() {
                    // TODO: keep track of (not yet implemented) threads and wait for them to end.
                    let status = match crt.renew() {
                        Ok(_) => "Success.".to_string(),
                        Err(e) => {
                            let msg = format!(
                                "Unable to renew the {} certificate for {}: {}",
                                crt.algo,
                                crt.domains.first().unwrap(),
                                e
                            );
                            warn!("{}", msg);
                            format!("Failed: {}", msg)
                        }
                    };
                    match crt.call_post_operation_hooks(&status) {
                        Ok(_) => {}
                        Err(e) => {
                            let msg = format!(
                                "{} certificate for {}: post-operation hook error: {}",
                                crt.algo,
                                crt.domains.first().unwrap(),
                                e
                            );
                            warn!("{}", msg);
                        }
                    };
                }
            }

            thread::sleep(Duration::from_secs(crate::DEFAULT_SLEEP_TIME));
        }
    }
}
