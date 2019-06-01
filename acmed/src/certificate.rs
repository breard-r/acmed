use crate::acme_proto::Challenge;
use crate::config::{Account, Domain, HookType};
use crate::hooks::{self, ChallengeHookData, Hook, HookEnvData, PostOperationHookData};
use crate::storage::{certificate_files_exists, get_certificate};
use acme_common::error::Error;
use log::{debug, info, trace, warn};
use openssl::x509::X509;
use std::collections::{HashMap, HashSet};
use std::fmt;
use time::{strptime, Duration};

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
            _ => Err(format!("{}: unknown algorithm.", s).into()),
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

#[derive(Debug)]
pub struct Certificate {
    pub account: Account,
    pub domains: Vec<Domain>,
    pub algo: Algorithm,
    pub kp_reuse: bool,
    pub remote_url: String,
    pub tos_agreed: bool,
    pub hooks: Vec<Hook>,
    pub account_directory: String,
    pub crt_directory: String,
    pub crt_name: String,
    pub crt_name_format: String,
    pub cert_file_mode: u32,
    pub cert_file_owner: Option<String>,
    pub cert_file_group: Option<String>,
    pub pk_file_mode: u32,
    pub pk_file_owner: Option<String>,
    pub pk_file_group: Option<String>,
    pub env: HashMap<String, String>,
    pub id: usize,
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: set a more "funky" id
        write!(f, "crt-{:x}", self.id)
    }
}

impl Certificate {
    pub fn warn(&self, msg: &str) {
        warn!("{}: {}", &self, msg);
    }

    pub fn info(&self, msg: &str) {
        info!("{}: {}", &self, msg);
    }

    pub fn debug(&self, msg: &str) {
        debug!("{}: {}", &self, msg);
    }

    pub fn trace(&self, msg: &str) {
        trace!("{}: {}", &self, msg);
    }

    // OpenSSL ASN1_TIME_print madness
    // The real fix would be to add Asn1TimeRef access in the openssl crate.
    //
    // https://github.com/sfackler/rust-openssl/issues/687
    // https://github.com/sfackler/rust-openssl/pull/673
    fn parse_openssl_time_string(&self, time: &str) -> Result<time::Tm, Error> {
        self.debug(&format!("Parsing OpenSSL time: \"{}\"", time));
        let formats = [
            "%b %d %T %Y %Z",
            "%b  %d %T %Y %Z",
            "%b %d %T %Y",
            "%b  %d %T %Y",
            "%b %d %T.%f %Y %Z",
            "%b  %d %T.%f %Y %Z",
            "%b %d %T.%f %Y",
            "%b  %d %T.%f %Y",
        ];
        for fmt in formats.iter() {
            if let Ok(t) = strptime(time, fmt) {
                self.trace(&format!("Format \"{}\" matches", fmt));
                return Ok(t);
            }
            self.trace(&format!("Format \"{}\" does not match", fmt));
        }
        Err(format!("invalid time string: {}", time).into())
    }

    pub fn get_domain_challenge(&self, domain_name: &str) -> Result<Challenge, Error> {
        let domain_name = domain_name.to_string();
        for d in self.domains.iter() {
            if d.dns == domain_name {
                let c = Challenge::from_str(&d.challenge)?;
                return Ok(c);
            }
        }
        Err(format!("{}: domain name not found", domain_name).into())
    }

    fn is_expiring(&self, cert: &X509) -> Result<bool, Error> {
        let not_after = cert.not_after().to_string();
        let not_after = self.parse_openssl_time_string(&not_after)?;
        self.debug(&format!("not after: {}", not_after.asctime()));
        // TODO: allow a custom duration (using time-parse ?)
        let renewal_time = not_after - Duration::weeks(3);
        self.debug(&format!("renew on: {}", renewal_time.asctime()));
        Ok(time::now_utc() > renewal_time)
    }

    fn has_missing_domains(&self, cert: &X509) -> bool {
        let cert_names = match cert.subject_alt_names() {
            Some(s) => s
                .iter()
                .filter(|v| v.dnsname().is_some())
                .map(|v| v.dnsname().unwrap().to_string())
                .collect(),
            None => HashSet::new(),
        };
        let req_names = self
            .domains
            .iter()
            .map(|v| v.dns.to_owned())
            .collect::<HashSet<String>>();
        let has_miss = req_names.difference(&cert_names).count() != 0;
        if has_miss {
            let domains = req_names
                .difference(&cert_names)
                .map(std::borrow::ToOwned::to_owned)
                .collect::<Vec<String>>()
                .join(", ");
            self.debug(&format!(
                "The certificate does not include the following domains: {}",
                domains
            ));
        }
        has_miss
    }

    pub fn should_renew(&self) -> Result<bool, Error> {
        if !certificate_files_exists(&self) {
            self.debug("certificate does not exist: requesting one");
            return Ok(true);
        }
        let cert = get_certificate(&self)?;

        let renew = self.has_missing_domains(&cert);
        let renew = renew || self.is_expiring(&cert)?;

        if renew {
            self.debug("The certificate will be renewed now.");
        } else {
            self.debug("The certificate will not be renewed now.");
        }
        Ok(renew)
    }

    pub fn call_challenge_hooks(
        &self,
        file_name: &str,
        proof: &str,
        domain: &str,
    ) -> Result<(ChallengeHookData, HookType), Error> {
        let challenge = self.get_domain_challenge(domain)?;
        let mut hook_data = ChallengeHookData {
            challenge: challenge.to_string(),
            domain: domain.to_string(),
            file_name: file_name.to_string(),
            proof: proof.to_string(),
            is_clean_hook: false,
            env: HashMap::new(),
        };
        hook_data.set_env(&self.env);
        for d in self.domains.iter().filter(|d| d.dns == domain) {
            hook_data.set_env(&d.env);
        }
        let hook_type = match challenge {
            Challenge::Http01 => (HookType::ChallengeHttp01, HookType::ChallengeHttp01Clean),
            Challenge::Dns01 => (HookType::ChallengeDns01, HookType::ChallengeDns01Clean),
            Challenge::TlsAlpn01 => (
                HookType::ChallengeTlsAlpn01,
                HookType::ChallengeTlsAlpn01Clean,
            ),
        };
        hooks::call(self, &hook_data, hook_type.0)?;
        Ok((hook_data, hook_type.1))
    }

    pub fn call_challenge_hooks_clean(
        &self,
        data: &ChallengeHookData,
        hook_type: HookType,
    ) -> Result<(), Error> {
        hooks::call(self, data, hook_type)
    }

    pub fn call_post_operation_hooks(&self, status: &str, is_success: bool) -> Result<(), Error> {
        let domains = self
            .domains
            .iter()
            .map(|d| format!("{} ({})", d.dns, d.challenge))
            .collect::<Vec<String>>();
        let mut hook_data = PostOperationHookData {
            domains,
            algorithm: self.algo.to_string(),
            status: status.to_string(),
            is_success,
            env: HashMap::new(),
        };
        hook_data.set_env(&self.env);
        hooks::call(self, &hook_data, HookType::PostOperation)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, Certificate};
    use std::collections::HashMap;

    fn get_dummy_certificate() -> Certificate {
        Certificate {
            account: crate::config::Account {
                name: String::new(),
                email: String::new(),
            },
            domains: Vec::new(),
            algo: Algorithm::Rsa2048,
            kp_reuse: false,
            remote_url: String::new(),
            tos_agreed: false,
            hooks: Vec::new(),
            account_directory: String::new(),
            crt_directory: String::new(),
            crt_name: String::new(),
            crt_name_format: String::new(),
            cert_file_mode: 0,
            cert_file_owner: None,
            cert_file_group: None,
            pk_file_mode: 0,
            pk_file_owner: None,
            pk_file_group: None,
            env: HashMap::new(),
            id: 0,
        }
    }

    #[test]
    fn test_parse_openssl_time() {
        let time_str_lst = [
            "May  7 18:34:07 2024",
            "May  7 18:34:07 2024 GMT",
            "May 17 18:34:07 2024",
            "May 17 18:34:07 2024 GMT",
            "May  7 18:34:07.922661874 2024",
            "May  7 18:34:07.922661874 2024 GMT",
            "May 17 18:34:07.922661874 2024",
            "May 17 18:34:07.922661874 2024 GMT",
        ];
        let crt = get_dummy_certificate();
        for time_str in time_str_lst.iter() {
            let time_res = crt.parse_openssl_time_string(time_str);
            assert!(time_res.is_ok());
        }
    }
}
