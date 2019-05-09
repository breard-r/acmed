use crate::acme_proto::Challenge;
use crate::config::{Account, Domain, HookType};
use crate::hooks::{self, ChallengeHookData, Hook, HookEnvData, PostOperationHookData};
use crate::storage::{certificate_files_exists, get_certificate};
use acme_common::error::Error;
use log::{debug, trace};
use openssl::x509::X509;
use std::collections::{HashMap, HashSet};
use std::fmt;
use time::{strptime, Duration};

// OpenSSL ASN1_TIME_print madness
// The real fix would be to add Asn1TimeRef access in the openssl crate.
//
// https://github.com/sfackler/rust-openssl/issues/687
// https://github.com/sfackler/rust-openssl/pull/673
fn parse_openssl_time_string(time: &str) -> Result<time::Tm, Error> {
    debug!("Parsing OpenSSL time: \"{}\"", time);
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
            trace!("Format \"{}\" matches", fmt);
            return Ok(t);
        }
        trace!("Format \"{}\" does not match", fmt);
    }
    let msg = format!("invalid time string: {}", time);
    Err(msg.into())
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
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hooks = self
            .hooks
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        let domains = self
            .domains
            .iter()
            .map(|d| format!("{} ({})", d.dns, d.challenge))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "Certificate information:
Domains: {domains}
Algorithm: {algo}
Account: {account}
Private key reuse: {kp_reuse}
Hooks: {hooks}",
            domains = domains,
            algo = self.algo,
            account = self.account.name,
            kp_reuse = self.kp_reuse,
            hooks = hooks,
        )
    }
}

impl Certificate {
    pub fn get_domain_challenge(&self, domain_name: &str) -> Result<Challenge, Error> {
        let domain_name = domain_name.to_string();
        for d in self.domains.iter() {
            if d.dns == domain_name {
                let c = Challenge::from_str(&d.challenge)?;
                return Ok(c);
            }
        }
        let msg = format!("{}: domain name not found", domain_name);
        Err(msg.into())
    }

    fn is_expiring(&self, cert: &X509) -> Result<bool, Error> {
        let not_after = cert.not_after().to_string();
        let not_after = parse_openssl_time_string(&not_after)?;
        debug!("not after: {}", not_after.asctime());
        // TODO: allow a custom duration (using time-parse ?)
        let renewal_time = not_after - Duration::weeks(3);
        debug!("renew on: {}", renewal_time.asctime());
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
            debug!(
                "The certificate does not include the following domains: {}",
                domains
            );
        }
        has_miss
    }

    pub fn should_renew(&self) -> Result<bool, Error> {
        if !certificate_files_exists(&self) {
            debug!("certificate does not exist: requesting one");
            return Ok(true);
        }
        let cert = get_certificate(&self)?;

        let renew = self.has_missing_domains(&cert);
        let renew = renew || self.is_expiring(&cert)?;

        if renew {
            debug!("The certificate will be renewed now.");
        } else {
            debug!("The certificate will not be renewed now.");
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
    use super::parse_openssl_time_string;

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
        for time_str in time_str_lst.iter() {
            let time_res = parse_openssl_time_string(time_str);
            assert!(time_res.is_ok());
        }
    }
}
