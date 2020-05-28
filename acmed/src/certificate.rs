use crate::acme_proto::Challenge;
use crate::config::{Account, Domain};
use crate::hooks::{self, ChallengeHookData, Hook, HookEnvData, HookType, PostOperationHookData};
use crate::storage::{certificate_files_exists, get_certificate};
use acme_common::crypto::X509Certificate;
use acme_common::error::Error;
use log::{debug, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

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

#[derive(Clone, Debug)]
pub struct Certificate {
    pub account: Account,
    pub domains: Vec<Domain>,
    pub algo: Algorithm,
    pub kp_reuse: bool,
    pub remote_url: String,
    pub tos_agreed: bool,
    pub https_throttle: SyncSender<crate::rate_limits::Request>,
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

    pub fn get_domain_challenge(&self, domain_name: &str) -> Result<Challenge, Error> {
        let domain_name = domain_name.to_string();
        for d in self.domains.iter() {
            // strip wildcards from domain before matching
            let base_domain = d.dns.trim_start_matches("*.");
            if base_domain == domain_name {
                let c = Challenge::from_str(&d.challenge)?;
                return Ok(c);
            }
        }
        Err(format!("{}: domain name not found", domain_name).into())
    }

    fn is_expiring(&self, cert: &X509Certificate) -> Result<bool, Error> {
        let expires_in = cert.expires_in()?;
        self.debug(&format!("Certificate expires in {} days", expires_in.as_secs() / 86400));
        // TODO: allow a custom duration (using time-parse ?)
        // 1814400 is 3 weeks (3 * 7 * 24 * 60 * 60)
        let renewal_time = Duration::new(1_814_400, 0);
        Ok(expires_in <= renewal_time)
    }

    fn has_missing_domains(&self, cert: &X509Certificate) -> bool {
        let cert_names = cert.subject_alt_names();
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

    /// Return a comma-separated list of the domains this certificate is valid for.
    pub fn domain_list(&self) -> String {
        self.domains
            .iter()
            .map(|domain| &*domain.dns)
            .collect::<Vec<&str>>()
            .join(",")
    }

    pub fn should_renew(&self) -> Result<bool, Error> {
        self.debug(&format!("Checking for renewal (domains: {})", self.domain_list()));
        if !certificate_files_exists(&self) {
            self.debug("certificate does not exist: requesting one");
            return Ok(true);
        }
        let cert = get_certificate(&self)?;

        let renew = self.has_missing_domains(&cert);
        let renew = renew || self.is_expiring(&cert)?;

        if renew {
            self.debug("The certificate will be renewed now");
        } else {
            self.debug("The certificate will not be renewed now");
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
