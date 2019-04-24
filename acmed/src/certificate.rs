use crate::acme_proto::Challenge;
use crate::config::Account;
use crate::error::Error;
use crate::hooks::{self, ChallengeHookData, Hook, PostOperationHookData};
use crate::storage::{certificate_files_exists, get_certificate};
use log::debug;
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
    pub domains: Vec<String>,
    pub algo: Algorithm,
    pub kp_reuse: bool,
    pub remote_url: String,
    pub tos_agreed: bool,
    pub challenge: Challenge,
    pub challenge_hooks: Vec<Hook>,
    pub post_operation_hooks: Vec<Hook>,
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
    pub file_pre_create_hooks: Vec<Hook>,
    pub file_post_create_hooks: Vec<Hook>,
    pub file_pre_edit_hooks: Vec<Hook>,
    pub file_post_edit_hooks: Vec<Hook>,
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let challenge_hooks = self
            .challenge_hooks
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        let post_operation_hooks = self
            .post_operation_hooks
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "Certificate information:
Domains: {domains}
Algorithm: {algo}
Account: {account}
Private key reuse: {kp_reuse}
Challenge: {challenge}
Challenge hooks: {challenge_hooks}
Post operation hooks: {post_operation_hooks}",
            domains = self.domains.join(", "),
            algo = self.algo,
            account = self.account.name,
            kp_reuse = self.kp_reuse,
            challenge = self.challenge,
            challenge_hooks = challenge_hooks,
            post_operation_hooks = post_operation_hooks,
        )
    }
}

impl Certificate {
    pub fn should_renew(&self) -> Result<bool, Error> {
        if !certificate_files_exists(&self) {
            debug!("certificate does not exist: requesting one");
            return Ok(true);
        }
        let cert = get_certificate(&self)?;
        let not_after = cert.not_after().to_string();
        // TODO: check the time format and put it in a const
        let not_after = match strptime(&not_after, "%b %d %T %Y") {
            Ok(t) => t,
            Err(_) => {
                let msg = format!("invalid time string: {}", not_after);
                return Err(msg.into());
            }
        };
        debug!("not after: {}", not_after.asctime());
        // TODO: allow a custom duration (using time-parse ?)
        let renewal_time = not_after - Duration::weeks(3);
        debug!("renew on: {}", renewal_time.asctime());
        let renew = time::now_utc() > renewal_time;
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
    ) -> Result<(), Error> {
        let hook_data = ChallengeHookData {
            domains: self.domains.to_owned(),
            algorithm: self.algo.to_string(),
            challenge: self.challenge.to_string(),
            current_domain: domain.to_string(),
            file_name: file_name.to_string(),
            proof: proof.to_string(),
        };
        hooks::call_multiple(&hook_data, &self.challenge_hooks)?;
        Ok(())
    }

    pub fn call_post_operation_hooks(&self, status: &str) -> Result<(), Error> {
        let hook_data = PostOperationHookData {
            domains: self.domains.to_owned(),
            algorithm: self.algo.to_string(),
            challenge: self.challenge.to_string(),
            status: status.to_string(),
        };
        hooks::call_multiple(&hook_data, &self.post_operation_hooks)?;
        Ok(())
    }
}
