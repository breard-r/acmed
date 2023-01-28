use crate::acme_proto::Challenge;
use crate::hooks::{self, ChallengeHookData, Hook, HookEnvData, HookType, PostOperationHookData};
use crate::identifier::{Identifier, IdentifierType};
use crate::logs::HasLogger;
use crate::storage::{certificate_files_exists, get_certificate, FileManager};
use acme_common::crypto::{HashFunction, KeyType, SubjectAttribute, X509Certificate};
use acme_common::error::Error;
use log::{debug, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Certificate {
	pub account_name: String,
	pub identifiers: Vec<Identifier>,
	pub subject_attributes: HashMap<SubjectAttribute, String>,
	pub key_type: KeyType,
	pub csr_digest: HashFunction,
	pub kp_reuse: bool,
	pub endpoint_name: String,
	pub hooks: Vec<Hook>,
	pub crt_name: String,
	pub env: HashMap<String, String>,
	pub renew_delay: Duration,
	pub file_manager: FileManager,
}

impl fmt::Display for Certificate {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.get_id())
	}
}

impl HasLogger for Certificate {
	fn warn(&self, msg: &str) {
		warn!("certificate \"{}\": {}", &self, msg);
	}

	fn info(&self, msg: &str) {
		info!("certificate \"{}\": {}", &self, msg);
	}

	fn debug(&self, msg: &str) {
		debug!("certificate \"{}\": {}", &self, msg);
	}

	fn trace(&self, msg: &str) {
		trace!("certificate \"{}\": {}", &self, msg);
	}
}

impl Certificate {
	pub fn get_id(&self) -> String {
		format!("{}_{}", self.crt_name, self.key_type)
	}

	pub fn get_identifier_from_str(&self, identifier: &str) -> Result<Identifier, Error> {
		let identifier = identifier.to_string();
		for d in self.identifiers.iter() {
			let val = match d.id_type {
				// strip wildcards from domain before matching
				IdentifierType::Dns => d.value.trim_start_matches("*.").to_string(),
				IdentifierType::Ip => d.value.to_owned(),
			};
			if identifier == val {
				return Ok(d.clone());
			}
		}
		Err(format!("{}: identifier not found", identifier).into())
	}

	fn is_expiring(&self, cert: &X509Certificate) -> Result<bool, Error> {
		let expires_in = cert.expires_in()?;
		self.debug(&format!(
			"certificate expires in {} days ({} days delay)",
			expires_in.as_secs() / 86400,
			self.renew_delay.as_secs() / 86400,
		));
		Ok(expires_in <= self.renew_delay)
	}

	fn has_missing_identifiers(&self, cert: &X509Certificate) -> bool {
		let cert_names = cert.subject_alt_names();
		let req_names = self
			.identifiers
			.iter()
			.map(|v| v.value.to_owned())
			.collect::<HashSet<String>>();
		let has_miss = req_names.difference(&cert_names).count() != 0;
		if has_miss {
			let domains = req_names
				.difference(&cert_names)
				.map(std::borrow::ToOwned::to_owned)
				.collect::<Vec<String>>()
				.join(", ");
			self.debug(&format!(
				"the certificate does not include the following domains: {}",
				domains
			));
		}
		has_miss
	}

	/// Return a comma-separated list of the domains this certificate is valid for.
	pub fn identifier_list(&self) -> String {
		self.identifiers
			.iter()
			.map(|d| d.value.as_str())
			.collect::<Vec<&str>>()
			.join(",")
	}

	pub fn should_renew(&self) -> Result<bool, Error> {
		self.debug(&format!(
			"checking for renewal (identifiers: {})",
			self.identifier_list()
		));
		if !certificate_files_exists(&self.file_manager) {
			self.debug("certificate does not exist: requesting one");
			return Ok(true);
		}
		let cert = get_certificate(&self.file_manager)?;

		let renew_ident = self.has_missing_identifiers(&cert);
		if renew_ident {
			self.debug("the current certificate doesn't include all the required identifiers");
		}
		let renew_exp = self.is_expiring(&cert)?;
		if renew_exp {
			self.debug("the certificate is expiring");
		}
		let renew = renew_ident || renew_exp;

		if renew {
			self.debug("the certificate will be renewed now");
		} else {
			self.debug("the certificate will not be renewed now");
		}
		Ok(renew)
	}

	pub fn call_challenge_hooks(
		&self,
		file_name: &str,
		proof: &str,
		identifier: &str,
	) -> Result<(ChallengeHookData, HookType), Error> {
		let identifier = self.get_identifier_from_str(identifier)?;
		let mut hook_data = ChallengeHookData {
			challenge: identifier.challenge.to_string(),
			identifier: identifier.value.to_owned(),
			identifier_tls_alpn: identifier.get_tls_alpn_name().unwrap_or_default(),
			file_name: file_name.to_string(),
			proof: proof.to_string(),
			is_clean_hook: false,
			env: HashMap::new(),
		};
		hook_data.set_env(&self.env);
		hook_data.set_env(&identifier.env);
		let hook_type = match identifier.challenge {
			Challenge::Http01 => (HookType::ChallengeHttp01, HookType::ChallengeHttp01Clean),
			Challenge::Dns01 => (HookType::ChallengeDns01, HookType::ChallengeDns01Clean),
			Challenge::TlsAlpn01 => (
				HookType::ChallengeTlsAlpn01,
				HookType::ChallengeTlsAlpn01Clean,
			),
		};
		hooks::call(self, &self.hooks, &hook_data, hook_type.0)?;
		Ok((hook_data, hook_type.1))
	}

	pub fn call_challenge_hooks_clean(
		&self,
		data: &ChallengeHookData,
		hook_type: HookType,
	) -> Result<(), Error> {
		hooks::call(self, &self.hooks, data, hook_type)
	}

	pub fn call_post_operation_hooks(&self, status: &str, is_success: bool) -> Result<(), Error> {
		let identifiers = self
			.identifiers
			.iter()
			.map(|d| d.value.to_owned())
			.collect::<Vec<String>>();
		let mut hook_data = PostOperationHookData {
			identifiers,
			key_type: self.key_type.to_string(),
			status: status.to_string(),
			is_success,
			env: HashMap::new(),
		};
		hook_data.set_env(&self.env);
		hooks::call(self, &self.hooks, &hook_data, HookType::PostOperation)?;
		Ok(())
	}
}
