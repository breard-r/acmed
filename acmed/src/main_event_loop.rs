use crate::account::Account;
use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::config;
use crate::endpoint::Endpoint;
use crate::hooks::HookType;
use crate::logs::HasLogger;
use crate::storage::FileManager;
use acme_common::error::Error;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

type AccountSync = Arc<RwLock<Account>>;
type EndpointSync = Arc<RwLock<Endpoint>>;

fn renew_certificate(
    crt: &Certificate,
    root_certs: &[String],
    endpoint: &mut Endpoint,
    account: &mut Account,
) {
    let (status, is_success) = match request_certificate(crt, root_certs, endpoint, account) {
        Ok(_) => ("success".to_string(), true),
        Err(e) => {
            let e = e.prefix("unable to renew the certificate");
            crt.warn(&e.message);
            (e.message, false)
        }
    };
    match crt.call_post_operation_hooks(&status, is_success) {
        Ok(_) => {}
        Err(e) => {
            let e = e.prefix("post-operation hook error");
            crt.warn(&e.message);
        }
    };
}

pub struct MainEventLoop {
    certs: Vec<Certificate>,
    root_certs: Vec<String>,
    accounts: HashMap<String, AccountSync>,
    endpoints: HashMap<String, EndpointSync>,
}

impl MainEventLoop {
    pub fn new(config_file: &str, root_certs: &[&str]) -> Result<Self, Error> {
        let cnf = config::from_file(config_file)?;
        let file_hooks = vec![
            HookType::FilePreCreate,
            HookType::FilePostCreate,
            HookType::FilePreEdit,
            HookType::FilePostEdit,
        ]
        .into_iter()
        .collect();
        let cert_hooks = vec![
            HookType::ChallengeHttp01,
            HookType::ChallengeHttp01Clean,
            HookType::ChallengeDns01,
            HookType::ChallengeDns01Clean,
            HookType::ChallengeTlsAlpn01,
            HookType::ChallengeTlsAlpn01Clean,
            HookType::PostOperation,
        ]
        .into_iter()
        .collect();

        let mut accounts = HashMap::new();
        for acc in cnf.account.iter() {
            let fm = FileManager {
                account_directory: cnf.get_account_dir(),
                account_name: acc.name.clone(),
                crt_name: String::new(),
                crt_name_format: String::new(),
                crt_directory: String::new(),
                crt_key_type: String::new(),
                cert_file_mode: cnf.get_cert_file_mode(),
                cert_file_owner: cnf.get_cert_file_user(),
                cert_file_group: cnf.get_cert_file_group(),
                pk_file_mode: cnf.get_pk_file_mode(),
                pk_file_owner: cnf.get_pk_file_user(),
                pk_file_group: cnf.get_pk_file_group(),
                hooks: acc
                    .get_hooks(&cnf)?
                    .iter()
                    .filter(|h| !h.hook_type.is_disjoint(&file_hooks))
                    .map(|e| e.to_owned())
                    .collect(),
                env: acc.env.clone(),
            };
            let account = acc.to_generic(&fm)?;
            accounts.insert(acc.name.clone(), account);
        }

        let mut certs = Vec::new();
        let mut endpoints = HashMap::new();
        for (i, crt) in cnf.certificate.iter().enumerate() {
            let endpoint = crt.get_endpoint(&cnf)?;
            let endpoint_name = endpoint.name.clone();
            let crt_name = crt.get_crt_name()?;
            let key_type = crt.get_key_type()?;
            let hooks = crt.get_hooks(&cnf)?;
            let fm = FileManager {
                account_directory: cnf.get_account_dir(),
                account_name: crt.account.clone(),
                crt_name: crt_name.clone(),
                crt_name_format: crt.get_crt_name_format(),
                crt_directory: crt.get_crt_dir(&cnf),
                crt_key_type: key_type.to_string(),
                cert_file_mode: cnf.get_cert_file_mode(),
                cert_file_owner: cnf.get_cert_file_user(),
                cert_file_group: cnf.get_cert_file_group(),
                pk_file_mode: cnf.get_pk_file_mode(),
                pk_file_owner: cnf.get_pk_file_user(),
                pk_file_group: cnf.get_pk_file_group(),
                hooks: hooks
                    .iter()
                    .filter(|h| !h.hook_type.is_disjoint(&file_hooks))
                    .map(|e| e.to_owned())
                    .collect(),
                env: crt.env.clone(),
            };
            let cert = Certificate {
                account_name: crt.account.clone(),
                identifiers: crt.get_identifiers()?,
                subject_attributes: crt.subject_attributes.to_generic(),
                key_type,
                csr_digest: crt.get_csr_digest()?,
                kp_reuse: crt.get_kp_reuse(),
                endpoint_name: endpoint_name.clone(),
                hooks: hooks
                    .iter()
                    .filter(|h| !h.hook_type.is_disjoint(&cert_hooks))
                    .map(|e| e.to_owned())
                    .collect(),
                crt_name,
                env: crt.env.to_owned(),
                id: i + 1,
                renew_delay: crt.get_renew_delay(&cnf)?,
                file_manager: fm,
            };
            match accounts.get_mut(&crt.account) {
                Some(acc) => acc.add_endpoint_name(&endpoint_name),
                None => {
                    let msg = format!("{}: account not found", &crt.account);
                    return Err(msg.into());
                }
            };
            endpoints.entry(endpoint_name).or_insert(endpoint);
            certs.push(cert);
        }

        Ok(MainEventLoop {
            certs,
            root_certs: root_certs.iter().map(|v| (*v).to_string()).collect(),
            accounts: accounts
                .iter()
                .map(|(k, v)| (k.to_owned(), Arc::new(RwLock::new(v.to_owned()))))
                .collect(),
            endpoints: endpoints
                .iter()
                .map(|(k, v)| (k.to_owned(), Arc::new(RwLock::new(v.to_owned()))))
                .collect(),
        })
    }

    pub fn run(&mut self) {
        loop {
            self.renew_certificates();
            thread::sleep(Duration::from_secs(crate::DEFAULT_SLEEP_TIME));
        }
    }

    fn renew_certificates(&mut self) {
        let mut handles = vec![];
        for (ep_name, endpoint_lock) in self.endpoints.iter_mut() {
            let mut certs_to_renew = vec![];
            for crt in self.certs.iter() {
                if crt.endpoint_name == *ep_name {
                    match crt.should_renew() {
                        Ok(true) => {
                            let crt_arc = Arc::new(crt.clone());
                            certs_to_renew.push(crt_arc);
                        }
                        Ok(false) => {}
                        Err(e) => {
                            crt.warn(&e.message);
                        }
                    }
                }
            }
            let mut accounts_lock = self.accounts.clone();
            let ep_lock = endpoint_lock.clone();
            let rc = self.root_certs.clone();
            let handle = thread::spawn(move || {
                let mut endpoint = ep_lock.write().unwrap();
                for crt in certs_to_renew {
                    if let Some(acc_lock) = accounts_lock.get_mut(&crt.account_name) {
                        let mut account = acc_lock.write().unwrap();
                        renew_certificate(&crt, &rc, &mut endpoint, &mut account);
                    };
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            let _ = handle.join();
        }
    }
}
