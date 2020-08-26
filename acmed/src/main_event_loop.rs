use crate::acme_proto::account::init_account;
use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::config;
use crate::endpoint::Endpoint;
use acme_common::error::Error;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

type EndpointSync = Arc<RwLock<Endpoint>>;

fn renew_certificate(crt: &Certificate, root_certs: &[String], endpoint: &mut Endpoint) {
    let (status, is_success) = match request_certificate(crt, root_certs, endpoint) {
        Ok(_) => ("Success.".to_string(), true),
        Err(e) => {
            let e = e.prefix("Unable to renew the certificate");
            crt.warn(&e.message);
            (e.message, false)
        }
    };
    match crt.call_post_operation_hooks(&status, is_success) {
        Ok(_) => {}
        Err(e) => {
            let e = e.prefix("Post-operation hook error");
            crt.warn(&e.message);
        }
    };
}

pub struct MainEventLoop {
    certs: Vec<Certificate>,
    root_certs: Vec<String>,
    endpoints: HashMap<String, EndpointSync>,
}

impl MainEventLoop {
    pub fn new(config_file: &str, root_certs: &[&str]) -> Result<Self, Error> {
        let cnf = config::from_file(config_file)?;

        let mut certs = Vec::new();
        let mut endpoints = HashMap::new();
        for (i, crt) in cnf.certificate.iter().enumerate() {
            let endpoint = crt.get_endpoint(&cnf)?;
            let endpoint_name = endpoint.name.clone();
            let cert = Certificate {
                account: crt.get_account(&cnf)?,
                identifiers: crt.get_identifiers()?,
                key_type: crt.get_key_type()?,
                csr_digest: crt.get_csr_digest()?,
                kp_reuse: crt.get_kp_reuse(),
                endpoint_name: endpoint_name.clone(),
                hooks: crt.get_hooks(&cnf)?,
                account_directory: cnf.get_account_dir(),
                crt_directory: crt.get_crt_dir(&cnf),
                crt_name: crt.get_crt_name()?,
                crt_name_format: crt.get_crt_name_format(),
                cert_file_mode: cnf.get_cert_file_mode(),
                cert_file_owner: cnf.get_cert_file_user(),
                cert_file_group: cnf.get_cert_file_group(),
                pk_file_mode: cnf.get_pk_file_mode(),
                pk_file_owner: cnf.get_pk_file_user(),
                pk_file_group: cnf.get_pk_file_group(),
                env: crt.env.to_owned(),
                id: i + 1,
                renew_delay: crt.get_renew_delay(&cnf)?,
            };
            endpoints
                .entry(endpoint_name)
                .or_insert_with(|| Arc::new(RwLock::new(endpoint)));
            init_account(&cert)?;
            certs.push(cert);
        }

        Ok(MainEventLoop {
            certs,
            root_certs: root_certs.iter().map(|v| (*v).to_string()).collect(),
            endpoints,
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
            let lock = endpoint_lock.clone();
            let rc = self.root_certs.clone();
            let handle = thread::spawn(move || {
                let mut endpoint = lock.write().unwrap();
                for crt in certs_to_renew {
                    renew_certificate(&crt, &rc, &mut endpoint);
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            let _ = handle.join();
        }
    }
}
