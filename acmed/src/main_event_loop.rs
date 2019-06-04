use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::config;
use acme_common::error::Error;
use std::thread;
use std::time::Duration;

fn renew_certificate(crt: &Certificate, root_certs: &[String]) {
    let (status, is_success) = match request_certificate(crt, root_certs) {
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
}

impl MainEventLoop {
    pub fn new(config_file: &str, root_certs: &[&str]) -> Result<Self, Error> {
        let cnf = config::from_file(config_file)?;
        let rate_limits_corresp = config::init_rate_limits(&cnf)?;

        let mut certs = Vec::new();
        for (i, crt) in cnf.certificate.iter().enumerate() {
            let ep_name = crt.get_endpoint_name(&cnf)?;
            let https_throttle = rate_limits_corresp
                .get(&ep_name)
                .ok_or_else(|| {
                    Error::from(format!(
                        "{}: rate limit not found for this endpoint",
                        ep_name
                    ))
                })?
                .to_owned();
            let cert = Certificate {
                account: crt.get_account(&cnf)?,
                domains: crt.domains.to_owned(),
                algo: crt.get_algorithm()?,
                kp_reuse: crt.get_kp_reuse(),
                remote_url: crt.get_remote_url(&cnf)?,
                tos_agreed: crt.get_tos_agreement(&cnf)?,
                https_throttle,
                hooks: crt.get_hooks(&cnf)?,
                account_directory: cnf.get_account_dir(),
                crt_directory: crt.get_crt_dir(&cnf),
                crt_name: crt.get_crt_name(),
                crt_name_format: crt.get_crt_name_format(),
                cert_file_mode: cnf.get_cert_file_mode(),
                cert_file_owner: cnf.get_cert_file_user(),
                cert_file_group: cnf.get_cert_file_group(),
                pk_file_mode: cnf.get_pk_file_mode(),
                pk_file_owner: cnf.get_pk_file_user(),
                pk_file_group: cnf.get_pk_file_group(),
                env: crt.env.to_owned(),
                id: i + 1,
            };
            certs.push(cert);
        }

        Ok(MainEventLoop {
            certs,
            root_certs: root_certs.iter().map(|v| v.to_string()).collect(),
        })
    }

    pub fn run(&self) {
        loop {
            self.renew_certificates();
            thread::sleep(Duration::from_secs(crate::DEFAULT_SLEEP_TIME));
        }
    }

    fn renew_certificates(&self) {
        let mut handles = vec![];
        for crt in self.certs.iter() {
            match crt.should_renew() {
                Ok(true) => {
                    let root_certs = self.root_certs.clone();
                    let cert = (*crt).clone();
                    let handler = thread::spawn(move || {
                        renew_certificate(&cert, &root_certs);
                    });
                    handles.push(handler);
                }
                Ok(false) => {}
                Err(e) => {
                    crt.warn(&e.message);
                }
            };
        }
        for handler in handles {
            let _ = handler.join();
        }
    }
}
