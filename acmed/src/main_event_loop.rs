use crate::acme_proto::request_certificate;
use crate::certificate::Certificate;
use crate::config;
use crate::error::Error;
use log::{debug, warn};
use std::thread;
use std::time::Duration;

pub struct MainEventLoop {
    certs: Vec<Certificate>,
}

impl MainEventLoop {
    pub fn new(config_file: &str) -> Result<Self, Error> {
        let cnf = config::from_file(config_file)?;

        let mut certs = Vec::new();
        for crt in cnf.certificate.iter() {
            let cert = Certificate {
                domains: crt.domains.to_owned(),
                algo: crt.get_algorithm()?,
                kp_reuse: crt.get_kp_reuse(),
                email: crt.email.to_owned(),
                remote_url: crt.get_remote_url(&cnf)?,
                challenge: crt.get_challenge()?,
                challenge_hooks: crt.get_challenge_hooks(&cnf)?,
                post_operation_hooks: crt.get_post_operation_hooks(&cnf)?,
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
                file_pre_create_hooks: crt.get_file_pre_create_hooks(&cnf)?,
                file_post_create_hooks: crt.get_file_post_create_hooks(&cnf)?,
                file_pre_edit_hooks: crt.get_file_pre_edit_hooks(&cnf)?,
                file_post_edit_hooks: crt.get_file_post_edit_hooks(&cnf)?,
            };
            certs.push(cert);
        }

        Ok(MainEventLoop { certs })
    }

    pub fn run(&mut self) {
        loop {
            for crt in self.certs.iter_mut() {
                debug!("{}", crt);
                match crt.should_renew() {
                    Ok(sr) => {
                        if sr {
                            let status = match request_certificate(crt) {
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
                    Err(e) => {
                        warn!("{}", e);
                    }
                };
            }

            thread::sleep(Duration::from_secs(crate::DEFAULT_SLEEP_TIME));
        }
    }
}
