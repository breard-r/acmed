use crate::acmed::{Algorithm, Challenge, Format};
use crate::errors::Error;
use log::info;
use serde::Deserialize;
use std::fs::{self, File};
use std::path::Path;
use std::io::prelude::*;

#[derive(Deserialize)]
pub struct Config {
    pub global: Option<GlobalOptions>,
    pub endpoint: Vec<Endpoint>,
    pub hook: Vec<Hook>,
    pub certificate: Vec<Certificate>,
}

impl Config {
    pub fn get_account_dir(&self) -> String {
        let account_dir = match &self.global {
            Some(g) => match &g.accounts_directory {
                Some(d) => &d,
                None => crate::DEFAULT_ACCOUNTS_DIR,
            },
            None => crate::DEFAULT_ACCOUNTS_DIR,
        };
        account_dir.to_string()
    }

    pub fn get_hook(&self, name: &str) -> Result<Hook, Error> {
        for hook in self.hook.iter() {
            if name == hook.name {
                return Ok(hook.clone());
            }
        }
        Err(Error::new(&format!("{}: hook not found", name)))
    }

    pub fn get_cert_file_mode(&self) -> u32 {
        match &self.global {
            Some(g) => match g.cert_file_mode {
                Some(m) => m,
                None => crate::DEFAULT_CERT_FILE_MODE,
            },
            None => crate::DEFAULT_CERT_FILE_MODE,
        }
    }

    pub fn get_cert_file_user(&self) -> Option<String> {
        match &self.global {
            Some(g) => g.cert_file_user.to_owned(),
            None => None,
        }
    }

    pub fn get_cert_file_group(&self) -> Option<String> {
        match &self.global {
            Some(g) => g.cert_file_group.to_owned(),
            None => None,
        }
    }

    pub fn get_pk_file_mode(&self) -> u32 {
        match &self.global {
            Some(g) => match g.pk_file_mode {
                Some(m) => m,
                None => crate::DEFAULT_PK_FILE_MODE,
            },
            None => crate::DEFAULT_PK_FILE_MODE,
        }
    }

    pub fn get_pk_file_user(&self) -> Option<String> {
        match &self.global {
            Some(g) => g.pk_file_user.to_owned(),
            None => None,
        }
    }

    pub fn get_pk_file_group(&self) -> Option<String> {
        match &self.global {
            Some(g) => g.pk_file_group.to_owned(),
            None => None,
        }
    }
}

#[derive(Deserialize)]
pub struct GlobalOptions {
    pub accounts_directory: Option<String>,
    pub certificates_directory: Option<String>,
    pub cert_file_mode: Option<u32>,
    pub cert_file_user: Option<String>,
    pub cert_file_group: Option<String>,
    pub pk_file_mode: Option<u32>,
    pub pk_file_user: Option<String>,
    pub pk_file_group: Option<String>,
}

#[derive(Deserialize)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Hook {
    pub name: String,
    pub cmd: String,
    pub args: Option<Vec<String>>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[derive(Deserialize)]
pub struct Certificate {
    pub email: String,
    pub endpoint: String,
    pub domains: Vec<String>,
    pub challenge: String,
    pub challenge_hooks: Vec<String>,
    pub post_operation_hook: Option<Vec<String>>,
    pub algorithm: Option<String>,
    pub kp_reuse: Option<bool>,
    pub directory: Option<String>,
    pub name: Option<String>,
    pub name_format: Option<String>,
    pub formats: Option<Vec<String>>,
}

impl Certificate {
    pub fn get_algorithm(&self) -> Result<Algorithm, Error> {
        let algo = match &self.algorithm {
            Some(a) => &a,
            None => crate::DEFAULT_ALGO,
        };
        Algorithm::from_str(algo)
    }

    pub fn get_challenge(&self) -> Result<Challenge, Error> {
        Challenge::from_str(&self.challenge)
    }

    pub fn get_kp_reuse(&self) -> bool {
        match self.kp_reuse {
            Some(b) => b,
            None => crate::DEFAULT_KP_REUSE,
        }
    }

    pub fn get_formats(&self) -> Result<Vec<Format>, Error> {
        let ret = match &self.formats {
            Some(fmts) => {
                let mut lst = Vec::new();
                for f in fmts.iter() {
                    lst.push(match f.as_str() {
                        "der" => Format::Der,
                        "pem" => Format::Pem,
                        _ => return Err(Error::new(&format!("{}: unknown format.", f))),
                    });
                }
                lst.sort();
                lst.dedup();
                lst
            }
            None => vec![crate::DEFAULT_FMT],
        };
        Ok(ret)
    }

    pub fn get_crt_name(&self) -> String {
        match &self.name {
            Some(n) => n.to_string(),
            None => self.domains.first().unwrap().to_string(),
        }
    }

    pub fn get_crt_name_format(&self) -> String {
        match &self.name_format {
            Some(n) => n.to_string(),
            None => crate::DEFAULT_CERT_FORMAT.to_string(),
        }
    }

    pub fn get_crt_dir(&self, cnf: &Config) -> String {
        let crt_directory = match &self.directory {
            Some(d) => &d,
            None => match &cnf.global {
                Some(g) => match &g.certificates_directory {
                    Some(d) => &d,
                    None => crate::DEFAULT_CERT_DIR,
                },
                None => crate::DEFAULT_CERT_DIR,
            },
        };
        crt_directory.to_string()
    }

    pub fn get_remote_url(&self, cnf: &Config) -> Result<String, Error> {
        for endpoint in cnf.endpoint.iter() {
            if endpoint.name == self.endpoint {
                return Ok(endpoint.url.to_owned());
            }
        }
        Err(Error::new(&format!("{}: unknown endpoint.", self.endpoint)))
    }

    pub fn get_challenge_hooks(&self, cnf: &Config) -> Result<Vec<Hook>, Error> {
        let mut res = vec![];
        for name in self.challenge_hooks.iter() {
            let h = cnf.get_hook(&name)?;
            res.push(h);
        }
        Ok(res)
    }

    pub fn get_post_operation_hook(&self, cnf: &Config) -> Result<Vec<Hook>, Error> {
        let mut res = vec![];
        match &self.post_operation_hook {
            Some(po_hooks) => for name in po_hooks.iter() {
                let h = cnf.get_hook(&name)?;
                res.push(h);
            },
            None => {}
        };
        Ok(res)
    }
}

fn create_dir(path: &str) -> Result<(), Error> {
    if Path::new(path).is_dir() {
        Ok(())
    } else {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

fn init_directories(config: &Config) -> Result<(), Error> {
    create_dir(&config.get_account_dir())?;
    for crt in config.certificate.iter() {
        create_dir(&crt.get_crt_dir(config))?;
    }
    Ok(())
}

pub fn from_file(file: &str) -> Result<Config, Error> {
    info!("Loading configuration file: {}", file);
    let mut file = File::open(file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = toml::from_str(&contents)?;
    init_directories(&config)?;
    Ok(config)
}
