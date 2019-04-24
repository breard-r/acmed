use crate::acme_proto::Challenge;
use crate::certificate::Algorithm;
use crate::error::Error;
use crate::hooks;
use log::info;
use serde::Deserialize;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;

#[derive(Deserialize)]
pub struct Config {
    pub global: Option<GlobalOptions>,
    pub endpoint: Vec<Endpoint>,
    #[serde(default)]
    pub hook: Vec<Hook>,
    #[serde(default)]
    pub group: Vec<Group>,
    pub account: Vec<Account>,
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

    pub fn get_hook(&self, name: &str) -> Result<Vec<hooks::Hook>, Error> {
        for hook in self.hook.iter() {
            if name == hook.name {
                let h = hooks::Hook {
                    name: hook.name.to_owned(),
                    cmd: hook.cmd.to_owned(),
                    args: hook.args.to_owned(),
                    stdin: hook.stdin.to_owned(),
                    stdout: hook.stdout.to_owned(),
                    stderr: hook.stderr.to_owned(),
                };
                return Ok(vec![h]);
            }
        }
        for grp in self.group.iter() {
            if name == grp.name {
                let mut ret = vec![];
                for hook_name in grp.hooks.iter() {
                    let mut h = self.get_hook(&hook_name)?;
                    ret.append(&mut h);
                }
                return Ok(ret);
            }
        }
        Err(format!("{}: hook not found", name).into())
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

#[derive(Clone, Deserialize)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
    pub tos_agreed: bool,
}

#[derive(Deserialize)]
pub struct Hook {
    pub name: String,
    pub cmd: String,
    pub args: Option<Vec<String>>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[derive(Deserialize)]
pub struct Group {
    pub name: String,
    pub hooks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    pub name: String,
    pub email: String,
}

#[derive(Deserialize)]
pub struct Certificate {
    pub account: String,
    pub endpoint: String,
    pub domains: Vec<String>,
    pub challenge: String,
    pub algorithm: Option<String>,
    pub kp_reuse: Option<bool>,
    pub directory: Option<String>,
    pub name: Option<String>,
    pub name_format: Option<String>,
    pub formats: Option<Vec<String>>,
    pub challenge_hooks: Vec<String>,
    pub post_operation_hooks: Option<Vec<String>>,
    pub file_pre_create_hooks: Option<Vec<String>>,
    pub file_post_create_hooks: Option<Vec<String>>,
    pub file_pre_edit_hooks: Option<Vec<String>>,
    pub file_post_edit_hooks: Option<Vec<String>>,
}

impl Certificate {
    pub fn get_account(&self, cnf: &Config) -> Result<Account, Error> {
        for account in cnf.account.iter() {
            if account.name == self.account {
                return Ok(account.clone());
            }
        }
        Err(format!("{}: account not found", self.account).into())
    }

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

    fn get_endpoint(&self, cnf: &Config) -> Result<Endpoint, Error> {
        for endpoint in cnf.endpoint.iter() {
            if endpoint.name == self.endpoint {
                return Ok(endpoint.clone());
            }
        }
        Err(format!("{}: unknown endpoint.", self.endpoint).into())
    }

    pub fn get_remote_url(&self, cnf: &Config) -> Result<String, Error> {
        let ep = self.get_endpoint(cnf)?;
        Ok(ep.url)
    }

    pub fn get_tos_agreement(&self, cnf: &Config) -> Result<bool, Error> {
        let ep = self.get_endpoint(cnf)?;
        Ok(ep.tos_agreed)
    }

    pub fn get_challenge_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        get_hooks(&self.challenge_hooks, cnf)
    }

    pub fn get_post_operation_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        match &self.post_operation_hooks {
            Some(hooks) => get_hooks(hooks, cnf),
            None => Ok(vec![]),
        }
    }

    pub fn get_file_pre_create_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        match &self.file_pre_create_hooks {
            Some(hooks) => get_hooks(hooks, cnf),
            None => Ok(vec![]),
        }
    }

    pub fn get_file_post_create_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        match &self.file_post_create_hooks {
            Some(hooks) => get_hooks(hooks, cnf),
            None => Ok(vec![]),
        }
    }

    pub fn get_file_pre_edit_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        match &self.file_pre_edit_hooks {
            Some(hooks) => get_hooks(hooks, cnf),
            None => Ok(vec![]),
        }
    }

    pub fn get_file_post_edit_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        match &self.file_post_edit_hooks {
            Some(hooks) => get_hooks(hooks, cnf),
            None => Ok(vec![]),
        }
    }
}

fn get_hooks(lst: &[String], cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
    let mut res = vec![];
    for name in lst.iter() {
        let mut h = cnf.get_hook(&name)?;
        res.append(&mut h);
    }
    Ok(res)
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
