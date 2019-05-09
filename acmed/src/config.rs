use crate::certificate::Algorithm;
use crate::hooks;
use acme_common::error::Error;
use log::info;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

macro_rules! set_cfg_attr {
    ($to: expr, $from: expr) => {
        if let Some(v) = $from {
            $to = Some(v);
        };
    };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Option<GlobalOptions>,
    #[serde(default)]
    pub endpoint: Vec<Endpoint>,
    #[serde(default)]
    pub hook: Vec<Hook>,
    #[serde(default)]
    pub group: Vec<Group>,
    #[serde(default)]
    pub account: Vec<Account>,
    #[serde(default)]
    pub certificate: Vec<Certificate>,
    #[serde(default)]
    pub include: Vec<String>,
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
                    hook_type: hook.hook_type.to_owned(),
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
    pub tos_agreed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub name: String,
    #[serde(rename = "type")]
    pub hook_type: Vec<HookType>,
    pub cmd: String,
    pub args: Option<Vec<String>>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookType {
    FilePreCreate,
    FilePostCreate,
    FilePreEdit,
    FilePostEdit,
    #[serde(rename = "challenge-http-01")]
    ChallengeHttp01,
    #[serde(rename = "challenge-http-01-clean")]
    ChallengeHttp01Clean,
    #[serde(rename = "challenge-dns-01")]
    ChallengeDns01,
    #[serde(rename = "challenge-dns-01-clean")]
    ChallengeDns01Clean,
    #[serde(rename = "challenge-tls-alpn-01")]
    ChallengeTlsAlpn01,
    #[serde(rename = "challenge-tls-alpn-01-clean")]
    ChallengeTlsAlpn01Clean,
    PostOperation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub hooks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub account: String,
    pub endpoint: String,
    pub domains: Vec<Domain>,
    pub algorithm: Option<String>,
    pub kp_reuse: Option<bool>,
    pub directory: Option<String>,
    pub name: Option<String>,
    pub name_format: Option<String>,
    pub formats: Option<Vec<String>>,
    pub hooks: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
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

    pub fn get_kp_reuse(&self) -> bool {
        match self.kp_reuse {
            Some(b) => b,
            None => crate::DEFAULT_KP_REUSE,
        }
    }

    pub fn get_crt_name(&self) -> String {
        match &self.name {
            Some(n) => n.to_string(),
            None => self.domains.first().unwrap().dns.to_owned(),
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

    pub fn get_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        let mut res = vec![];
        for name in self.hooks.iter() {
            let mut h = cnf.get_hook(&name)?;
            res.append(&mut h);
        }
        Ok(res)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub challenge: String,
    pub dns: String,
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dns)
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

fn get_cnf_path(from: &PathBuf, file: &str) -> PathBuf {
    let mut path = from.clone();
    path.pop();
    path.push(file);
    path
}

fn read_cnf(path: &PathBuf) -> Result<Config, Error> {
    info!("Loading configuration file: {}", path.display());
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut config: Config = toml::from_str(&contents)?;
    for cnf_name in config.include.iter() {
        let cnf_path = get_cnf_path(path, cnf_name);
        let mut add_cnf = read_cnf(&cnf_path)?;
        config.endpoint.append(&mut add_cnf.endpoint);
        config.hook.append(&mut add_cnf.hook);
        config.group.append(&mut add_cnf.group);
        config.account.append(&mut add_cnf.account);
        config.certificate.append(&mut add_cnf.certificate);
        if config.global.is_none() {
            config.global = add_cnf.global;
        } else if let Some(new_glob) = add_cnf.global {
            let mut tmp_glob = config.global.clone().unwrap();
            set_cfg_attr!(tmp_glob.accounts_directory, new_glob.accounts_directory);
            set_cfg_attr!(
                tmp_glob.certificates_directory,
                new_glob.certificates_directory
            );
            set_cfg_attr!(tmp_glob.cert_file_mode, new_glob.cert_file_mode);
            set_cfg_attr!(tmp_glob.cert_file_user, new_glob.cert_file_user);
            set_cfg_attr!(tmp_glob.cert_file_group, new_glob.cert_file_group);
            set_cfg_attr!(tmp_glob.pk_file_mode, new_glob.pk_file_mode);
            set_cfg_attr!(tmp_glob.pk_file_user, new_glob.pk_file_user);
            set_cfg_attr!(tmp_glob.pk_file_group, new_glob.pk_file_group);
            config.global = Some(tmp_glob);
        }
    }
    Ok(config)
}

pub fn from_file(file_name: &str) -> Result<Config, Error> {
    let path = PathBuf::from(file_name);
    let config = read_cnf(&path)?;
    init_directories(&config)?;
    Ok(config)
}
