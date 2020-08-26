use crate::duration::parse_duration;
use crate::hooks;
use crate::identifier::IdentifierType;
use acme_common::crypto::{HashFunction, KeyType};
use acme_common::error::Error;
use glob::glob;
use log::info;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::result::Result;
use std::time::Duration;

macro_rules! set_cfg_attr {
    ($to: expr, $from: expr) => {
        if let Some(v) = $from {
            $to = Some(v);
        };
    };
}

fn get_stdin(hook: &Hook) -> Result<hooks::HookStdin, Error> {
    match &hook.stdin {
        Some(file) => match &hook.stdin_str {
            Some(_) => {
                let msg = format!(
                    "{}: A hook cannot have both stdin and stdin_str",
                    &hook.name
                );
                Err(msg.into())
            }
            None => Ok(hooks::HookStdin::File(file.to_string())),
        },
        None => match &hook.stdin_str {
            Some(s) => Ok(hooks::HookStdin::Str(s.to_string())),
            None => Ok(hooks::HookStdin::None),
        },
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Option<GlobalOptions>,
    #[serde(default)]
    pub endpoint: Vec<Endpoint>,
    #[serde(default, rename = "rate-limit")]
    pub rate_limit: Vec<RateLimit>,
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
    fn get_rate_limit(&self, name: &str) -> Result<(usize, String), Error> {
        for rl in self.rate_limit.iter() {
            if rl.name == name {
                return Ok((rl.number, rl.period.to_owned()));
            }
        }
        Err(format!("{}: rate limit not found", name).into())
    }

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
                    stdin: get_stdin(&hook)?,
                    stdout: hook.stdout.to_owned(),
                    stderr: hook.stderr.to_owned(),
                    allow_failure: hook
                        .allow_failure
                        .unwrap_or(crate::DEFAULT_HOOK_ALLOW_FAILURE),
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
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub renew_delay: Option<String>,
}

impl GlobalOptions {
    pub fn get_renew_delay(&self) -> Result<Duration, Error> {
        match &self.renew_delay {
            Some(d) => parse_duration(&d),
            None => Ok(Duration::new(crate::DEFAULT_CERT_RENEW_DELAY, 0)),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub url: String,
    pub tos_agreed: bool,
    #[serde(default)]
    pub rate_limits: Vec<String>,
    pub renew_delay: Option<String>,
}

impl Endpoint {
    pub fn get_renew_delay(&self, cnf: &Config) -> Result<Duration, Error> {
        match &self.renew_delay {
            Some(d) => parse_duration(&d),
            None => match &cnf.global {
                Some(g) => g.get_renew_delay(),
                None => Ok(Duration::new(crate::DEFAULT_CERT_RENEW_DELAY, 0)),
            },
        }
    }

    fn to_generic(&self, cnf: &Config) -> Result<crate::endpoint::Endpoint, Error> {
        let mut limits = vec![];
        for rl_name in self.rate_limits.iter() {
            let (nb, timeframe) = cnf.get_rate_limit(&rl_name)?;
            limits.push((nb, timeframe));
        }
        crate::endpoint::Endpoint::new(&self.name, &self.url, self.tos_agreed, &limits)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub name: String,
    pub number: usize,
    pub period: String,
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
    pub stdin_str: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub allow_failure: Option<bool>,
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
    pub key_type: Option<String>,
    pub signature_algorithm: Option<String>,
}

impl Account {
    pub fn to_generic(&self) -> Result<crate::account::Account, Error> {
        crate::account::Account::new(
            &self.name,
            &self.email,
            &self.key_type,
            &self.signature_algorithm,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub account: String,
    pub endpoint: String,
    pub identifiers: Vec<Identifier>,
    pub key_type: Option<String>,
    pub csr_digest: Option<String>,
    pub kp_reuse: Option<bool>,
    pub directory: Option<String>,
    pub name: Option<String>,
    pub name_format: Option<String>,
    pub formats: Option<Vec<String>>,
    pub hooks: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub renew_delay: Option<String>,
}

impl Certificate {
    pub fn get_account(&self, cnf: &Config) -> Result<crate::account::Account, Error> {
        for account in cnf.account.iter() {
            if account.name == self.account {
                let acc = account.to_generic()?;
                return Ok(acc);
            }
        }
        Err(format!("{}: account not found", self.account).into())
    }

    pub fn get_key_type(&self) -> Result<KeyType, Error> {
        match &self.key_type {
            Some(a) => a.parse(),
            None => Ok(crate::DEFAULT_CERT_KEY_TYPE),
        }
    }

    pub fn get_csr_digest(&self) -> Result<HashFunction, Error> {
        match &self.csr_digest {
            Some(d) => d.parse(),
            None => Ok(crate::DEFAULT_CSR_DIGEST),
        }
    }

    pub fn get_identifiers(&self) -> Result<Vec<crate::identifier::Identifier>, Error> {
        let mut ret = vec![];
        for id in self.identifiers.iter() {
            ret.push(id.to_generic()?);
        }
        Ok(ret)
    }

    pub fn get_kp_reuse(&self) -> bool {
        match self.kp_reuse {
            Some(b) => b,
            None => crate::DEFAULT_KP_REUSE,
        }
    }

    pub fn get_crt_name(&self) -> Result<String, Error> {
        let name = match &self.name {
            Some(n) => n.to_string(),
            None => {
                let id = self
                    .identifiers
                    .first()
                    .ok_or_else(|| Error::from("Certificate has no identifiers."))?;
                id.to_string()
            }
        };
        let name = name.replace("*", "_").replace(":", "_");
        Ok(name)
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

    fn do_get_endpoint(&self, cnf: &Config) -> Result<Endpoint, Error> {
        for endpoint in cnf.endpoint.iter() {
            if endpoint.name == self.endpoint {
                return Ok(endpoint.clone());
            }
        }
        Err(format!("{}: unknown endpoint.", self.endpoint).into())
    }

    pub fn get_endpoint(&self, cnf: &Config) -> Result<crate::endpoint::Endpoint, Error> {
        let endpoint = self.do_get_endpoint(cnf)?;
        endpoint.to_generic(cnf)
    }

    pub fn get_hooks(&self, cnf: &Config) -> Result<Vec<hooks::Hook>, Error> {
        let mut res = vec![];
        for name in self.hooks.iter() {
            let mut h = cnf.get_hook(&name)?;
            res.append(&mut h);
        }
        Ok(res)
    }

    pub fn get_renew_delay(&self, cnf: &Config) -> Result<Duration, Error> {
        match &self.renew_delay {
            Some(d) => parse_duration(&d),
            None => {
                let endpoint = self.do_get_endpoint(cnf)?;
                endpoint.get_renew_delay(cnf)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(remote = "Self")]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    pub challenge: String,
    pub dns: Option<String>,
    pub ip: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = Identifier::deserialize(deserializer)?;
        let filled_nb: u8 = [unchecked.dns.is_some(), unchecked.ip.is_some()]
            .iter()
            .copied()
            .map(u8::from)
            .sum();
        if filled_nb != 1 {
            return Err(de::Error::custom(
                "one and only one of `dns` or `ip` must be specified",
            ));
        }
        Ok(unchecked)
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = String::new();
        let msg = self.dns.as_ref().or_else(|| self.ip.as_ref()).unwrap_or(&s);
        write!(f, "{}", msg)
    }
}

impl Identifier {
    fn to_generic(&self) -> Result<crate::identifier::Identifier, Error> {
        let (t, v) = match &self.dns {
            Some(d) => (IdentifierType::Dns, d),
            None => match &self.ip {
                Some(ip) => (IdentifierType::Ip, ip),
                None => {
                    return Err("No identifier found.".into());
                }
            },
        };
        crate::identifier::Identifier::new(t, &v, &self.challenge, &self.env)
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

fn get_cnf_path(from: &PathBuf, file: &str) -> Result<Vec<PathBuf>, Error> {
    let mut path = from.clone().canonicalize()?;
    path.pop();
    path.push(file);
    let err = format!("{:?}: invalid UTF-8 path", path);
    let raw_path = path.to_str().ok_or(err)?;
    let g = glob(raw_path)?
        .filter_map(Result::ok)
        .collect::<Vec<PathBuf>>();
    if g.is_empty() {
        log::warn!(
            "Pattern `{}` (expanded as `{}`): no matching configuration file found.",
            file,
            raw_path
        );
    }
    Ok(g)
}

fn read_cnf(path: &PathBuf) -> Result<Config, Error> {
    info!("Loading configuration file: {}", path.display());
    let mut file =
        File::open(path).map_err(|e| Error::from(e).prefix(&path.display().to_string()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| Error::from(e).prefix(&path.display().to_string()))?;
    let mut config: Config = toml::from_str(&contents)
        .map_err(|e| Error::from(e).prefix(&path.display().to_string()))?;
    for cnf_name in config.include.iter() {
        for cnf_path in get_cnf_path(path, cnf_name)? {
            let mut add_cnf = read_cnf(&cnf_path)?;
            config.endpoint.append(&mut add_cnf.endpoint);
            config.rate_limit.append(&mut add_cnf.rate_limit);
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
    }
    Ok(config)
}

fn dispatch_global_env_vars(config: &mut Config) {
    if let Some(glob) = &config.global {
        if !glob.env.is_empty() {
            for mut cert in config.certificate.iter_mut() {
                let mut new_vars = glob.env.clone();
                for (k, v) in cert.env.iter() {
                    new_vars.insert(k.to_string(), v.to_string());
                }
                cert.env = new_vars;
            }
        }
    }
}

pub fn from_file(file_name: &str) -> Result<Config, Error> {
    let path = PathBuf::from(file_name);
    let mut config = read_cnf(&path)?;
    dispatch_global_env_vars(&mut config);
    init_directories(&config)?;
    Ok(config)
}
