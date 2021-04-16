extern crate serde;
extern crate toml;

use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

macro_rules! set_env_var_if_absent {
    ($name: expr, $default_value: expr) => {{
        if let Err(_) = env::var($name) {
            set_rustc_env_var!($name, $default_value);
        }
    }};
}

macro_rules! set_rustc_env_var {
    ($name: expr, $value: expr) => {{
        println!("cargo:rustc-env={}={}", $name, $value);
    }};
}

#[derive(Deserialize)]
pub struct Lock {
    package: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
}

struct Error;

impl From<std::io::Error> for Error {
    fn from(_error: std::io::Error) -> Self {
        Error {}
    }
}

impl From<toml::de::Error> for Error {
    fn from(_error: toml::de::Error) -> Self {
        Error {}
    }
}

fn get_lock() -> Result<Lock, Error> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("Cargo.lock");
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let ret: Lock = toml::from_str(&contents)?;
    Ok(ret)
}

fn set_lock() {
    let lock = match get_lock() {
        Ok(l) => l,
        Err(_) => {
            return;
        }
    };
    for p in lock.package.iter() {
        if p.name == "attohttpc" {
            let agent = format!("{}/{}", p.name, p.version);
            set_rustc_env_var!("ACMED_HTTP_LIB_AGENT", agent);
            set_rustc_env_var!("ACMED_HTTP_LIB_NAME", p.name);
            set_rustc_env_var!("ACMED_HTTP_LIB_VERSION", p.version);
            return;
        }
    }
}

fn set_target() {
    if let Ok(target) = env::var("TARGET") {
        set_rustc_env_var!("ACMED_TARGET", target);
    };
}

fn set_default_values() {
    set_env_var_if_absent!("ACMED_DEFAULT_ACCOUNTS_DIR", "/etc/acmed/accounts");
    set_env_var_if_absent!("ACMED_DEFAULT_CERT_DIR", "/etc/acmed/certs");
    set_env_var_if_absent!(
        "ACMED_DEFAULT_CERT_FORMAT",
        "{{name}}_{{key_type}}.{{file_type}}.{{ext}}"
    );
    set_env_var_if_absent!("ACMED_DEFAULT_CONFIG_FILE", "/etc/acmed/acmed.toml");
    set_env_var_if_absent!("ACMED_DEFAULT_PID_FILE", "/var/run/acmed.pid");
}

fn main() {
    set_target();
    set_lock();
    set_default_values();
}
