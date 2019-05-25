extern crate serde;
extern crate toml;

use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

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
        if p.name == "http_req" {
            let agent = format!("{}/{}", p.name, p.version);
            set_rustc_env_var!("ACMED_HTTP_LIB_AGENT", agent);
            set_rustc_env_var!("ACMED_HTTP_LIB_NAME", p.name);
            set_rustc_env_var!("ACMED_HTTP_LIB_VERSION", p.version);
            return;
        }
    }
}

fn get_openssl_version_unit(n: u64, pos: u32) -> u64 {
    let p = 0xff_00_00_00_0 >> (8 * pos);
    let n = n & p;
    n >> (8 * (3 - pos) + 4)
}

fn get_openssl_version(v: &str) -> String {
    let v = u64::from_str_radix(&v, 16).unwrap();
    let mut version = vec![];
    for i in 0..3 {
        let n = get_openssl_version_unit(v, i);
        version.push(format!("{}", n));
    }
    let version = version.join(".");
    let p = get_openssl_version_unit(v, 3);
    if p != 0 {
        let p = p + 0x60;
        let p = std::char::from_u32(p as u32).unwrap();
        format!("{}{}", version, p)
    } else {
        version
    }
}

fn set_tls() {
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = get_openssl_version(&v);
        set_rustc_env_var!("ACMED_TLS_LIB_VERSION", version);
        set_rustc_env_var!("ACMED_TLS_LIB_NAME", "OpenSSL");
    }
    if let Ok(v) = env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        let version = get_openssl_version(&v);
        set_rustc_env_var!("ACMED_TLS_LIB_VERSION", version);
        set_rustc_env_var!("ACMED_TLS_LIB_NAME", "LibreSSL");
    }
}

fn set_target() {
    if let Ok(target) = env::var("TARGET") {
        set_rustc_env_var!("ACMED_TARGET", target);
    };
}

fn main() {
    set_target();
    set_tls();
    set_lock();
}
