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

fn main() {
    set_target();
    set_lock();
}
