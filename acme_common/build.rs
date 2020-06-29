use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;

macro_rules! set_rustc_env_var {
    ($name: expr, $value: expr) => {{
        println!("cargo:rustc-env={}={}", $name, $value);
    }};
}

fn get_openssl_version_unit(n: u64, pos: u32) -> u64 {
    let p = 0x000f_f000_0000 >> (8 * pos);
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

fn get_lib_version(lib: &str) -> Option<String> {
    let pat = format!("\"checksum {} ", lib);
    let mut lock_file = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    lock_file.push("../Cargo.lock");
    let file = File::open(lock_file).unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        if line.starts_with(&pat) {
            let v: Vec<&str> = line.split(' ').collect();
            return Some(String::from(v[2]));
        }
    }
    None
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
    if env::var("CARGO_FEATURE_STANDALONE").is_ok() {
        let version = get_lib_version("ring").unwrap();
        set_rustc_env_var!("ACMED_TLS_LIB_VERSION", version);
        set_rustc_env_var!("ACMED_TLS_LIB_NAME", "ring");
    }
}

fn main() {
    set_tls();
}
