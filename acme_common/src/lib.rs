use daemonize::Daemonize;
use std::fs::File;
use std::io::prelude::*;
use std::{fs, process};

pub mod crypto;
pub mod error;
pub mod logs;

macro_rules! exit_match {
    ($e: expr) => {
        match $e {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(3);
            }
        }
    };
}

pub fn to_idna(domain_name: &str) -> Result<String, error::Error> {
    let mut idna_parts = vec![];
    let parts: Vec<&str> = domain_name.split('.').collect();
    for name in parts.iter() {
        let raw_name = name.to_lowercase();
        let idna_name = if name.is_ascii() {
            raw_name
        } else {
            let idna_name = punycode::encode(&raw_name)
                .map_err(|_| error::Error::from("IDNA encoding failed."))?;
            format!("xn--{}", idna_name)
        };
        idna_parts.push(idna_name);
    }
    Ok(idna_parts.join("."))
}

pub fn b64_encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub fn init_server(foreground: bool, pid_file: Option<&str>, default_pid_file: &str) {
    if !foreground {
        let daemonize = Daemonize::new().pid_file(pid_file.unwrap_or(default_pid_file));
        exit_match!(daemonize.start());
    } else if let Some(f) = pid_file {
        exit_match!(write_pid_file(f));
    }
}

fn write_pid_file(pid_file: &str) -> Result<(), error::Error> {
    let data = format!("{}\n", process::id()).into_bytes();
    let mut file = File::create(pid_file)?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}

pub fn clean_pid_file(pid_file: Option<&str>) -> Result<(), error::Error> {
    if let Some(f) = pid_file {
        fs::remove_file(f)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::to_idna;

    #[test]
    fn test_no_idna() {
        let idna_res = to_idna("HeLo.example.com");
        assert!(idna_res.is_ok());
        assert_eq!(idna_res.unwrap(), "helo.example.com");
    }

    #[test]
    fn test_simple_idna() {
        let idna_res = to_idna("Hélo.Example.com");
        assert!(idna_res.is_ok());
        assert_eq!(idna_res.unwrap(), "xn--hlo-bma.example.com");
    }

    #[test]
    fn test_multiple_idna() {
        let idna_res = to_idna("ns1.hÉlo.aç-éièè.example.com");
        assert!(idna_res.is_ok());
        assert_eq!(
            idna_res.unwrap(),
            "ns1.xn--hlo-bma.xn--a-i-2lahae.example.com"
        );
    }

    #[test]
    fn test_already_idna() {
        let idna_res = to_idna("xn--hlo-bma.example.com");
        assert!(idna_res.is_ok());
        assert_eq!(idna_res.unwrap(), "xn--hlo-bma.example.com");
    }

    #[test]
    fn test_mixed_idna_parts() {
        let idna_res = to_idna("ns1.xn--hlo-bma.aç-éièè.example.com");
        assert!(idna_res.is_ok());
        assert_eq!(
            idna_res.unwrap(),
            "ns1.xn--hlo-bma.xn--a-i-2lahae.example.com"
        );
    }
}
