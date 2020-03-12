use daemonize::Daemonize;
use std::fs::File;
use std::io::prelude::*;
use std::process;

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

pub fn b64_encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub fn init_server(foreground: bool, pid_file: &str) {
    if !foreground {
        let daemonize = Daemonize::new().pid_file(pid_file);
        exit_match!(daemonize.start());
    } else {
        exit_match!(write_pid_file(pid_file));
    }
}

fn write_pid_file(pid_file: &str) -> Result<(), error::Error> {
    let data = format!("{}\n", process::id()).into_bytes();
    let mut file = File::create(pid_file)?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}
