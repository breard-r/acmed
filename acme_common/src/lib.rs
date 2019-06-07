use daemonize::Daemonize;

pub mod crypto;
pub mod error;
pub mod logs;

pub fn b64_encode<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub fn init_server(foreground: bool, pid_file: &str) {
    if !foreground {
        let daemonize = Daemonize::new().pid_file(pid_file);
        match daemonize.start() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(3);
            }
        }
    }
}
