use std::env;

fn main() {
    if let Ok(target) = env::var("TARGET") {
        println!("cargo:rustc-env=TACD_TARGET={}", target);
    };
}
