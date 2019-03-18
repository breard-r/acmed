The Automatic Certificate Management Environment (ACME), is an internet standard ([RFC 8555](https://tools.ietf.org/html/rfc8555)) which allows to automate X.509 certificates signing by a Certification Authority (CA). ACMEd is one of the many clients for this protocol.


# Key features

- HTTP-01 and DNS-01 challenges
- RSA 2048, RSA 4096, ECDSA P-256 and ECDSA P-384 certificates
- Fully customizable  challenge validation action
- Run as a deamon: no need to set-up timers, crontab or other time-triggered process
- Nice and simple configuration file


# Build

In order to compile ADMEd, you will need the latest stable version of [Rust](https://www.rust-lang.org/), although it should work with versions as low as 1.31.

```
cargo build --release
```

The executable is located in `target/release/acmed`.
