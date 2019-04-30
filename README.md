# ACMEd

[![Build Status](https://api.travis-ci.org/breard-r/acmed.svg?branch=master)](https://travis-ci.org/breard-r/acmed)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.32.0+-lightgray.svg)](#build-from-source)
[![LICENSE MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT.txt)
[![LICENSE Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE-APACHE-2.0.txt)

The Automatic Certificate Management Environment (ACME), is an internet standard ([RFC 8555](https://tools.ietf.org/html/rfc8555)) which allows to automate X.509 certificates signing by a Certification Authority (CA). ACMEd is one of the many clients for this protocol.


## Key features

- http-01, dns-01 and tls-alpn-01 challenges
- RSA 2048, RSA 4096, ECDSA P-256 and ECDSA P-384 certificates
- Fully customizable challenge validation action
- Fully customizable archiving method (yes, you can use git or anything else)
- Nice and simple configuration file
- Run as a deamon: no need to set-up timers, crontab or other time-triggered process
- Retry of HTTPS request rejected with a badNonce or other recoverable errors
- Optional private-key reuse (useful for [HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning))
- For a given certificate, each domain names may be validated using a different challenge.
- A standalone server dedicated to the tls-alpn-01 challenge validation


## Planned features

- A pre-built set of hooks that can be used in most circumstances
- Daemon and certificates management via the `acmectl` tool


## Build from source

In order to compile ADMEd, you will need the [Rust](https://www.rust-lang.org/) compiler and its package manager, Cargo. The minimal required Rust version is 1.32.0, although it is recommended to use the latest stable one.

ACMEd depends on the OpenSSL. The minimal supported versions are those from the [openssl](https://docs.rs/openssl/) crate, currently OpenSSL 1.0.1 through 1.1.1 and LibreSSL 2.5 through 2.8. The `tacd` executable also requires your OpenSSL/LibreSSL version to support TLS-ALPN.

On systems based on Debian/Ubuntu, you may need to install the `libssl-dev`, `build-essential` and `pkg-config` packages.

```
cargo build --release
strip target/release/acmed
strip target/release/tacd
```

The executables are located in the `target/release` directory.


## Frequently Asked Questions

### Why this project?

After testing multiple ACME clients, I found out none supported all the features I wished for (see the key features above). It may have been possible to contribute or fork an existing project, however I believe those project made architectural choices incompatible with what i wanted, and therefore it would be as much or less work to start a new project from scratch.

### Is it free and open-source software?

Yes, ACMEd is dual-licensed under the MIT and Apache 2.0 terms.

See [LICENSE-MIT.txt](LICENSE-MIT.txt) and [LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt) for details.

### Can it automatically change my server configuration?

Short answer: No.

Long answer: At some points in a certificate's life, ACMEd triggers hook in order to let you customize how some actions are done, therefore you can use those hooks to run any server configuration you wish. However, this may not be what you are looking for since it cannot proactively detect which certificates should be emitted since ACMEd only manages certificates that have already been declared in the configuration files.

### Is it suitable for beginners?

It depends on what you call a beginner. This software is intended to be used by system administrator with a certain knowledge of their environment. Furthermore, it is also expected to know the bases of the ACME protocol. Let's Encrypt wrote a nice article about [how it works](https://letsencrypt.org/how-it-works/).

### Why is RSA 2048 the default?

Yes, ACMED support RSA 4096, ECDSA P-256 and ECDSA P-384. However, those are not (yet) fitted to be the default choice.

It is not obvious at the first sight, but [RSA 4096](https://gnupg.org/faq/gnupg-faq.html#no_default_of_rsa4096) is NOT twice more secure than RSA 2048. In fact, it adds a lot more calculation while providing only a small security improvement. If you think you will use it anyway since you are more concerned about security than performance, please check your certificate chain up to the root. Most of the time, the root certificate and the intermediates will be RSA 2048 ones (that is the case for [Let’s Encrypt](https://letsencrypt.org/certificates/)). If so, using RSA 4096 in the final certificate will not add any additional security since a system's global security level is equal to the level of its weakest point.

ECDSA certificates may be a good alternative to RSA since, for the same security level, they are smaller and requires less computation, hence improve performance. Unfortunately, as X.509 certificates may be used in various contexts, some software may not support this not-so-recent technology. To achieve maximal compatibility while using ECC, you usually have to set-up an hybrid configuration with both an ECDSA and a RSA certificate to fall-back to. Therefore, even if you are encouraged to use ECDSA certificates, it should not currently be the default. That said, it may be in a soon future.
