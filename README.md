# ACMEd

[![Build Status](https://api.travis-ci.org/breard-r/acmed.svg?branch=master)](https://travis-ci.org/breard-r/acmed)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.31.0+-lightgray.svg)](#build-from-source)
i[![LICENSE MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT.txt)
i[![LICENSE Apache 2.0](https://img.shields.io/badge/license-Apache 2.0-blue.svg)](LICENSE-APACHE-2.0.txt)

The Automatic Certificate Management Environment (ACME), is an internet standard ([RFC 8555](https://tools.ietf.org/html/rfc8555)) which allows to automate X.509 certificates signing by a Certification Authority (CA). ACMEd is one of the many clients for this protocol.


## Key features

- HTTP-01 and DNS-01 challenges
- RSA 2048, RSA 4096, ECDSA P-256 and ECDSA P-384 certificates
- Fully customizable  challenge validation action
- Run as a deamon: no need to set-up timers, crontab or other time-triggered process
- Nice and simple configuration file


## Planned features

- optional private-key reuse (useful for [HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning))
- customizable way to archive old certificates and private keys
- daemon management via the `acmectl` tool


## Build from source

In order to compile ADMEd, you will need the [Rust](https://www.rust-lang.org/) compiler and its package manager, Cargo. The minimal required Rust version is 1.31.0, although it is recommended to use the latest stable one.

ACMEd depends on the OpenSSL. The minimal supported versions are those from the [openssl](https://docs.rs/openssl/) crate, currently OpenSSL 1.0.1 through 1.1.1 and LibreSSL 2.5 through 2.8.

```
cargo build --release
```

The executable is located in `target/release/acmed`.


## Frequently Asked Questions

### Why this project?

After testing multiple ACME clients, I found out none supported all the features I wished for (see the key features above). It may have been possible to contribute or fork an existing project, however I believe those project made architectural choices incompatible with what i wanted, and therefore it would be as much or less work to start a new project from scratch.

### Is it free and open-source software?

Yes, ACMEd is dual-licensed under the MIT and Apache 2.0 terms.

See [LICENSE-MIT.txt](LICENSE-MIT.txt) and [LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt) for details.

### Can it automatically change my server configuration?

Some ACME client, like certbot, can read some software configuration and automatically edit it so this software will use the issued certificates. ACMEd will never do that since we believe this feature is dangerous. As the proverb says, the road to hell is paved with good intentions. This feature was meant to make the web more secure since system administrators with no knowledge at all about TLS could set-it up in a decent way. However, we think this feature pushed towards a list of "blessed" software and therefore harms the diversity. Some people's ignorance should not be an excuse to recommend some kind uniform set-up. Instead, people should be educated so they can make the best choices. This is achieved through tutorials and courses, not some kind of dark-magic automation.

### Why is RSA 2048 the default?

Yes, ACMED support RSA 4096, ECDSA P-256 and ECDSA P-384. However, those are not fitted to be the default choice.

It is not obvious at the first sight, but [RSA 4096](https://gnupg.org/faq/gnupg-faq.html#no_default_of_rsa4096) is NOT twice more secure than RSA 2048. In fact, it adds a lot more calculation while providing only a small security improvement. If you think you will use it anyway since you are more concerned about security than performance, please check your certificate chain up to the root. Most of the time, the root certificate and the intermediates will be RSA 2048 ones (that is the case for [Let’s Encrypt](https://letsencrypt.org/certificates/)). If so, using RSA 4096 in the final certificate will not add any additional security since a system's global security level is equal to the level of its weakest point.


ECDSA certificates may be a good alternative to RSA since, for the same security level, they are smaller and requires less computation. Unfortunately, as x.509 certificates are not meant only for websites visited using a web browser, some software may not support this not-so-recent technology. To achieve maximal compatibility while using ECC, you usually have to set-up an hybrid configuration with both an ECDSA and a RSA certificate to fall-back to. Therefore, even if you are encouraged to use ECDSA certificates, it should not currently be the default. That said, it may be in a soon future.

### What is the difference between SSL, TLS and X.509?

SSL is an old and now insecure protocol that has been deprecated in favor of TLS. In fact, TLS 1.0 was an upgrade of SSL 3. In order to work, both uses X.509 certificates. Please note that X.509 is only the certificate format, it is not suitable for private keys.

Therefore, do not say "a CA issue SSL certificates". Instead, say "a CA issue X.509 certificated that can be used for TLS". Yes, most CA websites are wrong, mostly because of commercial reasons since most people don't know what X.509 (or TLS) is but have the term SSL anchored in their mind.
