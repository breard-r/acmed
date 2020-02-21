
[//]: # (Copyright 2019 Rodolphe Bréard <rodolphe@breard.tf>)

[//]: # (Copying and distribution of this file, with or without modification,)
[//]: # (are permitted in any medium without royalty provided the copyright)
[//]: # (notice and this notice are preserved.  This file is offered as-is,)
[//]: # (without any warranty.)

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
- Customizable HTTPS requests rate limits.
- Optional key pair reuse (useful for [HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning))
- For a given certificate, each domain name may be validated using a different challenge.
- A standalone server dedicated to the tls-alpn-01 challenge validation (tacd).


## Planned features

- A pre-built set of hooks that can be used in most circumstances
- Daemon and certificates management via the `acmectl` tool
- Nonce scoping configuration
- HTTP/2 support


## Project status

This project is usable, but is still a work in progress. Each release should works well and accordingly to its documentation.
Because the API has not been stabilized yet, breaking changes may occur. Therefore, before any upgrade, you are invited to read the [CHANGELOG](CHANGELOG.md) and check if any change can break your setup.

Please keep in mind this software has neither been subject to a peer review nor to a security audit.


## Documentation

This project provides the following man pages:

- acmed (8)
- acmed.toml (5)
- tacd (8)


## Build from source

In order to compile ACMEd, you will need the [Rust](https://www.rust-lang.org/) compiler and its package manager, Cargo. The minimal required Rust version is 1.34.2, although it is recommended to use the latest stable one.

ACMEd depends OpenSSL 1.1.0 or higher.

On systems based on Debian/Ubuntu, you may need to install the `libssl-dev`, `build-essential` and `pkg-config` packages.

```
$ make
$ make install
```


## Frequently Asked Questions

### Why this project?

After testing multiple ACME clients, I found out none supported all the features I wished for (see the key features above). It may have been possible to contribute or fork an existing project, however I believe those project made architectural choices incompatible with what i wanted, and therefore it would be as much or less work to start a new project from scratch.

### Is it free and open-source software?

Yes, ACMEd is dual-licensed under the MIT and Apache 2.0 terms. See [LICENSE-MIT.txt](LICENSE-MIT.txt) and [LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt) for details.

The man pages, the default hooks configuration file, the `CHANGELOG.md` and the `README.md` files are released under the [GNU All-Permissive License](https://www.gnu.org/prep/maintain/html_node/License-Notices-for-Other-Files.html).

### Can it automatically change my server configuration?

Short answer: No.

Long answer: At some points in a certificate's life, ACMEd triggers hook in order to let you customize how some actions are done, therefore you can use those hooks to modify any server configuration you wish. However, this may not be what you are looking for since it cannot proactively detect which certificates should be emitted since ACMEd only manages certificates that have already been declared in the configuration files.

### Is it suitable for beginners?

It depends on your definition of a beginner. This software is intended to be used by system administrator with a certain knowledge of their environment. Furthermore, it is also expected to know the bases of the ACME protocol. Let's Encrypt wrote a nice article about [how it works](https://letsencrypt.org/how-it-works/).

### Why is RSA 2048 the default?

Yes, ACMED support RSA 4096, ECDSA P-256 and ECDSA P-384. However, those are not (yet) fitted to be the default choice.

It is not obvious at the first sight, but [RSA 4096](https://gnupg.org/faq/gnupg-faq.html#no_default_of_rsa4096) is NOT twice more secure than RSA 2048. In fact, it adds a lot more calculation while providing only a small security improvement. If you think you will use it anyway since you are more concerned about security than performance, please check your certificate chain up to the root. Most of the time, the root certificate and the intermediates will be RSA 2048 ones (that is the case for [Let’s Encrypt](https://letsencrypt.org/certificates/)). If so, using RSA 4096 in the final certificate will not add any additional security since a system's global security level is equal to the level of its weakest point.

ECDSA certificates may be a good alternative to RSA since, for the same security level, they are smaller and requires less computation, hence improve performance. Unfortunately, as X.509 certificates may be used in various contexts, some software may not support this not-so-recent technology. To achieve maximal compatibility while using ECC, you usually have to set-up an hybrid configuration with both an ECDSA and a RSA certificate to fall-back to. Therefore, even if you are encouraged to use ECDSA certificates, it should not currently be the default. That said, it may be in a soon future.
