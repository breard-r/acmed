
[//]: # (Copyright 2019-2020 Rodolphe Bréard <rodolphe@breard.tf>)

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

- http-01, dns-01 and [tls-alpn-01](https://tools.ietf.org/html/rfc8737) challenges
- RSA 2048, RSA 4096, ECDSA P-256 and ECDSA P-384 certificates
- Internationalized domain names support
- Fully customizable challenge validation action
- Fully customizable archiving method (yes, you can use git or anything else)
- Nice and simple configuration file
- A pre-built set of hooks that can be used in most circumstances
- Run as a deamon: no need to set-up timers, crontab or other time-triggered process
- Retry of HTTPS request rejected with a badNonce or other recoverable errors
- Customizable HTTPS requests rate limits.
- Optional key pair reuse (useful for [HPKP](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning))
- For a given certificate, each domain name may be validated using a different challenge.
- A standalone server dedicated to the tls-alpn-01 challenge validation (tacd).


## Planned features

- IP Identifier Validation Extension [RFC 8738](https://tools.ietf.org/html/rfc8738)
- STAR Certificates [RFC 8739](https://tools.ietf.org/html/rfc8739)
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

In order to compile ACMEd, you will need the [Rust](https://www.rust-lang.org/) compiler and its package manager, Cargo. The minimal required Rust version is 1.40.0, although it is recommended to use the latest stable one.

ACMEd depends OpenSSL 1.1.0 or higher.

On systems based on Debian/Ubuntu, you may need to install the `libssl-dev`, `build-essential` and `pkg-config` packages.

On Alpine Linux, you may need to install the `openssl-dev` and `alpine-sdk` packages. Since Alpine Linux 3.12 you can use the `rust` and `cargo` packages from the community repository. Older versions of Alpine Linux will require you to install the stable version of Rust using rustup.

```
$ make
$ make install
```

To build ACMEd and tacd inside a temporary Docker container, use the `contrib/build-docker.sh` helper script. It currently supports Debian Buster / Stretch.


## Frequently Asked Questions

### Why this project?

After testing multiple ACME clients, I found out none supported all the features I wished for (see the key features above). It may have been possible to contribute or fork an existing project, however I believe those project made architectural choices incompatible with what i wanted, and therefore it would be as much or less work to start a new project from scratch.

### Is it free and open-source software?

Yes, ACMEd is dual-licensed under the MIT and Apache 2.0 terms. See [LICENSE-MIT.txt](LICENSE-MIT.txt) and [LICENSE-APACHE-2.0.txt](LICENSE-APACHE-2.0.txt) for details.

The man pages, the default hooks configuration file, the `CHANGELOG.md` and the `README.md` files are released under the [GNU All-Permissive License](https://www.gnu.org/prep/maintain/html_node/License-Notices-for-Other-Files.html).

### Can it automatically change my server configuration?

Short answer: No.

Long answer: At some points in a certificate's life, ACMEd triggers hook in order to let you customize how some actions are done, therefore you can use those hooks to modify any server configuration you wish. However, this may not be what you are looking for since it cannot proactively detect which certificates should be emitted since ACMEd only manages certificates that have already been declared in the configuration files.

### How should I configure my TLS server?

You decide. ACMEd only retrieve the certificate for you, it does not impose any specific configuration or limitation on how to use it. For the record, if you are looking for security recommendations on TLS deployment, you can follow the [ANSSI TLS guide](https://www.ssi.gouv.fr/en/guide/security-recommendations-for-tls/) (the english version might not be the latest version of this document, if possible use [the french one](https://www.ssi.gouv.fr/entreprise/guide/recommandations-de-securite-relatives-a-tls/)).

### Should ACMEd run as root?

Running ACMEd as root is the simplest configuration since you do not have to worry about access rights, especially within hooks (Eg: restart a service).

However, if you are concerned with safety, you should create a dedicated user for ACMEd. Before doing so, please consider the following points: "Will your services be able to read both the private key and the certificate?" and "Will the ACMEd user be able to execute the hooks?". The later could be achieved using sudo or Polkit.

### Why is there no option to run ACMEd as a specific user or group?

The reason some services has such an option is because at startup they may have to load data only accessible by root, hence they have to change the user themselves after those data are loaded. For example, this is wildly used in web servers so they load a private key, which should only be accessible by root. Since ACMEd does not have such requirement, it should be run directly as the correct user.

### How can I run ACMEd with systemd?

An example service file is provided (see `contrib/acmed.service.example`). The file might need adjustments in order to work on your system (e.g. binary path, user, group, directories...), but it's probably a good starting point.

### Is it suitable for beginners?

It depends on your definition of a beginner. This software is intended to be used by system administrator with a certain knowledge of their environment. Furthermore, it is also expected to know the bases of the ACME protocol. Let's Encrypt wrote a nice article about [how it works](https://letsencrypt.org/how-it-works/).

### Why is RSA 2048 the default?

Short answer: it is sufficiently secured, has good performances and is wildly supported.

Before choosing a different algorithm for your certificate's signature, you might want to consider all of those three points.

* For security, you may refer to the table 2 of the [NIST SP 800-57 Part 1](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final).
* For performances, you can launch the following command on your machine: `openssl speed rsa2048 rsa3072 rsa4096 ecdsap256 ecdsap384 ecdsap521 ed25519 ed448`. Your server will be affected by the signature performances and the clients connecting to it will be affected by the verification performances.
* Nowadays, every client support ECDSA support. So, unless you have very specific requirements, you can safely use it. At time of writing, EdDSA certificates are not yet supported, but it might become a thing in the future.

Currently, security and client support aren't the main concerns since every possible type of certificates is good enough on those two points. The performances clearly favors ECDSA P-256, Ed25519 and RSA 2048. The later has been chosen as the default because it's the most wildly used as Certification Authorities root and intermediate certificates. This choice could change in favor of ECDSA once Let's Encrypt issues [a full ECDSA certificates chain](https://community.letsencrypt.org/t/lets-encrypt-new-hierarchy-plans/125517).
