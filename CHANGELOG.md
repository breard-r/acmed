[//]: # (Copyright 2019-2020 Rodolphe Bréard <rodolphe@breard.tf>)

[//]: # (Copying and distribution of this file, with or without modification,)
[//]: # (are permitted in any medium without royalty provided the copyright)
[//]: # (notice and this notice are preserved.  This file is offered as-is,)
[//]: # (without any warranty.)

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.19.0] - 2022-04-17

### Added
- The `acmed@user.service` systemd unit configuration has been added as an alternative to the `acmed.service` unit.

### Changed
- The minimal required Rust version is now 1.46.

## [0.18.0] - 2021-06-13

### Added
- Add support for Ed25519 and Ed448 account keys and certificates.
- In addition to `restart`, the Polkit rule also allows the `reload`, `try-restart`, `reload-or-restart` and `try-reload-or-restart` verbs.


## [0.17.0] - 2021-05-04

### Added
- Allow the configuration of some default values at compile time using environment variables.

### Changed
- The template engine has been changed in favor of TinyTemplate, which has a different syntax than the previous one.
- The default account directory now is `/var/lib/acmed/accounts`.
- The default certificates and private keys directory now is `/var/lib/acmed/certs`.
- The default for volatile runtime data now is `/run`.


## [0.16.0] - 2020-11-11

### Added
- The `pkcs9_email_address`, `postal_address` and `postal_code` subject attributes has been added.

### Changed
- The `friendly_name` and `pseudonym` subject attributes has been removed.
- The `street_address` subject attribute has been renamed `street`.


## [0.15.0] - 2020-11-03

### Added
- The names of both the certificate file and the associated private key can now be configured.

### Fixed
- Configuration files cannot be loaded more than one time, which prevents infinite recursion.

### Changed
- Certificates are now allowed to share the same name if their respective key type is different.


## [0.14.0] - 2020-10-27

### Added
- Add proxy support through the `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables.
- Allow to specify a unique name for each certificate.

### Changed
- The minimal required Rust version is 1.42.0.


## [0.13.0] - 2020-10-10

### Added
- In the configuration, `root_certificates` has been added to the `global` and `endpoint` sections as an array of strings representing the path to root certificate files.
- At compilation, it is now possible to statically link OpenSSL using the `openssl_vendored` feature.
- In the Makefile, it is now possible to specify which target triple to build for.


## [0.12.0] - 2020-09-26

### Added
- Some subject attributes can now be specified.
- Support for NIST P-521 certificates and account keys.

### Fixed
- Support for Let's Encrypt non-standard account creation object.


## [0.11.0] - 2020-09-19

### Added
- The `contacts` account configuration field has been added.
- External account binding.

### Changed
- The `email` account configuration field has been removed. In replacement, use the `contacts` field.
- Accounts now have their own hooks and environment.
- Accounts are now stored in a single binary file.

### Fixed
- ACMEd can now build on platforms with a `time_t` not defined as an `i64`.
- The Makefile is now fully works on FreeBSD.


## [0.10.0] - 2020-08-27

### Added
- The account key type and signature algorithm can now be specified in the configuration using the `key_type` and `signature_algorithm` parameters.
- The delay to renew a certificate before its expiration date can be specified in the configuration using the `renew_delay` parameter at either the certificate, endpoint and global level.
- It is now possible to specify IP identifiers (RFC 8738) using the `ip` parameter instead of the `dns` one.
- The hook templates of type `challenge-*` have a new `identifier_tls_alpn` field which contains, if available, the identifier in a form that is suitable to the TLS ALPN challenge.
- Globing is now supported for configuration files inclusion.
- The CSR's digest algorithm can now be specified using the `csr_digest` parameter.

### Changed
- In the certificate configuration, the `domains` field has been renamed `identifiers`.
- The `algorithm` certificate configuration field has been renamed `key_type`.
- The `algorithm` hook template variable has been renamed `key_type`.
- The `domain` hook template variable has been renamed `identifier`.
- The default hooks have been updated.

### Fixed
- The Makefile now works on FreeBSD. It should also work on other BSD although it has not been tested.


## [0.9.0] - 2020-08-01

### Added
- System users and groups can now be specified by name in addition to uid/gid.

### Changed
- The HTTP(S) part is now handled by `attohttpc` instead of `reqwest`.

### Fixed
- In tacd, the `--acme-ext-file` parameter is now in conflict with `acme-ext` instead of itself.


## [0.8.0] - 2020-06-12

### Changed
- The HTTP(S) part is now handled by `reqwest` instead of `http_req`.

## Fixed
- `make install` now work with the busybox toolchain.


## [0.7.0] - 2020-03-12

### Added
- Wildcard certificates are now supported. In the file name, the `*` is replaced by `_`.
- Internationalized domain names are now supported.

### Changed
- The PID file is now always written whether or not ACMEd is running in the foreground. Previously, it was written only when running in the background.

### Fixed
- In the directory, the `externalAccountRequired` field is now a boolean instead of a string.


## [0.6.1] - 2019-09-13

### Fixed
- A race condition when requesting multiple certificates on the same non-existent account has been fixed.
- The `foregroung` option has been renamed `foreground`.


## [0.6.0] - 2019-06-05

### Added
- Hooks now have the optional `allow_failure` field.
- In hooks, the `stdin_str` has been added in replacement of the previous `stdin` behavior.
- HTTPS request rate limits.

### Changed
- Certificates are renewed in parallel.
- Hooks are now cleaned right after the current challenge has been validated instead of after the certificate's retrieval.
- In hooks, the `stdin` field now refers to the path of the file that should be written into the hook's standard input.
- The logging format has been re-written.

### Fixed
- The http-01-echo hook now correctly sets the file's access rights


## [0.5.0] - 2019-05-09

### Added
- ACMEd now displays a warning when the server indicates an error in an order or an authorization.
- A configuration file can now include several other files.
- Hooks have access to environment variables.
- In the configuration, the global section, certificates and domains can define environment variables for the hooks.
- tacd is now able to listen on a unix socket.


## [0.4.0] - 2019-05-08

### Added
- Man pages.
- The project can now be built and installed using `make`.
- The post-operation hooks now have access to the `is_success` template variable.
- Challenge hooks now have the `is_clean_hook` template variable.
- An existing certificate will be renewed if more domains have been added in the configuration.

### Changed
- Unknown configuration fields are no longer tolerated.

### Removed
- In challenge hooks, the `algorithm` template variable has been removed.

### Fixed
- In some cases, ACMEd was unable to parse a certificate's expiration date.


## [0.3.0] - 2019-04-30

### Added
- tacd, the TLS-ALPN-01 validation daemon.
- An account object has been added in the configuration.
- In the configuration, hooks now have a mandatory `type` variable.
- It is now possible to declare hooks to clean after the challenge validation hooks.
- The CLI `--root-cert` option has been added.
- Failure recovery: HTTPS requests rejected by the server that are recoverable, like the badNonce error, are now retried several times before being considered a hard failure.
- The TLS-ALPN-01 challenge is now supported. The proof is a string representation of the acmeIdentifier extension. The self-signed certificate itself has to be built by a hook.

### Changed
- In the configuration, the `email` certificate field has been replaced by the `account` field which matches an account object.
- The format of the `domain` configuration variable has changed and now includes the challenge type.
- The `token` challenge hook variable has been renamed `file_name`.
- The `challenge_hooks`, `post_operation_hooks`, `file_pre_create_hooks`, `file_post_create_hooks`, `file_pre_edit_hooks` and `file_post_edit_hooks` certificate variables has been replaced by `hooks`.
- The logs has been purged from many useless debug and trace entries.

### Removed
- The DER storage format has been removed.
- The `challenge` certificate variables has been removed.


## [0.2.1] - 2019-03-30

### Changed
- The bug that prevented from requesting more than two certificates has been fixed.


## [0.2.0] - 2019-03-27

### Added
- The `kp_reuse` flag allow to reuse a key pair instead of creating a new one at each renewal.
- It is now possible to define hook groups that can reference either hooks or other hook groups.
- Hooks can be defined when before and after a file is created or edited (`file_pre_create_hooks`, `file_post_create_hooks`, `file_pre_edit_hooks` and `file_post_edit_hooks`).
- It is now possible to send logs either to syslog or stderr using the `--to-syslog` and `--to-stderr` arguments.

### Changed
- `post_operation_hook` has been renamed `post_operation_hooks`.
- By default, logs are now sent to syslog instead of stderr.
- The process is now daemonized by default. It is possible to still run it in the foreground using the `--foregroung` flag.
