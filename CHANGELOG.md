
[//]: # (Copyright 2019-2020 Rodolphe Bréard <rodolphe@breard.tf>)

[//]: # (Copying and distribution of this file, with or without modification,)
[//]: # (are permitted in any medium without royalty provided the copyright)
[//]: # (notice and this notice are preserved.  This file is offered as-is,)
[//]: # (without any warranty.)

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
