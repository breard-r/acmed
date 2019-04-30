# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added
- An account object has been added in the configuration.
- In the configuration, hooks now have a mandatory `type` variable.
- It is now possible to declare hooks to clean after the challenge validation hooks.
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
