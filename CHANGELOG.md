# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added
- An account object has been added in the configuration.

### Changed
- In the configuration, the `email` certificate field has been replaced by the `account` field which matches an account object.
- The `token` challenge hook variable has been renamed `file_name`.
- The logs has been purged from many useless debug and trace entries.

### Removed
- The DER storage format has been removed.


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
