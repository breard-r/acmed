# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added
- The `kp_reuse` flag allow to reuse a key pair instead of creating a new one at each renewal.
- It is now possible to define hook groups that can reference either hooks or other hook groups.

### Changed
- `post_operation_hook` has been renamed `post_operation_hooks`.
