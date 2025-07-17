# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive lexical validation to block `..` components before filesystem operations
- Expanded test suite from basic coverage to 58 comprehensive tests covering security, edge cases, and integration scenarios

## [0.0.1] - 2025-07-16

### Added
- Initial release of `jailed-path` crate
- `PathValidator` type for defining jail boundaries
- `JailedPath` type for validated paths within jail boundaries
- `JailedPathError` with comprehensive error handling
- Zero-dependency implementation
- Cross-platform support (Windows, macOS, Linux)
- Comprehensive documentation and examples

### Features
- Path validation ensuring paths stay within jail boundaries
- Path canonicalization to resolve symlinks and relative components
- Type-safe validation preventing directory traversal
- Simple two-type API: `PathValidator` and `JailedPath`
