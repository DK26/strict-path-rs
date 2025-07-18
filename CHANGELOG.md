# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Soft canonicalization algorithm**: Pure path resolution without filesystem modification
  - Handles non-existing paths securely by processing logical path traversal
  - Resolves `..` components mathematically without requiring filesystem touch operations
  - Provides security benefits of canonicalization for paths that don't exist yet
- **Cross-platform compatibility improvements**:
  - Conditional compilation for Windows vs Unix paths in tests and examples
  - Platform-appropriate test attack vectors and path generation
  - Updated all hardcoded Unix paths to use cross-platform alternatives
- **Enhanced test coverage**: Expanded from 58 to 57 comprehensive tests
  - Cross-platform test helpers for realistic attack simulation
  - Full coverage of edge cases including deeply nested non-existing paths
- **Improved documentation**: Updated examples to use platform-appropriate paths

### Changed
- **PathValidator**: Now uses soft canonicalize algorithm instead of touch technique
  - Eliminates filesystem modification during validation
  - Improves security by preventing side effects during path checking
  - Maintains mathematical precision in path resolution
- **Cross-platform examples**: All examples now work correctly on Windows, macOS, and Linux
- **Soft canonicalize extraction**: Moved soft canonicalize functionality to separate `soft-canonicalize` crate
  - Added dependency on `soft-canonicalize = "0.1.0"`
  - Maintains API compatibility while allowing independent versioning
  - Enables reuse of soft canonicalize algorithm in other projects

### Security
- **Zero filesystem modification**: Validation no longer creates temporary filesystem entries
- **Mathematical path security**: Pure algorithmic approach eliminates timing attacks and filesystem-based vulnerabilities

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
