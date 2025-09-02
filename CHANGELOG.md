# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Changed

- **BREAKING: API Rename**: Renamed `PathValidator` to `Jail` throughout the codebase for improved clarity and ergonomics

### Added

- Windows: Introduced `JailedPathError::WindowsShortName { component, original, checked_at }` returned when a DOS 8.3 short filename component (e.g., `PROGRA~1`) is detected in a non-existent path segment. This enables callers to implement their own recovery (e.g., prompting for a full long name) instead of treating it as a generic resolution error.
- **Enhanced Security Documentation**: Added comprehensive CVE protection documentation highlighting specific vulnerabilities addressed (CVE-2025-8088, CVE-2022-21658, Windows 8.3 CVEs) and emphasizing the security depth beyond simple string comparison
- **Security Foundation Messaging**: Updated README, crate docs, and API reference to emphasize the soft-canonicalize foundation and real-world vulnerability protection

### Security

- Windows hardening (Hybrid): Before canonicalization, the validator rejects 8.3 short-name looking components that do not yet exist inside the jail. Existing entries pass through and are validated normally. This reduces ambiguity and potential bypasses while keeping compatibility for already-present short-name entries.
- **BREAKING: Constructor Rename**: `PathValidator::with_jail()` is now `Jail::try_new()` for consistency with Rust naming conventions
- Updated all examples, documentation, and tests to use the new `Jail` API
- Added `examples/new_api.rs` to demonstrate the updated API usage
 - Windows hardening: Reject DOS 8.3 short filename components (e.g., `PROGRA~1`) when those components do not yet exist inside the jail, to avoid ambiguous future resolution outside/inside the boundary.

### Fixed

- **macOS test compatibility**: Fixed platform-specific path handling in security tests to properly handle Unix vs Windows path separator differences and temp directory canonicalization on macOS

## [0.0.4] - 2025-08-03

### Added

- **Virtual root display system**: `JailedPath` now always displays as starting from the jail root using forward slashes (`/`) on all platforms, hiding internal filesystem details from users
- **Internal type-state validation engine**: Introduced `ValidatedPath` with compile-time state tracking for strict, auditable security guarantees through marker types (`Raw`, `Clamped`, `JoinedJail`, `Canonicalized`, `BoundaryChecked`)
- Removed: The `try_jail()` helper has been removed in favor of explicit `Jail::try_new(...).try_path(...)` usage for clarity and consistency.
- **Safe file operations trait**: `JailedFileOps` trait provides jail-safe file operations (`read_to_string()`, `write_bytes()`, `exists()`, `create_dir_all()`, etc.) without exposing raw paths
- **Enhanced examples and documentation**: Added comprehensive examples for real-world usage patterns, marker types, virtual root display, and safe file operations

### Changed

- **BREAKING: Path validation behavior**: All path validation now clamps traversal and absolute paths to the jail root instead of rejecting them - escapes are mathematically impossible
- **BREAKING: API restructure**: Complete refactor of `JailedPath` and `PathValidator` for stricter jail enforcement and cross-platform consistency using type-state validation
- **Enhanced crate description**: Updated to "Prevent directory traversal with type-safe virtual path jails and safe symlinks"
- **Non-existent jail handling**: `PathValidator` now allows creation with non-existent jail directories (validates they would be directories if they exist)
- **Comprehensive test suite**: Updated all integration and unit tests to validate new clamping behavior and type-state API

### Dependencies

- **Added**: `tempfile = "3.20.0"` as dev dependency for robust testing

### Technical Implementation

- **Type-state pipeline**: All path validation uses `ValidatedPath<State>` where `State` tracks the exact sequence of security transformations
- **Clamping algorithm**: Absolute paths are forcibly clamped to jail root; all root components stripped before joining to jail
- **Virtual path abstraction**: Clean separation between user-facing virtual paths and internal real filesystem paths

### Fixed

- All Clippy lints resolved (`needless_borrow`, `redundant_clone`)
- Cross-platform display consistency across Windows, macOS, and Linux
- All doctests and integration tests now pass with new validation behavior
- Documentation examples compile and run successfully

## [0.0.3] - 2025-07-21

### Added
- **Type-State Police™ branding**: Added humorous tagline to embrace the compile-time safety theme
- **Enhanced documentation**: Comprehensive docs for `PathValidator::with_jail()` with clear error conditions

### Changed
- **Crate description**: Updated to "Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed"
- **Better examples**: All examples now use realistic paths ("public", "config", "uploads") instead of temp directories
- **Improved documentation flow**: Reorganized sections for better user experience

### Dependencies
- Updated `soft-canonicalize` to `0.1.2`
- Updated `app-path` dev dependency to `1.0.2`

## [0.0.2] - 2025-07-18

### Added
- **Comprehensive documentation overhaul**: Complete restructure following modern Rust documentation standards
  - Added Quick Start section with immediate working examples
  - Detailed Key Features and API Design sections
  - Security Guarantees section explaining protection mechanisms
  - Integration examples showing real-world usage patterns
- **Working documentation examples**: All doc tests now compile and run successfully
  - Web server file serving example with proper error handling
  - app-path integration example using correct API methods
  - Added app-path as dev dependency for documentation examples
- **Enhanced crate-level documentation**: Following app-path style and structure
  - Clear purpose statement and value proposition
  - Comprehensive API overview with security focus
  - Type-safe guarantees prominently featured
- **Improved module documentation**: Enhanced docs for all public types
  - PathValidator with detailed security examples
  - JailedPath with compatibility demonstrations
  - Comprehensive error handling examples

### Changed
- **Documentation structure**: Reorganized to follow modern Rust crate conventions
  - Moved from basic examples to comprehensive integration guides
  - Eliminated redundancy while improving clarity
  - Focus on copy-pasteable, working code examples
- **README.md**: Complete rewrite following professional standards
  - Clear project purpose and security value proposition
  - Working examples that demonstrate real integration patterns
  - Proper app-path API usage throughout examples

### Dependencies
- **Added dev dependency**: `app-path = "0.2.7"` for documentation examples
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

### Technical Changes
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
