# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Added
- Virtual root display: Jailed paths now always display as starting from the jail root, using forward slashes (`/`) on all platforms.
- Internal type-state engine (`StagedPath`): All path validation now uses a type-state pipeline for strict, auditable security guarantees. This benefits crate development and advanced users, but is fully hidden from typical API usage.
- Improved docs, roadmap, and tests for new clamping, canonicalization, and display logic.

### Changed
- All path validation now clamps traversal and absolute paths to the jail root; escapes are never allowed.
- `JailedPath` and `PathValidator` refactored for stricter jail enforcement and cross-platform consistency.

### Removed / Refactored
- **BREAKING:** Removed legacy types and traversal rejection; all path handling now clamps to jail root.

### Fixed
- Clippy lints, cross-platform display, and documentation issues.

### Changed
- **PathValidator:** Now uses `StagedPath` for all jail and candidate path handling. Jail existence check allows non-existent jails, but requires directories if present.
- **Clamping logic:** Absolute paths are forcibly clamped to jail root; all root components are stripped before joining to jail.
- **Integration and unit tests:** Updated to use new type-state API and dynamic jail roots.
- **README and docs:** Updated to explain type-state pattern, marker types, and new security guarantees.

### Removed / Refactored
- **BREAKING:** Removed `ClampedPath` type and all related logic. All clamping and normalization is now performed by `StagedPath` and its `.clamp()` method.
- **BREAKING:** Removed legacy newtypes and type aliases; all path handling now uses `StagedPath` and marker types.
- **BREAKING:** All usages, tests, and documentation updated to use the new type-state API.

### Fixed
- Fixed: All Clippy lints (needless_borrow, redundant_clone) resolved. All doctests and integration tests pass. Absolute path clamping logic fixed. Documentation and examples now compile and run successfully.

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
