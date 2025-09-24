# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2025-09-25

### Added
- `PathBoundary::try_new_app_path_with_env(subdir, env_name)` and `VirtualRoot::try_new_app_path_with_env(subdir, env_name)` convenience constructors
  - Always honor a specific environment variable override before falling back to the executable-relative directory
  - Accept any `AsRef<Path>` for `subdir`
- **Comprehensive mdBook documentation** with new ergonomics section covering:
  - Function signature best practices and type-driven design patterns
  - Interop vs Display guidelines for external API integration  
  - Escape hatches and ownership conversions
  - Equality, ordering, and naming conventions
  - Canonicalized vs lexical solution decision guide
  

### Changed
- `try_new_app_path(subdir, env_override)` on both `PathBoundary` and `VirtualRoot` now accept any `AsRef<Path>` for `subdir` (previously `&str`)
- Clarified and aligned environment override semantics with the upstream `app-path` crate:
  - When an override is present, the environment variable’s value is used as the final root path (no subdirectory append)
  - This corrects inconsistent behavior in earlier prereleases

### Documentation
- **Major README restructure**: Optimized newcomer experience with integrated decision guide and streamlined examples
- **LLM-ready API documentation**: Renamed `API_REFERENCE.md` → `LLM_API_REFERENCE.md` with enhanced function-calling compatibility for AI tools
- Standardized doc comments to the "SUMMARY / PARAMETERS / RETURNS / ERRORS / EXAMPLE" format across key modules
- Expanded docs for `app-path` constructors and linking helpers; improved method summaries for `VirtualPath` I/O and directory utilities
- **Expanded security explanations**: Enhanced coverage of type-system guarantees and CVE protections in both README and lib.rs
- **Real-world examples**: Updated demos with production-authentic integration patterns

### Migration
- Env override behavior for `app-path` constructors: when an environment override is set, its value is now treated as the final root path (no subdirectory append). If your previous code relied on subdir being appended even when the env var was set, update your configuration accordingly.

### Tests
- Added `app-path` feature tests covering env override precedence for both `PathBoundary` and `VirtualRoot`


## [0.1.0-alpha.6] - 2025-09-18

### Added
- **Symlink and Hard Link Support**: Complete support for creating symbolic and hard links within path boundaries
  - `StrictPath::strict_symlink(link_path)` - Creates symbolic links between paths in the same boundary
  - `StrictPath::strict_hard_link(link_path)` - Creates hard links between paths in the same boundary
  - `VirtualPath::virtual_symlink(link_path)` - Creates symbolic links between virtual paths in the same root
  - `VirtualPath::virtual_hard_link(link_path)` - Creates hard links between virtual paths in the same root
  - `PathBoundary::strict_symlink(link_path)` - Creates symbolic links pointing to the PathBoundary root directory
  - `PathBoundary::strict_hard_link(link_path)` - Creates hard links pointing to the PathBoundary root directory  
  - `VirtualRoot::virtual_symlink(link_path)` - Creates symbolic links pointing to the virtual root directory
  - `VirtualRoot::virtual_hard_link(link_path)` - Creates hard links pointing to the virtual root directory

### Enhanced
- **Security Testing**: Added comprehensive advanced security test suite covering edge cases and attack vectors
- **Link Resolution**: Improved symlink resolution and junction handling on Windows platforms

### Fixed  
- **Code Quality**: Fixed clippy lints including unnecessary let bindings in demos

## [0.1.0-alpha.5] - 2025-09-17

### Added
- **Temporary Directory Support**: Missing RAII-backed temporary directory constructors for the virtual dimension
  - `VirtualRoot::try_new_temp()` - Creates virtual root with automatic cleanup
  - `VirtualRoot::try_new_temp_with_prefix(prefix)` - Temporary directory with custom prefix
- **Metadata Access**: New methods to inspect filesystem properties
  - `PathBoundary::metadata()`, `VirtualRoot::metadata()`, `StrictPath::metadata()` & `VirtualPath::metadata()` - Returns filesystem metadata 
- **Directory Discovery**: Consistent helpers to enumerate entries safely before re-joining
  - `StrictPath::read_dir()`, `VirtualPath::read_dir()`, `PathBoundary::read_dir()` & `VirtualRoot::read_dir()`
- **Conversion Helpers**: Ergonomic conversions between path values and policy roots
  - `StrictPath::try_into_boundary()` and `StrictPath::try_into_boundary_create()`
  - `VirtualPath::try_into_root()` and `VirtualPath::try_into_root_create()`
- **Root Deletion Helpers**: Manage root directories directly at policy types
  - `PathBoundary::remove_dir()` and `PathBoundary::remove_dir_all()`
  - `VirtualRoot::remove_dir()` and `VirtualRoot::remove_dir_all()`
- **VirtualPath API Expansion**: Complete implementation of virtual path operations
  - `virtual_copy(dest)` - Copies files/directories within virtual space with clamping
  - `virtual_rename(dest)` - Enhanced rename with proper virtual space resolution  
  - `create_parent_dir()` / `create_parent_dir_all()` - Directory creation in virtual dimension
  - `read()` / `write()` - Simplified I/O methods (replacing deprecated `read_bytes`/`write_string`)
  - Virtual path manipulation: `virtualpath_with_*`, `virtualpath_file_*`, `virtualpath_*_with` methods

### Deprecated
- **I/O Methods**: Older I/O methods replaced with simplified alternatives
  - `read_bytes()` → use `read()` instead
  - `write_bytes()` / `write_string()` → use `write()` instead

### Documentation
- API reference updated to include `read_dir()` on all core types, root deletion helpers, and the new conversion helpers
- Examples and best practices now use `boundary.read_dir()`/`vroot.read_dir()` instead of `std::fs::read_dir(boundary.interop_path())`
- Removed outdated guidance around constructing roots via empty joins; constructor docs and anti-patterns guide reflect current APIs

## [0.1.0-alpha.4] - 2025-09-16

### Added
- **Rename/Move Operations**: Safe file and directory renaming within boundaries
  - `StrictPath::strict_rename(dest)` - Renames within the same `PathBoundary`
  - `VirtualPath::virtual_rename(dest)` - Renames within virtual space with clamping
  - Relative destinations resolve as siblings; absolute destinations validated against boundaries
  - Comprehensive test suite with 225+ lines covering edge cases, escapes, and cross-platform behavior
- **API Sugar Constructors**: Ergonomic one-liner constructors for simple flows
  - `StrictPath::with_boundary(..)` and `StrictPath::with_boundary_create(..)`
  - `VirtualPath::with_root(..)` and `VirtualPath::with_root_create(..)`

### Changed
- **Internal Refactoring**: Renamed `restriction` field to `boundary` throughout codebase for consistency
  - Affects `StrictPath` and `VirtualPath` internal structure and debug output
  - Public API unchanged; purely internal consistency improvement

### Documentation
- Crate-level Quick start now leads with the new sugar constructors
- Updated all examples to use sugar constructors (`with_boundary`/`with_root`) over policy types for simple flows
- Added comprehensive rename operation examples in lib.rs documentation
- Doctests updated to use temporary directories for reliable CI execution

## [0.1.0-alpha.3] - 2025-09-15

### Changed
- Renamed all repository links and badges from `DK26/jailed-path-rs` to `DK26/strict-path-rs` across the codebase
  - README badges and guide URL now point to `https://github.com/DK26/strict-path-rs` and `https://dk26.github.io/strict-path-rs/`
  - Crate metadata (`repository`, `homepage`) updated in `strict-path/Cargo.toml`
  - Release workflow notes updated to reference the new repository
- Crate-level docs link updated to the new repository path in `strict-path/src/lib.rs`

### Dependencies
- Bumped `soft-canonicalize` from `0.3.4` to `0.3.6` (feature `anchored` unchanged)

### License
- Refreshed `LICENSE-APACHE` wording to the standard Apache-2.0 template and updated copyright year

## [0.1.0-alpha.2] - 2025-09-13

### Added

- **OS Directory Constructors**: `try_new_os_*` methods for standard directories (config, data, cache, home, desktop, documents, downloads, pictures, audio, videos, executables, runtime, state) on both `PathBoundary` and `VirtualRoot`
- **MDBook Documentation**: Complete guide with OS directory examples and cross-platform tables
- **Demos Crate**: Moved real-world demos from `examples/` to separate `demos/` crate with feature flags
- **Input Source Decision Matrix**: Comprehensive table showing when to use `VirtualPath` vs `StrictPath` for different input sources
- **Security Education**: "Why Simple Solutions Fail" section explaining common path security vulnerabilities

### Changed - BREAKING

- **API**: `.unrestrict()` → `.unstrict()`, `tempdir` → `tempfile` feature  
- **Project Structure**: Demos moved to separate crate for MSRV isolation

### Changed

- **Documentation Structure**: Major overhaul for better accessibility and human readability
  - Renamed "Anti‑Patterns (Tell‑offs)" to "Common Mistakes to Avoid" 
  - Restructured README with immediate security hook and practical examples
  - Enhanced examples to follow "encode guarantees in signatures" principle
- **Function Signatures**: Updated all examples to pass `PathBoundary`/`VirtualRoot` as parameters instead of creating them inside functions
- **API Reference**: Updated with accurate method signatures and complete feature coverage
- **Anti-Patterns Documentation**: Rewritten from LLM-style to developer-friendly format with clear ❌/✅ examples

### Fixed

- **References**: Updated `jailed-path` → `strict-path` throughout codebase
- **Table Formatting**: Fixed corrupted markdown tables in README with proper headers and structure
- **Method Consistency**: Fixed examples to use `.as_unvirtual()` instead of `.unvirtual()` for borrowing patterns

## [0.1.0-alpha.1] - 2024-12-09

### Changed - BREAKING 

- **Complete API Restructure**: Renamed crate from `jailed-path` to `strict-path` with comprehensive API updates
- **Core Type Names**: 
  - `Jail<T>` → `PathBoundary<T>` - represents the secure root boundary
  - `VirtualRoot<T>` → `VirtualRoot<T>` - unchanged name but new implementation  
  - `JailedPath<T>` → `StrictPath<T>` - path validated within boundary
  - `VirtualPath<T>` → `VirtualPath<T>` - unchanged name but updated integration
- **Method Naming Consistency**:
  - `jailed_join()` → `strict_join()` - join paths within boundary
  - `systempath_display()` → `strictpath_display()` - display system path
  - Kept `virtualpath_display()` for virtual path display
- **Enhanced Type System**: Complete rewrite of internal validation pipeline using `PathHistory<State>` for compile-time path validation guarantees
- **Extended Platform Support**: Added comprehensive feature gates for `dirs`, `tempdir`, and `app-path` integrations

### Added

- **Convenience Constructors**: 
  - `PathBoundary::try_new_config()`, `try_new_data()`, `try_new_cache()` for system directories
  - `PathBoundary::try_new_temp()` for RAII temporary directories  
  - `VirtualRoot::try_new_*()` equivalents for virtual filesystem scenarios
- **String Parsing**: `FromStr` implementations for both `PathBoundary` and `VirtualRoot` enabling seamless CLI/config integration
- **Comparison Traits**: Full `PartialEq/Eq/PartialOrd/Ord/Hash` implementations with cross-type compatibility
- **Enhanced Security Tests**: 1000+ lines of new security tests covering:
  - CVE-2025-8088 style ADS traversal attacks (Windows)
  - Zip-slip and tar-slip extraction scenarios
  - Unicode normalization edge cases
  - TOCTOU (Time-of-Check-Time-of-Use) attack scenarios
  - Platform-specific symlink/junction escape attempts

### Security

- **Windows ADS Protection**: Specific defenses against CVE-2025-8088 style attacks using NTFS Alternate Data Streams
- **Enhanced Symlink Validation**: Improved detection and rejection of symlink-based escape attempts on all platforms  
- **Directory Traversal Hardening**: Comprehensive protection against `../` style attacks through virtual path clamping
- **Path Injection Prevention**: Robust validation of all user-supplied path components before filesystem operations

### Fixed  

- **Cross-Platform Compatibility**: Resolved Windows/Unix path separator handling inconsistencies
- **Memory Safety**: Eliminated potential path buffer overflows through type-safe path construction
- **Error Handling**: More precise error types distinguishing between boundary violations vs filesystem I/O errors

### Changed

- Placeholder for future changes

### Added  

- Placeholder for future additions

### Fixed

- Placeholder for future fixes

## [0.0.4] - 2025-08-03

### Added

- **Virtual root display system**: `JailedPath` now always displays as starting from the jail root using forward slashes (`/`) on all platforms, hiding internal filesystem details from users
- **Internal type-state validation engine**: Introduced `ValidatedPath` with compile-time state tracking for strict, auditable security guarantees through marker types (`Raw`, `Clamped`, `JoinedJail`, `Canonicalized`, `BoundaryChecked`)
- Removed: The `try_jail()` helper has been removed in favor of explicit `Jail::try_new(...).try_path(...)` usage for clarity and consistency.
- **Safe file operations trait**: `JailedFileOps` trait provides jail-safe file operations (`read_to_string()`, `write_bytes()`, `exists()`, `create_dir_all()`, etc.) without exposing raw paths
- **Enhanced examples and documentation**: Added comprehensive examples for real-world usage patterns, marker types, virtual root display, and safe file operations

### Changed

- **Path validation behavior**: All path validation now clamps traversal and absolute paths to the jail root instead of rejecting them - escapes are mathematically impossible
- **API restructure**: Complete refactor of `JailedPath` and `PathValidator` for stricter jail enforcement and cross-platform consistency using type-state validation
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
