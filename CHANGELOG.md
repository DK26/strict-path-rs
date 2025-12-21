# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-12-20

### Added
- **New I/O methods** for `StrictPath` and `VirtualPath`:
  - `open_with()` - Advanced file opening with custom `OpenOptions`
  - `append()` - Append data to files
  - `read_dir()` / `strict_read_dir()` / `virtual_read_dir()` - Safe directory iteration
  - `read_link()` / `strict_read_link()` / `virtual_read_link()` - Symlink target validation
  - `set_permissions()` - Modify file permissions
  - `try_exists()` - Check file existence without requiring it to exist
  - `touch()` - Create empty file or update timestamp
- **Formal verification**: Added Kani proof harness for mathematical verification of virtualization clamping logic
- **Security testing**: Comprehensive fuzz tests for security invariants (1000+ iterations)
- **CI workflows**: Kani verification and semver compatibility checks

### Changed
- **Windows junction dependency**: Switched from `junction` to the `junction-verbatim` git fork crate
  - `junction-verbatim` is a fork published to crates.io, for use until PR tesuji/junction#31 is merged and published. 
  - Fixes tesuji/junction#30 (verbatim prefix handling bug)
  - Enables crates.io publishing (git deps not allowed on registry)

### Documentation
- **README badges**: Added Kani Verified and Protected CVEs badges
- **Security guidance**: Enhanced documentation on `interop_path()` risks in user-facing contexts
- **Use case clarification**: Better guidance on StrictPath vs VirtualPath for file upload scenarios

### Fixed
- **MSRV compatibility**: Fixed filesystem tests for Rust 1.71.0 and Linux CI environments
- **Windows junction tests**: Enhanced junction handling and comprehensive test coverage

## [0.1.0-rc.2] - 2025-12-11

### Fixed
- **Critical security fix**: Upgrade `soft-canonicalize` from 0.4.5 → 0.5.2 to address indirect `/proc/PID/root` symlink bypass
  - Indirect symlinks to `/proc/self/root` (e.g., `/tmp/link -> /proc/self/root`) now correctly preserve the `/proc` path instead of resolving to `/` (host root)
  - Fixes container isolation bypass where `PathBoundary::try_new("/proc/12345/root")` would silently become `/`, making all security checks useless
  - Upstream fix in `proc-canonicalize` v0.0.3 adds post-check detection and correction
  - See [soft-canonicalize#44](https://github.com/DK26/soft-canonicalize-rs/issues/44) for details
- **Windows junction verbatim prefix fix**: Add `strip_verbatim_prefix` helper to work around junction crate bug #30
  - `\\?\` prefix caused `ERROR_INVALID_NAME` (123) on created junctions
- **Windows anchored path fix**: Fix `soft-canonicalize` anchored_canonicalize producing malformed verbatim paths on Windows (`\\?\C:foo` instead of `\\?\C:\foo`)

### Added
- **New method**: `symlink_metadata()` for `StrictPath` and `VirtualPath`
  - Query link metadata without following symlinks
  - Useful for distinguishing symlinks from regular files/directories
- **Comprehensive `/proc` symlink security tests** (1500+ lines):
  - Black-box attacker-perspective escape attempts
  - White-box internal behavior and edge cases
  - CVE resistance tests: runc-style and container runtime escape patterns
  - PathBoundary/VirtualRoot container boundary tests
  - All `/proc` magic variants: `/proc/self/{root,cwd}`, `/proc/thread-self/root`, `/proc/{PID}/{root,cwd}`
  - Indirect symlink chains (2x and 3x deep) to `/proc` magic paths
  - VirtualRoot isolation through indirect symlinks
  - Edge cases: Unicode, long paths, empty segments

### Changed
- **BREAKING**: Updated `soft-canonicalize` dependency from 0.4.5 → 0.5.2
  - Includes critical security fix for indirect `/proc/PID/root` symlink bypass
  - Linux container environments now properly enforce isolation boundaries

### Documentation
- **Renamed LLM documentation files** (Issue #31):
  - `LLM_API_REFERENCE.md` → `LLM_CONTEXT_FULL.md` (full API reference)
  - `LLM_USER.md` → `LLM_CONTEXT.md` (Context7-style guide)
  - Deprecation stubs created at old locations with redirects
- **Aligned messaging with project description**:
  - "Handle paths from external or unknown sources securely"
  - Added soft-canonicalize + proc-canonicalize foundation details
  - Added "minimal, restrictive, explicit" API philosophy
  - Note "security > performance" trade-off
- **Updated AGENTS.md** with "CHECK FOR EXISTING FUNCTIONALITY" guidance
- **Improved doctests** with descriptive untrusted input variable names

### CI
- Updated push branch from `main` to `dev` (#32)

## [0.1.0-rc.1] - 2025-10-21

Release candidate for 0.1.0 stable release.

### Removed
- **BREAKING**: Removed deprecated methods (deprecated since 0.1.0-alpha.5)
  - `StrictPath::read_bytes()` - Use `read()` instead
  - `StrictPath::write_bytes(data)` - Use `write(data)` instead
  - `StrictPath::write_string(data)` - Use `write(data)` instead
  - `VirtualPath::read_bytes()` - Use `read()` instead
  - `VirtualPath::write_bytes(data)` - Use `write(data)` instead
  - `VirtualPath::write_string(data)` - Use `write(data)` instead
  - **Rationale**: Simplifies API surface and enforces consistent method names

### Changed
- **BREAKING**: Removed feature-gated ecosystem integrations from library core
  - **Removed features**: `serde`, `dirs`, `tempfile`, `app-path`
  - **Removed modules**: `serde_ext` (WithBoundary/WithVirtualRoot seeds)
  - **Removed impls**: `Serialize` for `StrictPath`/`VirtualPath`
  - **Removed constructors**: `try_new_os_*`, `try_new_temp*`, `try_new_app_path*`
  - **Rationale**: Users now compose ecosystem crates directly with validation primitives for maximum flexibility
  - **Migration** (composition pattern):
    ```rust
    // Before: PathBoundary::try_new_os_config("app")?
    // After:
    let config_dir = dirs::config_dir()?.join("app");
    PathBoundary::try_new_create(config_dir)?

    // Before: PathBoundary::try_new_temp()?
    // After:
    let temp = tempfile::tempdir()?;
    PathBoundary::try_new(temp.path())?

    // Before: WithBoundary(&boundary).deserialize(de)?
    // After:
    let raw: String = String::deserialize(de)?;
    let boundary: PathBoundary = raw.parse()?;
    // Then validate untrusted segments:
    boundary.strict_join(untrusted_segment)?
    ```

### Added
- **Windows junction support** (feature: `junctions`)
  - Added optional junction helpers with inline implementation
  - `StrictPath::strict_junction(link_path)` - Creates junctions between paths in the same boundary
  - `VirtualPath::virtual_junction(link_path)` - Creates junctions between virtual paths
  - `PathBoundary::strict_junction(link_path)` - Creates junctions pointing to boundary root
  - `VirtualRoot::virtual_junction(link_path)` - Creates junctions pointing to virtual root
  - Enables Windows junction support without requiring Developer Mode/admin privileges
  - Useful fallback when symlink creation fails with ERROR_PRIVILEGE_NOT_HELD (1314)
- **CVE protection verification**
  - Added comprehensive tests demonstrating protection against CVE-2025-11001 (Windows 8.3 short name bypass)
  - Added tests demonstrating protection against CVE-2025-11002 (symlink-based TOCTOU attacks)
  - Validates that strict-path's canonicalization-based approach prevents both classes of vulnerabilities

### Documentation
- **Clarified interop_path() usage**
  - Enhanced documentation explaining when to use `.interop_path()` vs built-in I/O methods
  - Added anti-patterns section warning against wrapping `.interop_path()` in `Path::new()` or `PathBuf::from()`
  - Emphasized that `.interop_path()` should only be used for third-party crate integration
- **Variable naming rules and ecosystem integration patterns**
  - Updated documentation with clear variable naming conventions for VirtualRoot and PathBoundary
  - Added guidance on realistic demo patterns and ecosystem integration
  - Enhanced examples showing composition with dirs, tempfile, and other crates
- **Link creation refactoring**
  - Refactored link creation methods to accept generic path types
  - Improved type ergonomics for symlink/junction/hard link helpers

### New Examples
- **Ecosystem integration examples** (replacing removed features):
  - `strict-path/examples/app_path_integration.rs` - Shows composition with app-path crate
  - `strict-path/examples/dirs_integration.rs` - Shows composition with dirs crate
  - `strict-path/examples/tempfile_integration.rs` - Shows composition with tempfile crate
  - Removed: `strict-path/examples/os_directories.rs` (replaced by dirs_integration.rs)

### Demos
- **Updated demos** to use composition pattern instead of removed features:
  - `demos/src/bin/config/app_path_demo.rs` - Now composes with app-path directly
  - `demos/src/bin/config/os_directories_demo.rs` - Now composes with dirs directly
  - `demos/src/bin/filesystem/dirs_demo.rs` - Updated for composition pattern
  - `demos/src/bin/filesystem/tempfile_demo.rs` - Updated for composition pattern
  - `demos/src/bin/web/axum_static_server.rs` - Updated for new patterns
  - **Major refactor**: `demos/src/bin/config/config_management_example.rs` - Complete rewrite using composition pattern

## [0.1.0-beta.3] - 2025-10-14

### Changed
- **BREAKING**: `VirtualPath` and `VirtualRoot` now require the `virtual-path` feature (closes #19)
  - `StrictPath` and `PathBoundary` remain always available (the core 90% use case)
  - **Philosophy shift**: StrictPath is for *detecting* escape attempts (archive extraction, file uploads, config loading), VirtualPath is for *containing* escape attempts (sandboxes, multi-tenant systems)
  - To enable virtual paths: `strict-path = { version = "...", features = ["virtual-path"] }`
  - **Rationale**: Making VirtualPath opt-in teaches the correct mental model (detect vs. contain) and reduces binary size for users who don't need containment semantics
- **BREAKING**: Updated `soft-canonicalize` dependency from 0.3.6 → 0.4.5 (addresses #18)
  - **0.4.0**: Virtual symlink clamping - `VirtualPath` now clamps absolute symlink targets to the virtual root instead of rejecting them
    - Implements true virtual filesystem semantics where symlinks like `/etc/config` are interpreted as `vroot/etc/config`
    - Perfect for multi-tenant systems and archive extractors where symlinks must stay within user sandboxes
    - `StrictPath` behavior unchanged: continues to use system filesystem semantics and rejects escaping symlinks
  - **0.4.1**: Critical bug fix for anchored canonicalization symlink clamping - properly preserves path structure when clamping escaped symlinks (fixed strict-path CI failures)
  - **0.4.2-0.4.5**: Documentation improvements, performance optimizations, enhanced Windows path handling, `dunce` feature for simplified Windows paths
  - See [soft-canonicalize CHANGELOG](https://github.com/DK26/soft-canonicalize-rs/blob/main/CHANGELOG.md) for complete details

- **Removed Windows 8.3 short name rejection**: Previous approach was too aggressive and broke legitimate paths on GitHub runners
  - Canonicalization already expands short names for existing paths (security via soft-canonicalize)
  - Non-existent paths are handled by subsequent I/O operations failing naturally

### Documentation
- **Major documentation reorganization** (closes #24, #21, #20):
  - **README.md**: Lead with StrictPath (detect & reject), introduce VirtualPath as opt-in containment feature
  - **Added "Choosing Between Types" decision guide**: 
    - **Use StrictPath (default)**: Archive extraction, file uploads, config loading, any security boundary where escapes are attacks
    - **Use VirtualPath (opt-in)**: Malware sandboxes, multi-tenant isolation, container-like plugins, security research
  - **Key distinction**: Error on escape (StrictPath) vs. silently contain (VirtualPath)
- **Enhanced LLM documentation** (closes #23, #17):
  - Added comparison with `path_absolutize::absolutize_virtually` to `LLM_API_REFERENCE.md`
  - Clarified difference between strict-path (high-level security) and soft-canonicalize (low-level foundation)
  - Updated terminology throughout: "path bounded at" instead of "path rooted at" for StrictPath
- **Fixed smelly doc examples** (closes #14):
  - Fixed `.change_marker()` example to use tuple markers `(UserFiles, ReadOnly/ReadWrite)` and demonstrate proper authorization flow
  - Removed meaningless `assert_eq!` that didn't prove marker transformation
  - Fixed `.expect()` message to reflect actual error condition
  - Audited and fixed `Ok(())` usage in doctests (properly hidden with `#`)
  - Fixed "root" vs "boundary" terminology confusion in doc comments
- **New comprehensive user guide**: Added `LLM_USER.md` with Context7-compatible documentation
- **mdBook improvements** (closes #7, #8, #9, #10):
  - Split `best_practices.md` into 5 focused chapters: `why_naive_approaches_fail.md`, `real_world_patterns.md`, `common_operations.md`, `policy_and_reuse.md`, `authorization_architecture.md`
  - Added comparison tables (strict-path vs soft-canonicalize, vs path_absolutize) to `design_decisions.md`
  - Added explicit CVE coverage with 4 detailed examples in `security_methodology.md`
  - Moved mdBook to separate `docs` branch with `.docs/` worktree for independent documentation maintenance
  - **lib.rs docs streamlined**: Reduced from 928 to 243 lines (74% reduction), focused on gateway role with heavy linking to comprehensive mdBook guide
- **Enhanced virtual path documentation**:
  - Added detailed clamping behavior examples for `VirtualRoot::virtual_join()`, `VirtualPath::virtual_join()`, `VirtualPath::virtual_symlink()`, `VirtualPath::virtual_hard_link()`, `VirtualPath::virtual_rename()`, `VirtualPath::virtual_copy()`
  - Added "Critical distinction - Symlink behavior" section comparing StrictPath vs VirtualPath symlink semantics
  - Updated API comparison table with symlink target behavior and attack scenarios

### Added
- **README.md example validation** (closes #6):
  - All README.md code examples now have corresponding tests in `strict-path/src/tests/readme_examples.rs`
  - Tests ensure README examples compile, run, and produce expected behavior
  - Prevents documentation rot by validating examples in CI
- **Enhanced CI validation**:
  - Added no-features clippy validation (`cargo clippy --no-default-features`) to ensure library compiles cleanly without any features
  - Library now validates with no features, default features, and all features
  - Proper `#[cfg(feature = "virtual-path")]` guards throughout codebase
- **Issue management templates** (closes #12):
  - Added LLM-friendly issue template in `CONTRIBUTING.md`
  - Clear, concise format for bug reports, feature requests, and documentation issues

### Tests
- **Comprehensive symlink clamping test suite** (742 new lines):
  - `virtual_symlink_clamps_traversal_attempts` - Verifies `../../../` paths are clamped to root
  - `virtual_symlink_archive_extraction_scenario` - Real-world archive extraction with absolute symlinks
  - `following_symlink_pointing_outside_vroot` - Unix symlink escape prevention
  - `following_junction_pointing_outside_vroot` - Windows junction escape prevention (2 tests)
  - `virtual_join_clamps_absolute_paths_before_symlink_creation` - Security gateway validation
  - Plus 10+ additional tests covering hard links, copy, rename, and edge cases
- **Updated existing tests**: `test_junction_escape_is_rejected` now expects clamping for `VirtualPath` while maintaining rejection for `StrictPath`
- **Added GitHub runner simulation tests**: Validate 8.3 short name behavior without needing remote CI

### Performance
- **CI optimization** (closes #19):
  - Replaced feature matrix testing (8-10 separate clippy runs) with single combined test
  - Faster compilation, faster failure detection, simpler logs
  - CI builds ~40-60% faster
  - Updated: `ci-local.ps1`, `ci-local.sh`, `ci-check-demos.ps1`, `ci-check-demos.sh`, `.github/workflows/ci.yml`

## [0.1.0-beta.2] - 2025-10-03

### Added
- **New file handle methods**: `create_file()` and `open_file()` for both `StrictPath` and `VirtualPath`
  - `create_file()` creates or truncates files and returns writable `std::fs::File` handles
  - `open_file()` opens files in read-only mode
  - Both methods maintain boundary security guarantees while providing direct streaming access
- **Marker transformation support**: New `change_marker<NewMarker>()` methods for `PathBoundary`, `VirtualRoot`, `StrictPath`, and `VirtualPath`
  - Enables clean propagation of authorization markers after authentication
  - Consumes the original value to make marker changes explicit during code review
  - Optimized with `Arc::try_unwrap()` to minimize allocations when possible
- **Enhanced cross-marker equality**: `PathBoundary<M1>` and `VirtualRoot<M1>` can now be compared with different marker types
  - Enables flexible comparisons while preserving type safety in function signatures
- **New conversion methods**: `PathBoundary::into_strictpath()` and `VirtualRoot::into_virtualpath()`
  - Consume the boundary/root and return a `StrictPath`/`VirtualPath` anchored at the directory
  - Both return `Result` for proper error handling of canonicalization failures or race conditions
  - Replaces the pattern of calling `strict_join("")` or `virtual_join("")` with clearer intent
- **New example**: `user_virtual_root.rs` demonstrates per-user isolation patterns with `VirtualRoot<UserSpace>`

### Changed
- **BREAKING**: `StrictPath::try_into_boundary()` now returns `Result<PathBoundary<Marker>>` instead of `PathBoundary<Marker>`
  - The directory must exist and be a directory, or the method returns `InvalidRestriction` error  
  - Use `try_into_boundary_create()` to create the directory if missing
- **BREAKING**: `StrictPath::try_into_boundary_create()` now returns `Result<PathBoundary<Marker>>` instead of `PathBoundary<Marker>`
  - Proper error handling replaces previous best-effort directory creation
- **BREAKING**: `VirtualPath::try_into_root()` now returns `Result<VirtualRoot<Marker>>` instead of `VirtualRoot<Marker>`
  - Consistent error handling for directory validation
- **BREAKING**: `VirtualPath::try_into_root_create()` now returns `Result<VirtualRoot<Marker>>` instead of `VirtualRoot<Marker>`
  - Replaces best-effort creation with proper error propagation
- **Package description**: Updated to "Stop path attacks before they happen. This crate makes sure file paths can't escape where you want them to go"
  - More concise and user-focused than previous technical description

### Documentation
- **Enhanced interop guidance**: Stronger emphasis on using `.interop_path()` only for unavoidable third-party API adaptation
  - Updated method documentation to clarify "unavoidable third-party" use cases
  - Added clear anti-patterns and preferred alternatives
- **Improved doctests**: Many examples now compile and run to ensure accuracy
  - Previous illustrative examples were marked as `ignore`, now they demonstrate real working code
  - Added proper error handling and cleanup in documentation examples
- **Better API examples**: Enhanced examples showing file handle usage, marker transformation, and conversion patterns

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
