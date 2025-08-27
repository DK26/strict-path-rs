//! # jailed-path
//!
//! Prevent directory traversal with a type-safe, virtualized filesystem API.
//!
//! This crate provides two complementary sets of types for handling filesystem paths securely:
//!
//! 1.  User-Facing (`VirtualRoot` and `VirtualPath`): Designed for all user-facing interactions.
//!     Paths are displayed relative to a virtual root (e.g., `/downloads/file.txt`), preventing
//!     any leakage of the underlying filesystem structure. Use these for UI, logging, and user input.
//!
//! 2.  System-Facing (`Jail` and `JailedPath`): Designed for direct filesystem operations.
//!     Paths are real, canonicalized paths (e.g., `/var/app/storage/downloads/file.txt`). Use
//!     these for file I/O or when interfacing with other system APIs.
//!
//! The core security guarantee is that all paths are mathematically proven to stay within their
//! designated boundaries, neutralizing traversal attacks like `../../../etc/passwd`.
//!
//! ## About This Crate: JailedPath and VirtualPath
//!
//! `JailedPath` is a system‑facing filesystem path type, mathematically proven (via
//! canonicalization, boundary checks, and type‑state) to remain inside a configured jail directory.
//! `VirtualPath` wraps a `JailedPath` and therefore guarantees everything a `JailedPath` guarantees —
//! plus a rooted, forward‑slashed virtual view (treating the jail as "/") and safe virtual
//! operations (joins/parents/file‑name/ext) that preserve clamping.
//!
//! Construct them with `Jail::try_new(_create)` and `VirtualRoot::try_new(_create)`. Ingest
//! untrusted paths as `VirtualPath` for UI/UX and safe joins; convert to `JailedPath` only where you
//! perform actual I/O.
//!
//! Rule of thumb
//! - Use `VirtualRoot::try_path_virtual(..)` to accept untrusted input and get a `VirtualPath` for
//!   UI and safe path manipulation.
//! - Convert to `JailedPath` via `vp.unvirtual()` only where you perform I/O or pass to APIs
//!   requiring a system path.
//! - For `AsRef<Path>` interop, pass `jailed_path.systempath_as_os_str()` (no allocation).
//!
//! ## Quickstart: User-Facing Virtual Paths
//!
//! ```rust
//! use jailed_path::VirtualRoot;
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a virtual root, which corresponds to a real directory.
//! fs::create_dir_all("user_data")?;
//! let vroot = VirtualRoot::<()>::try_new("user_data")?;
//!
//! // 2. Create a virtual path from user input. Traversal attacks are neutralized.
//! let virtual_path = vroot.try_path_virtual("documents/report.pdf")?;
//! let attack_path = vroot.try_path_virtual("../../../etc/hosts")?;
//!
//! // 3. Displaying the path is always safe and shows the virtual view.
//! assert_eq!(virtual_path.to_string(), "/documents/report.pdf");
//! assert_eq!(attack_path.to_string(), "/etc/hosts"); // Clamped, not escaped
//!
//! // 4. For file I/O, convert to a system-facing JailedPath.
//! let jailed_path = virtual_path.unvirtual();
//! jailed_path.create_dir_all()?; // create the directory if needed
//!
//! assert!(jailed_path.exists());
//!
//! fs::remove_dir_all("user_data")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! - Separation of Concerns: `VirtualPath` for UX, `JailedPath` for I/O.
//! - Mathematical Guarantees: Rust's type system proves security at compile time.
//! - Zero Attack Surface: No `Deref` to `Path`, validation cannot be bypassed.
//! - Built-in Safe I/O: `JailedPath` provides safe file operations.
//! - Multi-Jail Safety: Marker types prevent cross-jail contamination at compile time.
//! - Type-History Design: Internal pattern ensures paths carry proof of validation stages.
//! - Cross-Platform: Works on Windows, macOS, and Linux.
//!
//! ## When to Use Which Type
//!
//! | Use Case                               | Correct Type  | Example                                      |
//! | -------------------------------------- | ------------- | -------------------------------------------- |
//! | Displaying a path in a UI or log       | `VirtualPath` | `println!("File: {}", virtual_path);`        |
//! | Manipulating a path based on user view | `VirtualPath` | `virtual_path.virtualpath_parent()`          |
//! | Reading or writing a file              | `JailedPath`  | `jailed_path.read_bytes()?`                  |
//! | Integrating with an external API       | `JailedPath`  | `external_api(jailed_path.systempath_as_os_str())` |
//!
//! ## Multi-Jail Type Safety
//!
//! Use marker types to prevent paths from different jails from being used interchangeably.
//!
//! ```rust
//! use jailed_path::{Jail, JailedPath, VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! struct StaticAssets;
//! struct UserUploads;
//!
//! fn serve_asset(asset: &JailedPath<StaticAssets>) -> Result<Vec<u8>, std::io::Error> {
//!     asset.read_bytes()
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # fs::create_dir_all("assets")?; fs::create_dir_all("uploads")?;
//! # fs::write("assets/style.css", "body{}")?;
//! let assets_vroot: VirtualRoot<StaticAssets> = VirtualRoot::try_new("assets")?;
//! let uploads_vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new("uploads")?;
//!
//! let css_file: VirtualPath<StaticAssets> = assets_vroot.try_path_virtual("style.css")?;
//! let user_file: VirtualPath<UserUploads> = uploads_vroot.try_path_virtual("avatar.jpg")?;
//!
//! serve_asset(&css_file.unvirtual())?; // ✅ Correct type
//! // serve_asset(&user_file.unvirtual())?; // ❌ Compile error: wrong marker type!
//! # fs::remove_dir_all("assets").ok(); fs::remove_dir_all("uploads").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Guarantees
//!
//! All `..` components are clamped, symbolic links are resolved, and the final real path is
//! validated against the jail boundary. Path traversal attacks are prevented by construction.
//!
//! ### Windows-only hardening: DOS 8.3 short names
//!
//! On Windows, paths like `PROGRA~1` are DOS 8.3 short-name aliases. To prevent ambiguity,
//! this crate rejects paths containing non-existent components that look like 8.3 short names
//! with a dedicated error, `JailedPathError::WindowsShortName`.
//!
//! ## Installation
//!
//! Add `jailed-path` to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! jailed-path = "0.1.0" # Replace with the latest version
//! ```
//!
//! ## Why We Don’t Expose `Path`/`PathBuf`
//!
//! Exposing raw `Path` or `PathBuf` encourages use of std path methods (`join`, `parent`, …)
//! that bypass this crate’s virtual-root clamping and boundary checks.
//!
//! - `join` danger: `std::path::Path::join` has no notion of a virtual root. Joining an
//!   absolute path, or a path with enough `..` components, can override or conceptually
//!   escape the intended root. That undermines the guarantees of `JailedPath`/`VirtualPath`.
//!   Use `JailedPath::join_systempath(...)` or `VirtualPath::join_virtualpath(...)` instead.
//! - `parent` ambiguity: `Path::parent` ignores jail/virtual semantics; our
//!   `systempath_parent()` and `virtualpath_parent()` preserve the correct behavior.
//! - Predictability: Users unfamiliar with the crate may accidentally mix virtual and
//!   system semantics if they are handed a raw `Path`.
//!
//! What to use instead:
//! - Passing to external APIs: Prefer `jailed_path.systempath_as_os_str()` which borrows the
//!   inner system path as `&OsStr` (implements `AsRef<Path>`). This is the cheapest and most
//!   correct way to interoperate without exposing risky methods.
//! - Ownership escape hatches: Use `.unvirtual()` (to get a `JailedPath`) and `.unjail()`
//!   (to get an owned `PathBuf`) explicitly and sparingly. These are deliberate, opt-in
//!   operations to make potential risk obvious in code review.
//!
//! Why `&OsStr` works well:
//! - `OsStr`/`OsString` are OS-native string types; you don’t lose platform-specific data.
//! - `Path` is just a thin wrapper over `OsStr`. Borrowing `&OsStr` is the straightest,
//!   allocation-free, and semantically correct way to pass a path to `AsRef<Path>` APIs.
//!
//! ## Common Pitfalls (and How to Avoid Them)
//!
//! - Do not leak raw `Path`/`PathBuf` from `JailedPath` or `VirtualPath`.
//!   Use `systempath_as_os_str()` when an external API needs `AsRef<Path>`.
//! - Do not call `Path::join`/`Path::parent` on leaked paths — they ignore jail/virtual semantics.
//!   Use `join_systempath`/`systempath_parent` and `join_virtualpath`/`virtualpath_parent`.
//! - Avoid `.unvirtual()`/`.unjail()` unless you explicitly need ownership for interop.
//!   Prefer borrowing with `systempath_as_os_str()`.
//! - Virtual strings are rooted. For UI/logging, use `format!("{}", vp)` or `vp.virtualpath_to_string()`.
//!   No borrowed `&str` accessors are exposed for virtual paths.
//! - Creating a jail: `Jail::try_new(..)` requires the directory to exist.
//!   Use `Jail::try_new_create(..)` if it may be missing.
//! - Windows: 8.3 short names (e.g., `PROGRA~1`) are rejected to avoid ambiguous resolution.
//! - Markers matter. Functions should take `JailedPath<MyMarker>` for their domain to prevent cross-jail mixing.
//!
//! ## Escape Hatches and Best Practices
//!
//! Prefer passing references to the inner system path instead of taking ownership:
//! - If an external API accepts `AsRef<Path>`, pass `jailed_path.systempath_as_os_str()`.
//! - Avoid `.unjail()` unless you explicitly need an owned `PathBuf`.
//!
//! ```rust
//! # use jailed_path::Jail;
//! # fn external_api<P: AsRef<std::path::Path>>(_p: P) {}
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let jail = Jail::try_new_create("./safe")?;
//! let jp = jail.try_path("file.txt")?;
//!
//! // Preferred: borrow as &OsStr (implements AsRef<Path>)
//! external_api(jp.systempath_as_os_str());
//!
//! // Escape hatches (use sparingly):
//! let owned: std::path::PathBuf = jp.clone().unjail();
//! let v: jailed_path::VirtualPath = jp.clone().virtualize();
//! let back: jailed_path::JailedPath = v.clone().unvirtual();
//! let owned_again: std::path::PathBuf = v.unvirtual().unjail();
//! # // Cleanup created jail directory for doctest hygiene
//! # std::fs::remove_dir_all("./safe").ok();
//! # Ok(()) }
//! ```
//!
//! ## API Reference (Concise)
//!
//! For a minimal, copy‑pastable guide to the API (optimized for both humans and LLMs),
//! see the repository reference:
//! <https://github.com/DK26/jailed-path-rs/blob/main/API_REFERENCE.md>
//!
//! This link is provided here so readers coming from docs.rs can easily discover it.
#![forbid(unsafe_code)]

pub mod error;
pub mod path;
pub mod validator;

// Public exports
pub use error::JailedPathError;
pub use path::{jailed_path::JailedPath, virtual_path::VirtualPath};
pub use validator::jail::Jail;
pub use validator::virtual_root::VirtualRoot;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
