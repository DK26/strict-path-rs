//! # strict-path
//!
//! **Handle paths from external or unknown sources securely.** Uses Rust's type system to
//! mathematically prove paths stay within defined boundaries—no escapes in any shape or form,
//! symlinks included. API is minimal, restrictive, and explicit to prevent human and LLM API misuse.
//!
//! This crate performs full normalization/canonicalization and boundary enforcement with:
//! - Safe symlink/junction handling (including cycle detection)
//! - Windows-specific quirks (8.3 short names, UNC and verbatim prefixes, ADS)
//! - Robust Unicode normalization and mixed-separator handling across platforms
//! - Canonicalized path proofs encoded in the type system
//!
//! If a `StrictPath<Marker>` value exists, it is already proven to be inside its
//! designated boundary by construction — not by best-effort string checks.
//!
//! 📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Reference](https://docs.rs/strict-path)**
//!
//! ## Quick Start
//!
//! ```rust
//! # use strict_path::StrictPath;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let temp = tempfile::tempdir()?;
//! # let request = std::collections::HashMap::from([("file", "report.pdf")]);
//! # std::fs::write(temp.path().join("report.pdf"), b"file contents")?;
//! // GET /download?file=report.pdf
//! let user_input = request.get("file").unwrap(); // Untrusted: "report.pdf" or "../../etc/passwd"
//! let untrusted_user_input = user_input.to_string();
//!
//! let file: StrictPath = StrictPath::with_boundary(temp.path())?
//!     .strict_join(&untrusted_user_input)?; // Validates untrusted input - attack blocked!
//!
//! let contents = file.read()?; // Built-in safe I/O
//! # Ok(()) }
//! ```
//!
//! ## Core Types
//!
//! - **`StrictPath`** — The fundamental security primitive. Every `StrictPath` is mathematically proven
//!   to be within its designated boundary via canonicalization and type-level guarantees.
//! - **`PathBoundary`** — Creates and validates `StrictPath` instances from external input.
//! - **`VirtualPath`** (feature `virtual-path`) — Extends `StrictPath` with user-friendly virtual root
//!   semantics (treating the boundary as "/").
//! - **`VirtualRoot`** (feature `virtual-path`) — Creates `VirtualPath` instances with containment semantics.
//!
//! **[→ Read the security methodology](https://dk26.github.io/strict-path-rs/security_methodology.html)**
//!
//! ## Which Type Should I Use?
//!
//! **`Path`/`PathBuf` (std)** — When the path comes from a safe source within your control, not external input.
//!
//! **`StrictPath`** — When you want to restrict paths to a specific boundary and error if they escape.
//! - **Use for:** Archive extraction, config loading, shared system resources, file uploads to shared storage (admin panels, CMS)
//! - **Behavior:** Returns `Err(PathEscapesBoundary)` on escape attempts (detect attacks)
//! - **Coverage:** 90% of use cases
//!
//! **`VirtualPath`** (feature `virtual-path`) — When you want to provide path freedom under isolation.
//! - **Use for:** Multi-tenant file uploads (SaaS per-user storage), malware sandboxes, security research, per-user filesystem views
//! - **Behavior:** Silently clamps/redirects escapes within virtual boundary (contain behavior)
//! - **Coverage:** 10% of use cases
//!
//! **[→ Read the detailed comparison](https://dk26.github.io/strict-path-rs/best_practices.html)**
//!
//! ## Type-System Guarantees
//!
//! Use marker types to encode policy directly in your APIs:
//!
//! ```rust
//! # use strict_path::{PathBoundary, StrictPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! struct PublicAssets;
//! struct UserUploads;
//!
//! # std::fs::create_dir_all("./assets")?;
//! # std::fs::create_dir_all("./uploads")?;
//! let assets = PathBoundary::<PublicAssets>::try_new("./assets")?;
//! let uploads = PathBoundary::<UserUploads>::try_new("./uploads")?;
//!
//! // User input from request parameters, form data, database, etc.
//! let requested_css = "style.css";      // From request: /static/style.css
//! let uploaded_avatar = "avatar.jpg";   // From form: <input type="file">
//!
//! let css: StrictPath<PublicAssets> = assets.strict_join(requested_css)?;
//! let avatar: StrictPath<UserUploads> = uploads.strict_join(uploaded_avatar)?;
//!
//! fn serve_public_asset(file: &StrictPath<PublicAssets>) { /* ... */ }
//!
//! serve_public_asset(&css);       // ✅ OK
//! // serve_public_asset(&avatar); // ❌ Compile error (wrong marker)
//! # std::fs::remove_dir_all("./assets").ok();
//! # std::fs::remove_dir_all("./uploads").ok();
//! # Ok(()) }
//! ```
//!
//! ## Security Foundation
//!
//! Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) (with
//! [`proc-canonicalize`](https://crates.io/crates/proc-canonicalize) for Linux container realpath support),
//! this crate protects against:
//! - **CVE-2025-8088** (NTFS ADS path traversal)
//! - **CVE-2022-21658** (TOCTOU attacks)
//! - **CVE-2019-9855, CVE-2020-12279** (Windows 8.3 short names)
//! - Path traversal, symlink attacks, Unicode normalization bypasses, race conditions
//!
//! > **Trade-off:** Security is prioritized above performance. This crate verifies paths on disk
//! > and follows symlinks for validation. If your use case doesn't involve symlinks and you need
//! > maximum performance, a lexical-only solution may be a better fit.
//!
//! **[→ Read attack surface analysis](https://dk26.github.io/strict-path-rs/security_methodology.html#attack-surface)**
//!
//! ## Interop with External APIs
//!
//! Use `.interop_path()` to pass paths to external APIs expecting `AsRef<Path>`:
//!
//! ```rust
//! # use strict_path::PathBoundary;
//! # fn external_api<P: AsRef<std::path::Path>>(_p: P) {}
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let restriction: PathBoundary = PathBoundary::try_new_create("./safe")?;
//!
//! // User input from CLI args, API request, config file, etc.
//! let user_input = "file.txt";
//! let jp = restriction.strict_join(user_input)?;
//!
//! // ✅ Preferred: borrow as &OsStr (implements AsRef<Path>)
//! external_api(jp.interop_path());
//!
//! // Escape hatches (use sparingly):
//! let owned: std::path::PathBuf = jp.clone().unstrict();
//! # let root_cleanup: strict_path::StrictPath = strict_path::StrictPath::with_boundary("./safe")?;
//! # root_cleanup.remove_dir_all().ok();
//! # Ok(()) }
//! ```
//!
//! **[→ Read the anti-patterns guide](https://dk26.github.io/strict-path-rs/anti_patterns.html)**
//!
//! ## Critical Anti-Patterns
//!
//! - **NEVER wrap `.interop_path()` in `Path::new()` or `PathBuf::from()`** — defeats all security
//! - **NEVER use std path operations on untrusted input** — use `.strict_join()`, not `Path::new().join()`
//! - **Use `.interop_path()` directly** for external APIs — it's already `AsRef<Path>`, no wrapping needed
//! - **Use proper display methods** — `.strictpath_display()` not `.interop_path().to_string_lossy()`
//!
//! Note: `.interop_path()` returns `&OsStr` (which is `AsRef<Path>`). After `.unstrict()` (explicit escape hatch), you own a `PathBuf` and can do whatever you need.
//!
//! **[→ See full anti-patterns list](https://dk26.github.io/strict-path-rs/anti_patterns.html)**
//!
//! ## Feature Flags
//!
//! - `virtual-path` — Enables `VirtualRoot`/`VirtualPath` for containment scenarios
//! - `junctions` (Windows) — Built-in NTFS junction helpers for strict/virtual paths
//!
//! ## Ecosystem Integration
//!
//! Use ecosystem crates directly with `PathBoundary` for maximum flexibility:
//! - `tempfile` — RAII temporary directories via `tempfile::tempdir()` → `PathBoundary::try_new()`
//! - `dirs` — OS standard directories via `dirs::config_dir()` → `PathBoundary::try_new_create()`
//! - `app-path` — Portable app paths via `AppPath::with("subdir")` → `PathBoundary::try_new_create()`
//! - `serde` — `PathBoundary`/`VirtualRoot` implement `FromStr` for automatic deserialization
//!
//! **[→ See Ecosystem Integration Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html)**
//!
//! **[→ Read the getting started guide](https://dk26.github.io/strict-path-rs/getting_started.html)**
//!
//! ## Additional Resources
//!
//! - **[LLM Context (Full)](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md)** —
//!   Concise, copy-pastable reference optimized for AI assistants
//! - **[Complete Guide](https://dk26.github.io/strict-path-rs/)** — Comprehensive documentation with examples
//! - **[API Reference](https://docs.rs/strict-path)** — Full type and method documentation
//! - **[Repository](https://github.com/DK26/strict-path-rs)** — Source code and issue tracker

#![forbid(unsafe_code)]

pub mod error;
pub mod path;
pub mod validator;

// Public exports
pub use error::StrictPathError;
pub use path::strict_path::StrictPath;
pub use validator::path_boundary::PathBoundary;

// Iterator exports
pub use path::strict_path::StrictOpenOptions;
pub use path::strict_path::StrictReadDir;
pub use validator::path_boundary::BoundaryReadDir;

#[cfg(feature = "virtual-path")]
pub use path::virtual_path::VirtualPath;

#[cfg(feature = "virtual-path")]
pub use path::virtual_path::VirtualReadDir;

#[cfg(feature = "virtual-path")]
pub use validator::virtual_root::VirtualRoot;

#[cfg(feature = "virtual-path")]
pub use validator::virtual_root::VirtualRootReadDir;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, StrictPathError>;

#[cfg(test)]
mod tests;
