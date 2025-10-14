//! # strict-path
//!
//! Strictly enforce path boundaries to prevent directory traversal attacks.
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
//! let temp = tempfile::tempdir()?;
//! let safe: StrictPath = StrictPath::with_boundary(temp.path())?
//!     .strict_join("users/alice.txt")?;  // Validated, stays inside boundary
//!
//! safe.create_parent_dir_all()?;
//! safe.write("hello")?;
//! safe.metadata()?;
//! safe.remove_file()?;
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
//! ## When to Use Which Type
//!
//! **StrictPath (default)** — Detect & reject path escapes (90% of use cases):
//! - Archive extraction, file uploads, config loading
//! - Returns `Err(PathEscapesBoundary)` on escape attempts
//!
//! **VirtualPath (opt-in)** — Contain & redirect path escapes (10% of use cases):
//! - Multi-tenant systems, malware sandboxes, security research
//! - Silently clamps escapes within the virtual boundary
//! - Requires `features = ["virtual-path"]` in `Cargo.toml`
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
//! let css: StrictPath<PublicAssets> = assets.strict_join("style.css")?;
//! let avatar: StrictPath<UserUploads> = uploads.strict_join("avatar.jpg")?;
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
//! Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize), this crate protects against:
//! - **CVE-2025-8088** (NTFS ADS path traversal)
//! - **CVE-2022-21658** (TOCTOU attacks)
//! - **CVE-2019-9855, CVE-2020-12279** (Windows 8.3 short names)
//! - Path traversal, symlink attacks, Unicode normalization bypasses, race conditions
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
//! let jp = restriction.strict_join("file.txt")?;
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
//! - **NEVER wrap our types in `Path::new()` or `PathBuf::from()`** — defeats all security
//! - **NEVER use std `Path::join`** on leaked paths — can escape boundaries
//! - **Use `.interop_path()` directly** for external APIs — no need for `.as_ref()`
//! - **Use proper display methods** — `.strictpath_display()` not `.interop_path().to_string_lossy()`
//!
//! **[→ See full anti-patterns list](https://dk26.github.io/strict-path-rs/anti_patterns.html)**
//!
//! ## Feature Flags
//!
//! - `virtual-path` — Enables `VirtualRoot`/`VirtualPath` for containment scenarios
//! - `serde` — Serialization support (deserialization requires context; see `serde_ext` module)
//! - `dirs` — OS directory discovery (`PathBoundary::from_home_dir()`, etc.)
//! - `tempfile` — RAII constructors for temporary boundaries
//! - `app-path` — Application-specific directory patterns with env var overrides
//!
//! **[→ Read the getting started guide](https://dk26.github.io/strict-path-rs/getting_started.html)**
//!
//! ## Additional Resources
//!
//! - **[LLM API Reference](https://github.com/DK26/strict-path-rs/blob/main/LLM_API_REFERENCE.md)** —
//!   Concise, copy-pastable reference optimized for AI assistants
//! - **[Complete Guide](https://dk26.github.io/strict-path-rs/)** — Comprehensive documentation with examples
//! - **[API Reference](https://docs.rs/strict-path)** — Full type and method documentation
//! - **[Repository](https://github.com/DK26/strict-path-rs)** — Source code and issue tracker

#![forbid(unsafe_code)]

pub mod error;
pub mod path;
pub mod validator;

#[cfg(feature = "serde")]
pub mod serde_ext {
    //! Serde helpers and notes.
    //!
    //! Built‑in `Serialize` (feature `serde`):
    //! - `StrictPath` → system path string
    //! - `VirtualPath` → virtual root string (e.g., "/a/b.txt")
    //!
    //! Deserialization requires context (a `PathBoundary` or `VirtualRoot`). Use the context helpers
    //! below to deserialize with context, or deserialize to `String` and validate explicitly.
    //!
    //! Example: Deserialize a single `StrictPath` with context
    //! ```rust
    //! use strict_path::{PathBoundary, StrictPath};
    //! use strict_path::serde_ext::WithBoundary;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let boundary: PathBoundary = PathBoundary::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let jp: StrictPath = WithBoundary(&boundary).deserialize(&mut de)?;
    //! // OS-agnostic assertion: file name should be "b.txt"
    //! assert_eq!(jp.strictpath_file_name().unwrap().to_string_lossy(), "b.txt");
    //! # Ok(()) }
    //! ```
    //!
    //! Example: Deserialize a single `VirtualPath` with context
    //! ```rust
    //! # #[cfg(feature = "virtual-path")] {
    //! use strict_path::{VirtualPath, VirtualRoot};
    //! use strict_path::serde_ext::WithVirtualRoot;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let vroot: VirtualRoot = VirtualRoot::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let vp: VirtualPath = WithVirtualRoot(&vroot).deserialize(&mut de)?;
    //! assert_eq!(vp.virtualpath_display().to_string(), "/a/b.txt");
    //! # Ok(()) }
    //! # }
    //! ```

    use crate::{path::strict_path::StrictPath, PathBoundary};
    #[cfg(feature = "virtual-path")]
    use crate::{path::virtual_path::VirtualPath, validator::virtual_root::VirtualRoot};
    use serde::de::DeserializeSeed;
    use serde::Deserialize;

    /// Deserialize a `StrictPath` with PathBoundary context.
    pub struct WithBoundary<'a, Marker>(pub &'a PathBoundary<Marker>);

    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithBoundary<'a, Marker> {
        type Value = StrictPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.strict_join(s).map_err(serde::de::Error::custom)
        }
    }

    /// Deserialize a `VirtualPath` with virtual root context.
    #[cfg(feature = "virtual-path")]
    pub struct WithVirtualRoot<'a, Marker>(pub &'a VirtualRoot<Marker>);

    #[cfg(feature = "virtual-path")]
    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithVirtualRoot<'a, Marker> {
        type Value = VirtualPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.virtual_join(s).map_err(serde::de::Error::custom)
        }
    }
}

// Public exports
pub use error::StrictPathError;
pub use path::strict_path::StrictPath;
pub use validator::path_boundary::PathBoundary;

#[cfg(feature = "virtual-path")]
pub use path::virtual_path::VirtualPath;

#[cfg(feature = "virtual-path")]
pub use validator::virtual_root::VirtualRoot;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, StrictPathError>;

#[cfg(test)]
mod tests;
