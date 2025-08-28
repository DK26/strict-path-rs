//! # jailed-path
//!
//! Prevent directory traversal with a type-safe, virtualized filesystem API.
//!
//! This crate provides two closely-related path types that operate at different “views”:
//!
//! - `JailedPath`: a validated, system-facing path that proves the underlying filesystem path is
//!   inside a predefined boundary (the “jail”). If a `JailedPath` exists, it is the proof.
//! - `VirtualPath`: conceptually extends `JailedPath` with a virtual-root view (treating the jail
//!   as "/"), restricting irrelevant std path methods, and adding jail-aware virtual operations
//!   (join/parent/with_file_name/with_extension). It preserves all guarantees of `JailedPath`.
//!
//! Both types support I/O. Choose `VirtualPath` when you want user-facing, rooted display and
//! virtual operations; choose `JailedPath` when you need an explicitly system-facing value or logs
//! that show the real on-disk path. You can convert between them explicitly.
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
//! operations (joins/parents/file‑name/ext) that preserve clamping and hide the real system path.
//! With `VirtualPath`, users are free to specify any path they like while you still guarantee it
//! cannot leak outside the underlying jail.
//!
//! Construct them with `Jail::try_new(_create)` and `VirtualRoot::try_new(_create)`. Ingest
//! untrusted paths as `VirtualPath` for UI/UX and safe joins; perform I/O from either type.
//!
//! Guidance
//! - Accept untrusted input via `VirtualRoot::try_virtual_path(..)` to obtain a `VirtualPath`.
//! - Perform I/O directly on `VirtualPath` or on `JailedPath`. Unvirtualize only when you need a
//!   `JailedPath` explicitly (e.g., for a signature that requires it or for system-facing logs).
//! - For `AsRef<Path>` interop, pass `systempath_as_os_str()` from either type (no allocation).
//!
//! Switching views (upgrade/downgrade)
//! - Prefer staying in one dimension for a given flow:
//!   - Virtual view: `VirtualPath` + `virtualpath_*` ops and direct I/O.
//!   - System view: `JailedPath` + `systempath_*` ops and direct I/O.
//! - Edge cases: upgrade with `JailedPath::virtualize()` or downgrade with `VirtualPath::unvirtual()`
//!   to access the other view’s operations explicitly.
//!
//! Markers and type inference
//! - All public types are generic over a `Marker` with a default of `()`.
//! - Inference usually works once a value is bound:
//!   - `let vroot: VirtualRoot = VirtualRoot::try_new("root")?;`
//!   - `let vp = vroot.try_virtual_path("a.txt")?; // inferred as VirtualPath<()>`
//! - When inference needs help, annotate the type or use an empty turbofish:
//!   - `let vroot: VirtualRoot<()> = VirtualRoot::try_new("root")?;`
//!   - `let vroot = VirtualRoot::<()>::try_new("root")?;`
//! - With custom markers, annotate as needed:
//!   - `struct UserFiles; let vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;`

//! ### Examples: Encode Guarantees in Signatures
//!
//! ```rust
//! # use jailed_path::{VirtualRoot, VirtualPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Cloud storage per‑user jail
//! let user_id = 42u32;
//! let root = format!("./cloud_user_{user_id}");
//! let vroot: VirtualRoot = VirtualRoot::try_new_create(&root)?;
//!
//! // Accept untrusted input, then pass VirtualPath by reference to functions
//! let requested = "projects/2025/report.pdf";
//! let vp: VirtualPath = vroot.try_virtual_path(requested)?;  // Stays inside ./cloud_user_42
//! // Ensure parent directory exists before writing
//! if let Some(parent) = vp.virtualpath_parent()? { parent.create_dir_all()?; }
//!
//! fn save_doc(p: &VirtualPath) -> std::io::Result<()> { p.write_bytes(b"user file content") }
//! save_doc(&vp)?; // Compiler enforces correct usage via the type
//! println!("virtual: {}", vp);
//!
//! # // Cleanup
//! # std::fs::remove_dir_all(&root).ok();
//! # Ok(()) }
//! ```
//!
//! ```rust
//! # use jailed_path::{VirtualRoot, VirtualPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Web/E‑mail templates resolved in a user‑scoped virtual root
//! # let user_id = 7u32;
//! let tpl_root = format!("./tpl_space_{user_id}");
//! let templates: VirtualRoot = VirtualRoot::try_new_create(&tpl_root)?;
//! let tpl: VirtualPath = templates.try_virtual_path("emails/welcome.html")?;
//! fn render(p: &VirtualPath) -> std::io::Result<String> { p.read_to_string() }
//! let _ = render(&tpl);
//!
//! # std::fs::remove_dir_all(&tpl_root).ok();
//! # Ok(()) }
//! ```
//!
//! ## Quickstart: User-Facing Virtual Paths (with signatures)
//!
//! ```rust
//! use jailed_path::{VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a virtual root, which corresponds to a real directory.
//! fs::create_dir_all("user_data")?;
//! let vroot = VirtualRoot::<()>::try_new("user_data")?;
//!
//! // 2. Create a virtual path from user input. Traversal attacks are neutralized.
//! let virtual_path: VirtualPath = vroot.try_virtual_path("documents/report.pdf")?;
//! let attack_path: VirtualPath = vroot.try_virtual_path("../../../etc/hosts")?;
//!
//! // 3. Displaying the path is always safe and shows the virtual view.
//! assert_eq!(virtual_path.to_string(), "/documents/report.pdf");
//! assert_eq!(attack_path.to_string(), "/etc/hosts"); // Clamped, not escaped
//!
//! // 4. Prefer signatures requiring `VirtualPath` for operations.
//! fn ensure_dir(p: &VirtualPath) -> std::io::Result<()> { p.create_dir_all() }
//! ensure_dir(&virtual_path)?;
//! assert!(virtual_path.exists());
//!
//! fs::remove_dir_all("user_data")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! - Two Views: `VirtualPath` extends `JailedPath` with a virtual-root UX; both support I/O.
//! - Mathematical Guarantees: Rust's type system proves security at compile time.
//! - Zero Attack Surface: No `Deref` to `Path`, validation cannot be bypassed.
//! - Built-in Safe I/O: `JailedPath` provides safe file operations.
//! - Multi-Jail Safety: Marker types prevent cross-jail contamination at compile time.
//! - Type-History Design: Internal pattern ensures paths carry proof of validation stages.
//! - Cross-Platform: Works on Windows, macOS, and Linux.
//!
//! Display/Debug semantics
//! - `Display` for `VirtualPath` shows a rooted virtual path (e.g., "/a/b.txt") for user-facing output.
//! - `Debug` for `VirtualPath` is developer-facing and verbose (derived): it includes the inner
//!   `JailedPath` (system path and jail root) and the virtual view for diagnostics.
//!
//! ## When to Use Which Type
//!
//! | Use Case                               | Type                       | Example                                                     |
//! | -------------------------------------- | -------------------------- | ----------------------------------------------------------- |
//! | Displaying a path in a UI or log       | `VirtualPath`              | `println!("File: {}", virtual_path);`                       |
//! | Manipulating a path based on user view | `VirtualPath`              | `virtual_path.virtualpath_parent()`                         |
//! | Reading or writing a file              | `VirtualPath` or `JailedPath` | `virtual_path.read_bytes()?` or `jailed_path.read_bytes()?` |
//! | Integrating with an external API       | Either (borrow `&OsStr`)   | `external_api(virtual_path.systempath_as_os_str())`         |
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
//! let css_file: VirtualPath<StaticAssets> = assets_vroot.try_virtual_path("style.css")?;
//! let user_file: VirtualPath<UserUploads> = uploads_vroot.try_virtual_path("avatar.jpg")?;
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
//! ## Why We Don’t Expose `Path`/`PathBuf`
//!
//! Exposing raw `Path` or `PathBuf` encourages use of std path methods (`join`, `parent`, …)
//! that bypass this crate’s virtual-root clamping and boundary checks.
//!
//! - `join` danger: `std::path::Path::join` has no notion of a virtual root. Joining an
//!   absolute path, or a path with enough `..` components, can override or conceptually
//!   escape the intended root. That undermines the guarantees of `JailedPath`/`VirtualPath`.
//!   Use `JailedPath::systempath_join(...)` or `VirtualPath::virtualpath_join(...)` instead.
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
//! Explicit method names (rationale)
//! - Operation names encode their dimension so intent is obvious:
//!   - `p.join(..)` (std) — unsafe on untrusted input; can escape the jail.
//!   - `jp.systempath_join(..)` — safe, validated system-path join.
//!   - `vp.virtualpath_join(..)` — safe, clamped virtual-path join.
//! - This naming applies broadly: `*_parent`, `*_with_file_name`, `*_with_extension`,
//!   `*_starts_with`, `*_ends_with`, etc.
//! - This makes API abuse easy to spot even when type declarations aren’t visible.
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
//!   Use `systempath_join`/`systempath_parent` and `virtualpath_join`/`virtualpath_parent`.
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
#[cfg(feature = "serde")]
pub mod serde_ext {
    //! Serde helpers and notes.
    //!
    //! Built‑in `Serialize` (feature `serde`):
    //! - `JailedPath` → system path string
    //! - `VirtualPath` → virtual root string (e.g., "/a/b.txt")
    //!
    //! Deserialization requires context (a `Jail` or `VirtualRoot`). Use the context helpers
    //! below to deserialize with context, or deserialize to `String` and validate explicitly.
    //!
    //! Example: Deserialize a single `JailedPath` with context
    //! ```rust
    //! use jailed_path::{Jail, JailedPath};
    //! use jailed_path::serde_ext::WithJail;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let jail: Jail = Jail::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let jp: JailedPath = WithJail(&jail).deserialize(&mut de)?;
    //! // OS-agnostic assertion: file name should be "b.txt"
    //! assert_eq!(jp.systempath_file_name().unwrap().to_string_lossy(), "b.txt");
    //! # Ok(()) }
    //! ```
    //!
    //! Example: Deserialize a single `VirtualPath` with context
    //! ```rust
    //! use jailed_path::{VirtualPath, VirtualRoot};
    //! use jailed_path::serde_ext::WithVirtualRoot;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let vroot: VirtualRoot = VirtualRoot::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let vp: VirtualPath = WithVirtualRoot(&vroot).deserialize(&mut de)?;
    //! assert_eq!(vp.virtualpath_to_string(), "/a/b.txt");
    //! # Ok(()) }
    //! ```

    use crate::{
        path::jailed_path::JailedPath, path::virtual_path::VirtualPath, validator::jail::Jail,
        validator::virtual_root::VirtualRoot,
    };
    use serde::de::DeserializeSeed;
    use serde::Deserialize;

    /// Deserialize a `JailedPath` with jail context.
    pub struct WithJail<'a, Marker>(pub &'a Jail<Marker>);

    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithJail<'a, Marker> {
        type Value = JailedPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.try_path(s).map_err(serde::de::Error::custom)
        }
    }

    /// Deserialize a `VirtualPath` with virtual root context.
    pub struct WithVirtualRoot<'a, Marker>(pub &'a VirtualRoot<Marker>);

    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithVirtualRoot<'a, Marker> {
        type Value = VirtualPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.try_virtual_path(s).map_err(serde::de::Error::custom)
        }
    }
}

// Public exports
pub use error::JailedPathError;
pub use path::{jailed_path::JailedPath, virtual_path::VirtualPath};
pub use validator::jail::Jail;
pub use validator::virtual_root::VirtualRoot;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
