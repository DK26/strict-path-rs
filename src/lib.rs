//! # jailed-path
//!
//! **Prevent directory traversal with type-safe virtual path jails and safe symlinks**
//!
//! > *Putting your paths in jail by the Type-State Police Department*
//!
//! *because your LLM can't be trusted with security*
//!
//! ## Key Features: Security-First Design
//!
//! 🔒 **Security First**: API makes unsafe operations impossible, not just difficult  
//! 🏛️ **Mathematical Guarantees**: Rust's type system proves security at compile time  
//! 🛡️ **Zero Attack Surface**: No `Deref` to `Path`, no `AsRef<Path>`, validation cannot be bypassed  
//! 🎯 **Multi-Jail Safety**: Marker types prevent cross-jail contamination  
//! 📁 **Built-in Safe Operations**: Direct file operations on jailed paths without exposing raw filesystem paths  
//! 👁️ **Virtual Root Display**: Clean user-facing paths that never leak filesystem structure  
//! 📦 **Minimal Attack Surface**: Only one dependency - our auditable `soft-canonicalize` crate (handles non-existent paths unlike `std::fs::canonicalize`)  
//! 🌍 **Cross-Platform**: Works on Windows, macOS, and Linux  
//! 🤖 **LLM-Friendly**: Documentation designed for both humans and AI systems to understand and use correctly  
//!
//! ## The Problem: Every Path Is a Security Risk
//!
//! ```rust
//! // 🚨 DANGEROUS - This code looks innocent but has a critical vulnerability
//! fn serve_file_unsafe(path: &str) -> std::io::Result<Vec<u8>> {
//!     // This is just an example of what NOT to do
//!     std::fs::read(format!("./public/{path}"))  // ← Path traversal attack possible!
//! }
//!
//! // Attacker could send: "../../../etc/passwd"
//! // Server would try to serve: ./public/../../../etc/passwd → /etc/passwd 💀
//! // (This example doesn't actually run the dangerous code)
//! # let _ = serve_file_unsafe; // Prevent unused warning
//! ```
//!
//! ## The Solution: Mathematical Security Guarantees
//!
//! ```rust
//! use jailed_path::{try_jail, PathValidator, JailedPath};
//!
//! // ✅ SECURE - Attack impossible by mathematical design
//! fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
//!     std::fs::read(safe_path.real_path())  // ← JailedPath GUARANTEES safety
//! }
//!
//! # std::fs::create_dir_all("public")?; std::fs::write("public/index.html", b"<html></html>")?;
//! // ⚠️ CRITICAL: These are the ONLY two ways to create a JailedPath!
//! // Both are mathematically secure by design:
//!
//! // Option 1: One-shot validation with try_jail()
//! let safe_path: JailedPath = try_jail("public", "index.html")?;  // Works!
//!
//! // Option 2: Reusable validator with try_path()
//! let validator = PathValidator::with_jail("public")?;
//! let safe_path = validator.try_path("index.html")?;  // Works!
//!
//! let content = serve_file(&safe_path)?;
//! # std::fs::remove_dir_all("public").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! **The key insight**: `JailedPath` is the ONLY type that promises security. You literally cannot create one without going through `try_jail()` or `validator.try_path()` - there are no other constructors!
//!
//! ## Multi-Jail Type Safety: Preventing Mix-ups
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedPath};
//!
//! struct PublicAssets;
//! struct UserUploads;
//!
//! fn serve_asset(asset: &JailedPath<PublicAssets>) -> Result<String, std::io::Error> {
//!     std::fs::read_to_string(asset.real_path())
//! }
//!
//! # std::fs::create_dir_all("assets")?; std::fs::create_dir_all("uploads")?;
//! # std::fs::write("assets/style.css", "body{}")?;
//! let assets: PathValidator<PublicAssets> = PathValidator::with_jail("assets")?;
//! let uploads: PathValidator<UserUploads> = PathValidator::with_jail("uploads")?;
//!
//! let css_file: JailedPath<PublicAssets> = assets.try_path("style.css")?;
//! let user_file: JailedPath<UserUploads> = uploads.try_path("avatar.jpg")?;
//!
//! serve_asset(&css_file)?; // ✅ Correct type
//! // serve_asset(&user_file)?; // ❌ Compile error: wrong marker type!
//! # std::fs::remove_dir_all("assets").ok(); std::fs::remove_dir_all("uploads").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Built-in Safe File Operations
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedFileOps};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("safe_jail")?;
//! let validator = PathValidator::<()>::with_jail("safe_jail")?;
//! let file = validator.try_path("data.txt")?;
//!
//! // ✅ SAFE - All operations stay within jail automatically
//! file.write_string("secure content")?;
//! let content = file.read_to_string()?;
//! assert_eq!(content, "secure content");
//! # std::fs::remove_dir_all("safe_jail").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ## Complete Integration Example
//!
//! ```rust
//! # fn doctest() -> Result<(), Box<dyn std::error::Error>> {
//! use jailed_path::PathValidator;
//! use std::fs;
//!
//! // Setup: create a unique test directory and files
//! let test_dir = "public_doctest_example";
//! fs::create_dir_all(format!("{test_dir}/css"))?;
//! fs::write(format!("{test_dir}/index.html"), "<html></html>")?;
//! fs::write(format!("{test_dir}/css/style.css"), "body{}")?;
//! // The clamped file does not need to exist for the test, but we create it for completeness
//! fs::write(format!("{test_dir}/config.toml"), "[config]\nkey = 'value'")?;
//!
//! let validator: PathValidator = PathValidator::with_jail(test_dir)?;
//!
//! // ✅ Valid paths
//! let safe = validator.try_path("index.html")?;
//! let nested = validator.try_path("css/style.css")?;
//!
//! // ❌ Any `..` component or absolute path is clamped to jail root
//! let clamped1 = validator.try_path("../config.toml")?;
//! let clamped2 = validator.try_path("assets/../../../etc/passwd")?;
//! let clamped3 = validator.try_path("/etc/shadow")?;
//! assert!(clamped1.real_path().starts_with(validator.jail()));
//! assert!(clamped2.real_path().starts_with(validator.jail()));
//! assert!(clamped3.real_path().starts_with(validator.jail()));
//!
//! // Cleanup: remove the test directory
//! fs::remove_dir_all(test_dir).ok();
//! Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! - **Security First**: Security is prioritized above convenience and performance - the API makes unsafe operations impossible rather than just difficult
//! - **Mathematical Guarantees**: Rust's type system proves security properties at compile time  
//! - **Zero Attack Surface**: No `Deref` to `Path`, no `AsRef<Path>`, validation cannot be bypassed
//! - **Multi-Jail Safety**: Marker types prevent accidental cross-jail contamination
//! - **Built-in Safe Operations**: Direct file operations on jailed paths without exposing raw filesystem paths
//! - **Virtual Root Display**: Clean user-facing paths that never leak internal filesystem structure
//! - **Minimal Attack Surface**: Only one dependency - our auditable `soft-canonicalize` crate (handles non-existent paths unlike `std::fs::canonicalize`)
//! - **Cross-Platform**: Works on Windows, macOS, and Linux  
//! - **LLM-Friendly**: Documentation designed for both humans and AI systems to understand and use correctly
//!
//! ## API Design
//!
//! **⚠️ CRITICAL: These are the ONLY two ways to create a JailedPath!**
//!
//! - [`try_jail()`] - One-shot path validation, returns `Result<JailedPath, JailedPathError>`
//! - [`PathValidator::with_jail()`] - Create validator with jail boundary
//! - [`validator.try_path()`] - Validate a single path, returns `Result<JailedPath, JailedPathError>`
//! - [`JailedPath`] - Validated path type (can ONLY be created via `try_jail()` or `try_path()`)
//! - [`JailedPathError`] - Detailed error information for debugging
//!
//! ## Security Guarantees
//!
//! All `..` components are clamped before processing, symbolic links are resolved, and paths are
//! mathematically validated against the jail boundary. Path traversal attacks
//! are impossible to bypass.
//!
//! ## Usage
//!
//! First, add `jailed-path` to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! jailed-path = "0.0.4" # Replace with the latest version
//! ```
//!
//! ### Basic Validation
//!
//! The easiest way to use the library is to create a `PathValidator` and use it to validate user-provided paths.
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! fn example() -> jailed_path::Result<()> {
//!     // 1. Define a jail directory.
//!     let jail_dir = "/var/www/uploads";
//!
//!     // 2. Create a validator for that jail.
//!     let validator = PathValidator::<()>::with_jail(jail_dir)?;
//!
//!     // 3. Validate a user-provided path.
//!     let user_path = "user123/avatar.jpg";
//!     let safe_path = validator.try_path(user_path)?;
//!
//!     // The `safe_path` is now a `JailedPath`, guaranteed to be inside the jail.
//!     println!("Accessing file: {safe_path}"); // Output: "/user123/avatar.jpg"
//!
//!     // Attempting to escape the jail will be clamped to the jail root.
//!     let malicious_path = "../../../etc/passwd";
//!     let clamped_path = validator.try_path(malicious_path)?; // This succeeds but is clamped
//!     assert!(clamped_path.real_path().starts_with(validator.jail()));
//!     Ok(())
//! }
//! ```
//!
//! ### Ergonomic File I/O with `JailedFileOps`
//!
//! By importing the `JailedFileOps` trait, you can call file I/O methods directly on your `JailedPath`.
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedFileOps};
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let validator = PathValidator::<()>::with_jail("/tmp/jail")?;
//!     let file = validator.try_path("data.txt")?;
//!
//!     // Write to the file (safely within the jail).
//!     file.write_bytes(b"secure content")?;
//!
//!     // Read from the file.
//!     let content = file.read_to_string()?;
//!     assert_eq!(content, "secure content");
//!     Ok(())
//! }
//! ```
//!
//! ### Type-Safe Markers for Different Jails
//!
//! You can use marker structs to ensure that a path for user uploads is never accidentally used to access public assets.
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! fn example() -> jailed_path::Result<()> {
//!     // Define unique markers for each jail type.
//!     struct UserUploads;
//!     struct PublicAssets;
//!
//!     let upload_validator = PathValidator::<UserUploads>::with_jail("/srv/uploads")?;
//!     let asset_validator = PathValidator::<PublicAssets>::with_jail("/srv/public")?;
//!
//!     let user_file = upload_validator.try_path("user1/profile.jpg")?;
//!     let asset_file = asset_validator.try_path("css/style.css")?;
//!
//!     // This would cause a compile-time error because the types don't match!
//!     // fn process_asset(path: JailedPath<PublicAssets>) { /* ... */ }
//!     // process_asset(user_file); // COMPILE ERROR!
//!     Ok(())
//! }
//! ```
//!
//! ## Security Philosophy
//!
//! The core design principle is **Secure by Construction**. This is achieved by:
//! - **No `Deref` or `AsRef<Path>`**: Prevents accidental use of insecure standard library path methods.
//! - **Explicitness**: Methods that expose the real, absolute path (like `real_path()` and `real_path_to_str()`) are clearly named to make the developer's intent obvious.
//! - **Virtualization**: By default, all string representations and display implementations use a virtual, jail-relative path to prevent leaking filesystem structure.

#![forbid(unsafe_code)]

// Public modules
pub mod error;
pub mod ext;
pub mod jailed_path;
pub mod validator;

#[cfg(test)]
mod tests;

// Public exports
pub use error::JailedPathError;
pub use ext::JailedFileOps;
pub use jailed_path::JailedPath;
pub use validator::PathValidator;

/// Creates a `JailedPath` by jailing a `path_to_jail` within a `jail_path`.
///
/// This function is a convenient way to create a `JailedPath` without needing to
/// create a `PathValidator` first. It performs the same validation steps as
/// `PathValidator::try_path`.
///
/// # Arguments
///
/// * `jail_path` - The path to the jail directory.
/// * `path_to_jail` - The path to jail, relative to the `jail_path`.
///
/// # Returns
///
/// A `Result` containing the `JailedPath` if successful, or a `JailedPathError`
/// if the path is invalid or escapes the jail.
pub fn try_jail<Marker, P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    jail_path: P,
    path_to_jail: Q,
) -> Result<JailedPath<Marker>> {
    let jail_root =
        validator::validated_path::ValidatedPath::<validator::validated_path::Raw>::new(
            jail_path.as_ref(),
        )
        .canonicalize()?;

    if jail_root.exists() && !jail_root.is_dir() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "The specified jail path exists but is not a directory.",
        );
        return Err(JailedPathError::invalid_jail(
            jail_path.as_ref().to_path_buf(),
            error,
        ));
    }

    let checked = validator::validated_path::ValidatedPath::<validator::validated_path::Raw>::new(
        path_to_jail.as_ref(),
    )
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()?
    .boundary_check(&jail_root)?;

    Ok(JailedPath::<Marker>::new(
        std::sync::Arc::new(jail_root),
        checked,
    ))
}

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
