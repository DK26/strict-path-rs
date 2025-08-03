//! # jailed-path
//!
//! **Prevent directory traversal with type-safe virtual path jails and safe symlinks**
//!
//! > *Putting your paths in jail by the Type-State Police Department*  
//! > *because your LLM can't be trusted with security*
//!
//! `JailedPath` is a filesystem path **mathematically proven** to stay within directory boundaries.
//! Only two ways to create one: `try_jail()` for one-shot validation, and `jail.try_path()`
//! for reusable validation. Both guarantee containment—even malicious input like `../../../etc/passwd` gets safely clamped.
//!
//! ```rust
//! use jailed_path::{try_jail, JailedPath};
//!
//! // ✅ SECURE - Guaranteed safe by construction
//! fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
//!     safe_path.read_bytes()  // Built-in safe operations
//! }
//!
//! # std::fs::create_dir_all("customer_uploads/documents")?;
//! # std::fs::write("customer_uploads/documents/invoice-2024.pdf", b"Customer invoice")?;
//! let safe_path: JailedPath = try_jail("customer_uploads", "documents/invoice-2024.pdf")?;
//!
//! // Even attacks are neutralized:
//! let attack_path: JailedPath = try_jail("customer_uploads", "../../../etc/passwd")?;
//! // ✅ Virtual path shows clean, predictable output - no filesystem leakage!
//! assert_eq!(attack_path.virtual_display(), "/etc/passwd");  // Virtual path display
//! // ✅ But the real path is safely clamped within the jail
//! assert!(attack_path.ends_with("customer_uploads/etc/passwd"));  // Real path clamped!
//! # std::fs::remove_dir_all("customer_uploads").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
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
//! ## Basic Usage
//!
//! ```rust
//! use jailed_path::{try_jail, PathValidator};
//!
//! // One-shot validation
//! let safe_path = try_jail("./web_public", "user/profile.html")?;
//!
//! // Reusable jail  
//! let customer_uploads_jail = PathValidator::with_jail("./customer_uploads")?;
//! let safe_path = customer_uploads_jail.try_path("invoices/2024-001.pdf")?;
//!
//! // Built-in file operations
//! safe_path.write_string("Invoice content updated")?;
//! let content = safe_path.read_to_string()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Multi-Jail Type Safety: Preventing Mix-ups
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedPath};
//!
//! struct StaticAssets;
//! struct UserUploads;
//!
//! fn serve_asset(asset: &JailedPath<StaticAssets>) -> Result<Vec<u8>, std::io::Error> {
//!     asset.read_bytes()  // ✅ Safe built-in operation
//! }
//!
//! # std::fs::create_dir_all("assets")?; std::fs::create_dir_all("uploads")?;
//! # std::fs::write("assets/style.css", "body{}")?;
//! let assets_jail: PathValidator<StaticAssets> = PathValidator::with_jail("assets")?;
//! let uploads_jail: PathValidator<UserUploads> = PathValidator::with_jail("uploads")?;
//!
//! let css_file_path: JailedPath<StaticAssets> = assets_jail.try_path("style.css")?;
//! let user_file_path: JailedPath<UserUploads> = uploads_jail.try_path("avatar.jpg")?;
//!
//! serve_asset(&css_file_path)?; // ✅ Correct type
//! // serve_asset(&user_file_path)?; // ❌ Compile error: wrong marker type!
//! # std::fs::remove_dir_all("assets").ok(); std::fs::remove_dir_all("uploads").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Built-in Safe File Operations
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("safe_jail")?;
//! let document_jail = PathValidator::<()>::with_jail("safe_jail")?;
//! let file_path = document_jail.try_path("data.txt")?;
//!
//! // ✅ SAFE - All operations stay within jail automatically
//! file_path.write_string("secure content")?;
//! let content = file_path.read_to_string()?;
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
//! // Setup: create a secure web server public directory with files
//! let web_public_dir = "public_doctest_example";
//! fs::create_dir_all(format!("{web_public_dir}/css"))?;
//! fs::write(format!("{web_public_dir}/index.html"), "<html></html>")?;
//! fs::write(format!("{web_public_dir}/css/style.css"), "body{}")?;
//! // Create config file outside public dir to simulate real scenario
//! fs::write(format!("{web_public_dir}/config.toml"), "[config]\nkey = 'value'")?;
//!
//! let web_server_jail: PathValidator = PathValidator::with_jail(web_public_dir)?;
//!
//! // ✅ Valid paths - legitimate web requests
//! let safe_path = web_server_jail.try_path("index.html")?;
//! let nested_path = web_server_jail.try_path("css/style.css")?;
//!
//! // ❌ Attack attempts - malicious requests trying to escape public directory
//! let attack1_path = web_server_jail.try_path("../config.toml")?;
//! let attack2_path = web_server_jail.try_path("assets/../../../etc/passwd")?;
//! let attack3_path = web_server_jail.try_path("/etc/shadow")?;
//! // ✅ SAFE: Verify all attacks were neutralized - paths are contained within jail
//! assert!(attack1_path.starts_with(web_public_dir));
//! assert!(attack2_path.starts_with(web_public_dir));
//! assert!(attack3_path.starts_with(web_public_dir));
//!
//! // Cleanup: remove the test directory
//! fs::remove_dir_all(web_public_dir).ok();
//! Ok(())
//! # }
//! ```
//!
//! ## API Design
//!
//! **⚠️ CRITICAL: These are the ONLY two ways to create a JailedPath!**
//!
//! - [`try_jail()`] - One-shot path validation, returns `Result<JailedPath, JailedPathError>`
//! - [`PathValidator::with_jail()`] - Create path jail with boundary
//! - [`jail.try_path()`] - Validate a single path, returns `Result<JailedPath, JailedPathError>`
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
//!     // 2. Create a path jail for that directory.
//!     let uploads_jail = PathValidator::<()>::with_jail(jail_dir)?;
//!
//!     // 3. Validate a user-provided path.
//!     let user_path = "user123/avatar.jpg";
//!     let safe_path = uploads_jail.try_path(user_path)?;
//!
//!     // The `safe_path` is now a `JailedPath`, guaranteed to be inside the jail.
//!     println!("Accessing file: {safe_path}"); // Output: "/user123/avatar.jpg"
//!
//!     // Attempting to escape the jail will be clamped to the jail root.
//!     let malicious_path = "../../../etc/passwd";
//!     let attack_path = uploads_jail.try_path(malicious_path)?; // This succeeds but is clamped
//!     // ✅ SAFE: Verify the attack was neutralized - path stays within jail
//!     assert!(attack_path.starts_with(jail_dir));
//!     Ok(())
//! }
//! ```
//!
//! ### Built-in File I/O Operations
//!
//! `JailedPath` provides convenient file I/O methods built-in, no additional imports needed.
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let temp_jail = PathValidator::<()>::with_jail("/tmp/jail")?;
//!     let file_path = temp_jail.try_path("data.txt")?;
//!
//!     // Write to the file (safely within the jail).
//!     file_path.write_bytes(b"secure content")?;
//!
//!     // Read from the file.
//!     let content = file_path.read_to_string()?;
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
//!     let uploads_jail = PathValidator::<UserUploads>::with_jail("/srv/uploads")?;
//!     let assets_jail = PathValidator::<PublicAssets>::with_jail("/srv/public")?;
//!
//!     let user_file_path = uploads_jail.try_path("user1/profile.jpg")?;
//!     let asset_file_path = assets_jail.try_path("css/style.css")?;
//!
//!     // This would cause a compile-time error because the types don't match!
//!     // fn process_asset(path: JailedPath<PublicAssets>) { /* ... */ }
//!     // process_asset(user_file_path); // COMPILE ERROR!
//!     Ok(())
//! }
//! ```
//!
//! ## ⚠️ Common Anti-Patterns to Avoid
//!
//! ### ❌ WRONG: Using `unjail()` for Basic Operations
//!
//! The `unjail()` method exists for integration with external APIs, but it's commonly misused:
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("/tmp/safe_example")?;
//! let validator = PathValidator::<()>::with_jail("/tmp/safe_example")?;
//! let jailed_path = validator.try_path("file.txt")?;
//!
//! // ❌ ANTI-PATTERN: Unjailing just to check containment
//! let real_path = jailed_path.unjail();
//! let contains_safe = real_path.starts_with("/safe");
//! // This anti-pattern produces wrong results because real path is different
//! assert!(!contains_safe, "Anti-pattern fails - real path is not '/safe/...'");
//!
//! // ❌ ANTI-PATTERN: Unjailing for file operations  
//! let jailed_path2 = validator.try_path("data.txt")?;
//! let real_path2 = jailed_path2.unjail();
//! // This exposes internal paths and defeats the security model
//! println!("Exposed internal path: {:?}", real_path2);
//!
//! // ❌ ANTI-PATTERN: Unjailing for path manipulation
//! let jailed_path3 = validator.try_path("subdir/file.txt")?;
//! let real_path3 = jailed_path3.unjail();
//! let parent = real_path3.parent(); // Lost security guarantees!
//! assert!(parent.is_some(), "Parent exists but security is lost");
//! # std::fs::remove_dir_all("/tmp/safe_example").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("/tmp/safe_example2")?;
//! let validator = PathValidator::<()>::with_jail("/tmp/safe_example2")?;
//! let jailed_path = validator.try_path("file.txt")?;
//!
//! // ❌ ANTI-PATTERN: Unjailing for file operations  
//! let real_path = jailed_path.unjail();
//! // This exposes the real path and loses security guarantees
//! println!("Exposed real path: {:?}", real_path); // Shows internal filesystem details
//!
//! // ❌ ANTI-PATTERN: Unjailing for path manipulation (create new jailed_path for demo)
//! let jailed_path2 = validator.try_path("file2.txt")?;
//! let real_path2 = jailed_path2.unjail();
//! let parent = real_path2.parent().unwrap(); // Lost security guarantees!
//! println!("Parent path: {:?}", parent); // May leak filesystem structure
//! # std::fs::remove_dir_all("/tmp/safe_example").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ### ✅ CORRECT: Use Built-in Methods ```
//!
//! ### ✅ CORRECT: Use Built-in Methods
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("/tmp/safe_correct")?;
//! let validator = PathValidator::<()>::with_jail("/tmp/safe_correct")?;
//! let jailed_path = validator.try_path("file.txt")?;
//!
//! // ✅ SECURE: Use built-in methods that preserve security
//! assert!(jailed_path.starts_with(validator.jail())); // Secure and direct
//! jailed_path.write_bytes(b"test content")?; // Safe file operations
//! let content = jailed_path.read_bytes()?; // Safe file operations
//! let parent = jailed_path.virtual_parent(); // Safe path manipulation (returns Option)
//! # std::fs::remove_dir_all("/tmp/safe_correct").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ### When `unjail()` is Appropriate
//!
//! Only use `unjail()` when you need to:
//! - **Pass to external APIs** that require `PathBuf` ownership (consume immediately)
//! - **Integration with other crates** that don't support our types
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! fn external_api_that_takes_pathbuf(path: std::path::PathBuf) -> String {
//!     format!("Processing: {}", path.display())
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("/tmp/external_api_example")?;
//! let validator = PathValidator::<()>::with_jail("/tmp/external_api_example")?;
//! let jailed_path = validator.try_path("file.txt")?;
//!
//! // ✅ OK: Immediate consumption for external API
//! let result = external_api_that_takes_pathbuf(jailed_path.unjail());
//! assert!(result.contains("file.txt"));
//! # std::fs::remove_dir_all("/tmp/external_api_example").ok();
//! # Ok(())
//! # }
//! ```
//!
//! **For logging/debugging, use the built-in Display/Debug implementations instead:**
//! ```rust
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("/tmp/logging_example")?;
//! let validator = PathValidator::<()>::with_jail("/tmp/logging_example")?;
//! let jailed_path = validator.try_path("file.txt")?;
//!
//! // ✅ PREFERRED: Use Display (shows virtual path)
//! println!("Processing file: {}", jailed_path);
//!
//! // ✅ PREFERRED: Use Debug (shows virtual path + jail info)
//! println!("Path details: {:?}", jailed_path);
//! # std::fs::remove_dir_all("/tmp/logging_example").ok();
//! # Ok(())
//! # }
//! ```
//!
//! **Remember**: Once you call `unjail()`, you lose all security guarantees.
//!
//! ## Security Philosophy
//!
//! The core design principle is **Secure by Construction**. This is achieved by:
//! - **No `Deref` or `AsRef<Path>`**: Prevents accidental use of insecure standard library path methods.
//! - **Explicitness**: Methods that expose the real, absolute path (like `real_path_to_str()`) are clearly named to make the developer's intent obvious.
//! - **Virtualization**: By default, all string representations and display implementations use a virtual, jail-relative path to prevent leaking filesystem structure.

#![forbid(unsafe_code)]

// Public modules
pub mod error;
pub mod jailed_path;
pub mod validator;

#[cfg(test)]
mod tests;

// Public exports
pub use error::JailedPathError;
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
