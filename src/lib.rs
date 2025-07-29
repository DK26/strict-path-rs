//! # jailed-path
//!
//! **Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed**
//!
//! *Brought to you by the Type-State Police™ - because apparently YOU can't be trusted with file paths!*
//!
//! `jailed-path` transforms runtime path validation into mathematical compile-time guarantees using Rust's type system. Unlike other validation libraries, it safely resolves and follows symbolic links while maintaining strict boundary enforcement.
//!
//! ## Basic Usage: Type Safety Over Manual Validation
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedPath};
//!
//! // ✅ Type-safe: Only accepts validated paths
//! fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
//!     std::fs::read(safe_path.real_path())
//! }
//!
//! # std::fs::create_dir_all("public")?; std::fs::write("public/index.html", b"<html></html>")?;
//! let validator = PathValidator::with_jail("public")?;
//! let safe_path: JailedPath = validator.try_path("index.html")?; // Only way to create JailedPath
//! let content = serve_file(&safe_path)?;
//! # std::fs::remove_dir_all("public").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Preventing Mix-ups with Multiple Jails
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedPath};
//!
//! struct ConfigFiles;
//! struct UserData;
//!
//! fn load_config(config_path: &JailedPath<ConfigFiles>) -> Result<String, std::io::Error> {
//!     std::fs::read_to_string(config_path.real_path())
//! }
//!
//! # std::fs::create_dir_all("config")?; std::fs::create_dir_all("userdata")?;
//! # std::fs::write("config/app.toml", "key=value")?;
//! let config_validator: PathValidator<ConfigFiles> = PathValidator::with_jail("config")?;
//! let user_validator: PathValidator<UserData> = PathValidator::with_jail("userdata")?;
//!
//! let config_file: JailedPath<ConfigFiles> = config_validator.try_path("app.toml")?;
//! let user_file: JailedPath<UserData> = user_validator.try_path("profile.json")?;
//!
//! load_config(&config_file)?; // ✅ Correct type
//! // load_config(&user_file)?; // ❌ Compile error: wrong marker type!
//! # std::fs::remove_dir_all("config").ok(); std::fs::remove_dir_all("userdata").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Optional: Adding Markers for Readability
//!
//! ```rust
//! use jailed_path::{PathValidator, JailedPath};
//!
//! struct UserUploads;
//!
//! fn process_upload(file: &JailedPath<UserUploads>) -> std::io::Result<()> {
//!     let content = std::fs::read(file.real_path())?;
//!     println!("Processing {} bytes", content.len());
//!     Ok(())
//! }
//!
//! # std::fs::create_dir_all("uploads")?; std::fs::write("uploads/photo.jpg", b"fake image data")?;
//! let upload_validator: PathValidator<UserUploads> = PathValidator::with_jail("uploads")?;
//! let upload_file: JailedPath<UserUploads> = upload_validator.try_path("photo.jpg")?;
//! process_upload(&upload_file)?;
//! # std::fs::remove_dir_all("uploads").ok();
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Key Features
//!
//! - **Security First**: Prevents `../` path traversal attacks automatically
//! - **Path Canonicalization**: Resolves symlinks and relative components safely
//! - **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries  
//! - **Multi-Jail Support**: Keep different validators separate with your own optional marker types
//! - **Single Dependency**: Only depends on our own `soft-canonicalize` crate
//! - **Cross-Platform**: Works on Windows, macOS, and Linux
//! - **Performance**: Minimal allocations, efficient validation
//! - **Virtual Root Display**: Paths are shown as if from the root of your jail, so user-facing output is always clean and intuitive. No leaking of internal or absolute paths—just what the user expects to see.
//!
//! ## API Design
//!
//! - [`PathValidator::with_jail()`] - Create validator with jail boundary
//! - [`validator.try_path()`] - Validate a single path, returns `Result<JailedPath, JailedPathError>`
//! - [`JailedPath`] - Validated path type (can ONLY be created via `try_path()`)
//! - [`JailedPathError`] - Detailed error information for debugging
//!
//! ## Security Guarantees
//!
//! All `..` components are blocked before processing, symbolic links are resolved, and paths are
//! mathematically validated against the jail boundary. Path traversal attacks
//! are impossible to bypass.
//!
//! ```rust
//! # fn doctest() -> Result<(), Box<dyn std::error::Error>> {
//! use jailed_path::PathValidator;
//! use std::fs;
//! use std::io::Write;
//!
//! // Setup: create a unique test directory and files
//! let test_dir = "public_doctest_example";
//! fs::create_dir_all(format!("{}/css", test_dir))?;
//! fs::write(format!("{}/index.html", test_dir), "<html></html>")?;
//! fs::write(format!("{}/css/style.css", test_dir), "body{}")?;
//! // The clamped file does not need to exist for the test, but we create it for completeness
//! fs::write(format!("{}/config.toml", test_dir), "[config]\nkey = 'value'")?;
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

pub mod error;
pub mod jailed_path;
pub mod validator;

#[cfg(test)]
mod tests;

pub use error::JailedPathError;
pub use jailed_path::JailedPath;
pub use soft_canonicalize::soft_canonicalize;
pub use validator::PathValidator;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
