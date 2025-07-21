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
//!     std::fs::read(safe_path)
//! }
//!
//! let validator = PathValidator::with_jail(std::env::temp_dir())?;
//! let safe_path: JailedPath = validator.try_path("document.pdf")?; // Only way to create JailedPath
//! # std::fs::write(&safe_path, b"test")?; let content = serve_file(&safe_path)?;
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
//!     std::fs::read_to_string(config_path)
//! }
//!
//! let config_validator: PathValidator<ConfigFiles> = PathValidator::with_jail(std::env::temp_dir())?;
//! let user_validator: PathValidator<UserData> = PathValidator::with_jail(std::env::temp_dir())?;
//!
//! let config_file: JailedPath<ConfigFiles> = config_validator.try_path("app.toml")?;
//! let user_file: JailedPath<UserData> = user_validator.try_path("profile.json")?;
//!
//! # std::fs::write(&config_file, "key=value")?; load_config(&config_file)?; // ✅ Correct type
//! // load_config(&user_file)?; // ❌ Compile error: wrong marker type!
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
//!     let content = std::fs::read(file)?;
//!     Ok(())
//! }
//!
//! let upload_validator: PathValidator<UserUploads> = PathValidator::with_jail(std::env::temp_dir())?;
//! let upload_file: JailedPath<UserUploads> = upload_validator.try_path("photo.jpg")?;
//! # std::fs::write(&upload_file, b"data")?; process_upload(&upload_file)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Key Features
//!
//! - **Single Dependency**: Only depends on our own `soft-canonicalize` crate
//! - **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries  
//! - **Security First**: Prevents `../` path traversal attacks automatically
//! - **Path Canonicalization**: Resolves symlinks and relative components safely
//! - **Cross-Platform**: Works on Windows, macOS, and Linux
//! - **Performance**: Minimal allocations, efficient validation
//! - **Zero-Cost Markers**: Generic markers add no runtime overhead
//!
//! ## API Design
//!
//! - [`PathValidator::with_jail()`] - Create validator with jail boundary
//! - [`validator.try_path()`] - Validate paths (returns `Result`)
//! - [`JailedPath`] - Validated path type with full `Path` compatibility
//! - [`JailedPathError`] - Detailed error information for debugging
//!
//! ## Security Guarantees
//!
//! All `..` components are blocked before processing, symbolic links are resolved, and paths are
//! mathematically validated against the jail boundary. Path traversal attacks
//! are impossible to bypass.
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! let validator: PathValidator = PathValidator::with_jail(std::env::temp_dir())?;
//!
//! // ✅ Valid paths
//! let safe = validator.try_path("file.txt")?;
//! let nested = validator.try_path("dir/file.txt")?;
//!
//! // ❌ Any `..` component causes validation failure
//! assert!(validator.try_path("../escape.txt").is_err());
//! assert!(validator.try_path("dir/../file.txt").is_err());
//! assert!(validator.try_path("../../etc/passwd").is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
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
