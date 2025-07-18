//! # jailed-path
//!
//! **Type-safe path validation ensuring files stay within defined jail boundaries**
//!
//! `jailed-path` prevents directory traversal attacks by validating that file paths
//! remain within designated boundaries using Rust's type system.
//!
//! ## Quick Start
//!
//! ```rust
//! use jailed_path::PathValidator;
//!
//! // Create validator with jail boundary
//! let temp_dir = std::env::temp_dir();
//! let validator: PathValidator = PathValidator::with_jail(&temp_dir)?;
//!
//! // Validate user-provided paths
//! let safe_path = validator.try_path("image.jpg")?;
//!
//! // Use with any std::fs operation
//! std::fs::write(&safe_path, b"image data")?;
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
//!
//! ## API Design
//!
//! - [`PathValidator::with_jail()`] - Create validator with jail boundary
//! - [`PathValidator::try_path()`] - Validate paths (returns `Result`)
//! - [`JailedPath`] - Validated path type with full `Path` compatibility
//! - [`JailedPathError`] - Detailed error information for debugging
//!
//! ## Security Guarantees
//!
//! All symbolic links are resolved, `..` components are blocked, and paths are
//! mathematically validated against the jail boundary. Path traversal attacks
//! are impossible to bypass.
//!
//! ## Integration Examples
//!
//! ### Web Server File Serving
//!
//! ```rust
//! use jailed_path::PathValidator;
//! use std::path::Path;
//!
//! fn serve_static_file(validator: &PathValidator, request_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//!     // Safely validate user-provided path
//!     let safe_path = validator.try_path(request_path)?;
//!     
//!     // Read file - guaranteed to be within jail
//!     Ok(std::fs::read(&safe_path).unwrap_or_default())
//! }
//!
//! let temp_dir = std::env::temp_dir();
//! let validator = PathValidator::with_jail(&temp_dir)?;
//! let _content = serve_static_file(&validator, "images/logo.png")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### With app-path for Portable Applications
//!
//! ```rust
//! use app_path::app_path;
//! use jailed_path::PathValidator;
//!
//! // Get application data directory using app-path macro
//! let app_data = app_path!("data");
//! app_data.create_dir()?;
//!
//! // Create validator jail around app data
//! let validator: PathValidator = PathValidator::with_jail(&app_data)?;
//!
//! // Safely handle user file requests
//! let user_file = validator.try_path("document.pdf")?;
//! std::fs::write(&user_file, b"pdf data")?;
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
