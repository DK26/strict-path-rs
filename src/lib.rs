//! # jailed-path
//!
//! Type-safe path validation ensuring files stay within defined jail boundaries.

pub mod error;
pub mod jailed_path;
pub mod validator;

#[cfg(test)]
mod tests;

pub use error::JailedPathError;
pub use jailed_path::JailedPath;
pub use validator::PathValidator;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
