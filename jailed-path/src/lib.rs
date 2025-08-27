//! # jailed-path
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
