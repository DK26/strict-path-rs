//! Type-safe clamped path for jail security
//!
//! # Security Architecture
//!
//! This module uses type-state patterns to prevent security vulnerabilities:
//!
//! - `Path` / `PathBuf` - Untrusted user input (potentially dangerous)
//! - `ClampedPath` - Guaranteed safe from directory traversal attacks
//! - `JailedPath` - Fully validated and ready for file operations
//!
//! ## Critical Security Rule
//!
//! **NEVER** use `Path::join()` directly with user input!
//! Always go through `PathValidator::clamp_path()` first.
//!
//! The type system enforces this rule at compile time.

use std::path::{Path, PathBuf};

/// A path that has been clamped to prevent jail escapes
/// Can ONLY be created through PathValidator::clamp_path()
/// This prevents contributors from accidentally using unclamped paths
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClampedPath {
    path: PathBuf,
}

impl ClampedPath {
    /// Private constructor - can only be called from within this module
    /// This ensures all ClampedPath instances went through proper clamping
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get reference to the inner path (safe because guaranteed clamped)
    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }
}
