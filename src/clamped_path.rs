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

use std::path::Component;

impl ClampedPath {
    /// Create a clamped path from user input, preventing jail escapes.
    /// Handles virtual root, excessive traversal, and normalizes path.
    pub(crate) fn new(candidate_path: impl AsRef<Path>) -> Self {
        let candidate_path = candidate_path.as_ref();
        // 1. Handle virtual root (strip leading "/")
        let jail_relative = if candidate_path.is_absolute() {
            candidate_path.components().skip(1).collect::<PathBuf>()
        } else {
            candidate_path.to_path_buf()
        };

        // 2. Clamp path components
        let mut result_components = Vec::new();
        for component in jail_relative.components() {
            match component {
                Component::Normal(name) => result_components.push(name),
                Component::ParentDir => {
                    result_components.pop();
                } // Clamp!
                Component::CurDir => {} // Ignore
                Component::RootDir => result_components.clear(),
                Component::Prefix(_) => {} // Windows drives - ignore
            }
        }

        // 3. Build final path
        let mut clamped = PathBuf::new();
        for component in result_components {
            clamped.push(component);
        }
        Self { path: clamped }
    }

    /// Get reference to the inner path (safe because guaranteed clamped)
    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }
}
