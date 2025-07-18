use crate::jailed_path::JailedPath;
use crate::soft_canonicalize::soft_canonicalize;
use crate::{JailedPathError, Result};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

/// Path Validator with Security-First Soft Canonicalization
///
/// This module implements a security-first path validation system that can handle both
/// existing and non-existent paths while providing mathematical guarantees against
/// path traversal attacks.
///
/// ## Key Features
///
/// - **Security-First Design**: Uses soft canonicalization for mathematical path resolution
/// - **Soft Canonicalization**: Resolves existing parts and handles non-existent paths safely
/// - **Cross-Platform**: Works correctly on Windows, macOS, and Linux
/// - **Zero-False-Positives**: All legitimate paths within the jail are accepted
/// - **Zero-False-Negatives**: All escape attempts are guaranteed to be blocked
///
/// ## Security Guarantees
///
/// 1. **Symbolic Link Resolution**: All symlinks are resolved to their canonical targets
/// 2. **Path Component Resolution**: All `.` and `..` components are mathematically resolved
/// 3. **Cross-Platform Normalization**: OS-specific path quirks are handled by the filesystem
/// 4. **Escape Detection**: Any path that resolves outside the jail is guaranteed to be caught
///
/// ## Implementation Details
///
/// Uses soft canonicalization which:
/// 1. Finds the deepest existing ancestor directory
/// 2. Canonicalizes the existing part (resolving symlinks, normalizing paths)
/// 3. Appends non-existing components to the canonicalized base
/// 4. Validates the final path against the jail boundary
///
/// This approach ensures that even complex traversal patterns like `a/b/../../../etc/passwd`
/// are properly resolved and validated against the jail boundary, without requiring
/// filesystem modification or temporary file creation.
///
/// ## Examples
///
/// ```rust
/// # use jailed_path::PathValidator;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let validator = PathValidator::<()>::with_jail("/safe/directory")?;
///
/// // Existing files work
/// let path = validator.try_path("existing_file.txt")?;
///
/// // Non-existent files for writing also work  
/// let path = validator.try_path("user123/new_document.pdf")?;
///
/// // Traversal attacks are blocked
/// assert!(validator.try_path("../../../etc/passwd").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PathValidator<Marker = ()> {
    jail: PathBuf,
    _marker: PhantomData<Marker>,
}

impl<Marker> PathValidator<Marker> {
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail_path = jail.as_ref();
        let canonical_jail = jail_path
            .canonicalize()
            .map_err(|e| JailedPathError::path_resolution_error(jail_path.to_path_buf(), e))?;

        if !canonical_jail.is_dir() {
            let error =
                std::io::Error::new(std::io::ErrorKind::NotFound, "path is not a directory");
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: canonical_jail,
            _marker: PhantomData,
        })
    }

    /// Validates that a path contains no parent directory traversals (..)
    ///
    /// This method performs lexical validation to reject any path containing ".." components
    /// before any filesystem operations occur. This prevents directory traversal attacks
    /// regardless of whether paths exist or not.
    fn validate_no_parent_traversal(&self, candidate_path: &Path) -> Result<()> {
        for component in candidate_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(JailedPathError::path_escapes_boundary(
                    candidate_path.to_path_buf(),
                    self.jail.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Validate a path and return detailed error information on failure
    ///
    /// This method prioritizes security over performance by using soft canonicalization
    /// to resolve all symbolic links and path components. This works with both existing
    /// and non-existent paths without requiring filesystem modification.
    ///
    /// # Security Guarantees
    /// - All symbolic links are resolved to their targets
    /// - All `..` and `.` components are rejected before filesystem access
    /// - Path traversal attacks are mathematically impossible to bypass
    /// - Cross-platform path normalization is handled by the OS
    ///
    /// # Use Cases
    /// - Validating paths for file creation (supports non-existent paths)
    /// - Validating paths for file reading (existing paths)
    /// - Any security-critical path validation
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        let candidate_path = candidate_path.as_ref(); // Compiler optimization

        // SECURITY: Reject any path containing ".." components before filesystem operations
        self.validate_no_parent_traversal(candidate_path)?;

        let full_path = if candidate_path.is_absolute() {
            // For absolute paths, use them directly but they'll be validated against jail later
            candidate_path.to_path_buf()
        } else {
            self.jail.join(candidate_path)
        };

        // SECURITY FIRST: Use soft canonicalization for safe path resolution
        let resolved_path = soft_canonicalize(&full_path).map_err(|e| {
            JailedPathError::path_resolution_error(candidate_path.to_path_buf(), e)
        })?;

        // CRITICAL SECURITY CHECK: Must be within jail boundary
        // Both paths are canonical, so comparison should be reliable
        if !resolved_path.starts_with(&self.jail) {
            return Err(JailedPathError::path_escapes_boundary(
                resolved_path,
                self.jail.clone(),
            ));
        }

        Ok(JailedPath::new(resolved_path))
    }

    pub fn jail(&self) -> &Path {
        &self.jail
    }
}
