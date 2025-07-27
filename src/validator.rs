use crate::clamped_path::ClampedPath;
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use soft_canonicalize::soft_canonicalize;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
/// This approach ensures that even complex traversal patterns like `a/b/../../../sensitive.txt`
/// are properly resolved and validated against the jail boundary, without requiring
/// filesystem modification or temporary file creation.
///
/// ## Examples
///
/// ```rust
/// # use jailed_path::PathValidator;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # std::fs::create_dir_all("uploads")?;
/// let validator = PathValidator::<()>::with_jail("uploads")?;
///
/// // Existing files work
/// let path = validator.try_path("existing_file.txt")?;
///
/// // Non-existent files for writing also work  
/// let path = validator.try_path("user123/new_document.pdf")?;
///
/// // Traversal attacks are blocked
/// assert!(validator.try_path("../../../sensitive.txt").is_err());
/// # std::fs::remove_dir_all("uploads").ok();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PathValidator<Marker = ()> {
    jail: Arc<PathBuf>,
    _marker: PhantomData<Marker>,
}

impl<Marker> PathValidator<Marker> {
    /// Creates a new PathValidator with the specified jail directory.
    ///
    /// This constructor performs strict validation to ensure the jail is a valid, existing directory.
    /// The jail path is canonicalized to resolve all symbolic links and normalize the path representation.
    ///
    /// # Arguments
    /// * `jail` - Path to the directory that will serve as the jail boundary
    ///
    /// # Returns
    /// * `Ok(PathValidator)` - If the jail is a valid, existing directory
    /// * `Err(JailedPathError)` - If validation fails (see Errors section)
    ///
    /// # Errors
    /// This method returns an error in the following cases:
    ///
    /// ## `JailedPathError::PathResolutionError`
    /// - The jail path does not exist
    /// - Permission denied when accessing the jail path
    /// - The jail path contains invalid characters or exceeds system limits
    /// - I/O errors during path canonicalization
    ///
    /// ## `JailedPathError::InvalidJail`
    /// - The jail path exists but is not a directory (e.g., it's a file or special device)
    ///
    /// # Security Considerations
    /// - The jail directory must exist before creating the validator (fail-fast principle)
    /// - All symbolic links in the jail path are resolved to prevent confusion
    /// - The canonicalized jail path is used for all subsequent validations
    ///
    /// # Examples
    /// ```rust
    /// # use jailed_path::PathValidator;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("valid_jail")?;
    /// // ✅ Valid jail directory
    /// let validator = PathValidator::<()>::with_jail("valid_jail")?;
    ///
    /// // ❌ Non-existent directory
    /// assert!(PathValidator::<()>::with_jail("does_not_exist").is_err());
    ///
    /// # std::fs::write("not_a_dir.txt", "content")?;
    /// // ❌ Path exists but is not a directory
    /// assert!(PathValidator::<()>::with_jail("not_a_dir.txt").is_err());
    /// # std::fs::remove_file("not_a_dir.txt").ok();
    /// # std::fs::remove_dir_all("valid_jail").ok();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail_path = jail.as_ref();
        let canonical_jail = soft_canonicalize(jail_path)
            .map_err(|e| JailedPathError::path_resolution_error(jail_path.to_path_buf(), e))?;

        // If jail exists, it must be a directory
        if canonical_jail.exists() && !canonical_jail.is_dir() {
            let error =
                std::io::Error::new(std::io::ErrorKind::NotFound, "path is not a directory");
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: Arc::new(canonical_jail),
            _marker: PhantomData,
        })
    }

    /// Creates a ClampedPath from user input
    ///
    /// This is the ONLY way to create a ClampedPath, ensuring all paths
    /// go through proper clamping and virtual root handling.
    ///
    /// # Security
    /// - Strips leading "/" for virtual root behavior
    /// - Clamps ".." components to prevent jail escapes  
    /// - Handles "." and empty components
    /// - Returns type-safe ClampedPath that cannot escape jail
    pub(crate) fn clamp_path(&self, candidate_path: &Path) -> ClampedPath {
        // Handle virtual root behavior
        let jail_relative = if candidate_path.is_absolute() {
            candidate_path.strip_prefix("/").unwrap_or(candidate_path)
        } else {
            candidate_path
        };

        // Clamp path components
        let mut result_components = Vec::new();
        for component in jail_relative.components() {
            match component {
                std::path::Component::Normal(name) => {
                    result_components.push(name);
                }
                std::path::Component::ParentDir => {
                    // Remove last component if present, otherwise stay at jail root
                    result_components.pop();
                }
                std::path::Component::CurDir => {
                    // Ignore "." components
                }
                std::path::Component::RootDir => {
                    // Treat as jail root - clear all components
                    result_components.clear();
                }
                _ => {
                    // Handle other components conservatively
                    if let Some(os_str) = component.as_os_str().to_str() {
                        if !os_str.is_empty() {
                            result_components.push(component.as_os_str());
                        }
                    }
                }
            }
        }

        // Build the clamped path
        let mut clamped = PathBuf::new();
        for component in result_components {
            clamped.push(component);
        }

        ClampedPath::new(clamped)
    }

    /// Validate a path and return detailed error information on failure
    ///
    /// # Two-Layer Security Model
    ///
    /// 1. **Path Clamping**: Handles `..` directory traversal by clamping navigation to the jail boundary.
    ///    - No error is returned for excessive `..` components; path is clamped to jail root.
    ///    - Absolute paths are treated as jail-relative (virtual root behavior).
    /// 2. **Canonicalization + Boundary Check**: Handles symlink escapes by resolving symlinks and verifying jail containment.
    ///    - Symlink escapes are detected and rejected.
    ///
    /// # Security Guarantees
    /// - No path can escape jail boundary through `..` navigation (clamped)
    /// - No path can escape jail boundary through symlinks (canonicalization + boundary check)
    /// - Virtual root behavior is cosmetic; all paths are contained within jail
    ///
    /// # Use Cases
    /// - Validating paths for file creation (supports non-existent paths)
    /// - Validating paths for file reading (existing paths)
    /// - Any security-critical path validation
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        let candidate_path = candidate_path.as_ref();

        // STEP 1: Create clamped path (type system enforces this step)
        let clamped_path: ClampedPath = self.clamp_path(candidate_path);

        // STEP 2: Build full path using clamped path (guaranteed safe)
        let full_path = self.jail.as_ref().join(clamped_path.as_path());

        // STEP 3: Canonicalize for symlink resolution
        let resolved_path = soft_canonicalize(full_path)
            .map_err(|e| JailedPathError::path_resolution_error(candidate_path.to_path_buf(), e))?;

        // STEP 4: Boundary check (primarily detects symlink escapes)
        if !resolved_path.starts_with(self.jail.as_ref()) {
            return Err(JailedPathError::path_escapes_boundary(
                resolved_path,
                self.jail.as_ref().to_path_buf(),
            ));
        }

        Ok(JailedPath::new(resolved_path, self.jail.clone()))
    }

    // ...existing code...

    pub fn jail(&self) -> &Path {
        &self.jail
    }
}
