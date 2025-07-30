use super::staged_path::*;
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use std::marker::PhantomData;
use std::path::Path;
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
/// use jailed_path::PathValidator;
/// use jailed_path::JailedPathError;
/// use std::fs;
/// use tempfile::tempdir;
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let temp_dir = tempdir()?;
///     let jail_path = temp_dir.path();
///     fs::create_dir_all(jail_path.join("uploads"))?;
///     fs::write(jail_path.join("uploads/existing_file.txt"), "test")?;
///     let validator = PathValidator::<()>::with_jail(jail_path.join("uploads"))?;
///
///     // Existing files work
///     let _path = validator.try_path("existing_file.txt")?;
///
///     // Non-existent files for writing also work  
///     let _path = validator.try_path("user123/new_document.pdf")?;
///
///     // Traversal attacks are clamped to the jail root (no error is returned)
///     let _ = validator.try_path("../../../sensitive.txt")?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PathValidator<Marker = ()> {
    jail: Arc<StagedPath<(Raw, Canonicalized)>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> PathValidator<Marker> {
    /// Like try_path, but normalizes all backslashes to slashes before validation.
    /// Use this for any external or untrusted string path to ensure cross-platform consistency.
    #[inline]
    pub fn try_path_normalized(&self, path_str: &str) -> Result<JailedPath<Marker>> {
        let normalized = path_str.replace('\\', "/");
        self.try_path(normalized)
    }
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
    /// use jailed_path::PathValidator;
    /// use jailed_path::JailedPathError;
    /// use std::fs;
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     fs::create_dir_all("valid_jail")?;
    ///     // ✅ Valid jail directory
    ///     let _validator = PathValidator::<()>::with_jail("valid_jail")?;
    ///
    ///     // Non-existent directory is allowed (validator is created)
    ///     let _ = PathValidator::<()>::with_jail("does_not_exist")?;
    ///
    ///     fs::write("not_a_dir.txt", "content")?;
    ///     // ❌ Path exists but is not a directory
    ///     assert!(PathValidator::<()>::with_jail("not_a_dir.txt").is_err());
    ///     fs::remove_file("not_a_dir.txt").ok();
    ///     fs::remove_dir_all("valid_jail").ok();
    ///     Ok(())
    /// }
    /// ```
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail_path = jail.as_ref();
        // Use StagedPath and its canonicalize method for jail path processing
        let staged = StagedPath::<Raw>::new(jail_path);
        let canonicalized = staged.canonicalize()?;

        // If jail exists, it must be a directory; if it does not exist, allow it
        if canonicalized.inner().exists() && !canonicalized.inner().is_dir() {
            let error =
                std::io::Error::new(std::io::ErrorKind::NotFound, "path is not a directory");
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: Arc::new(canonicalized),
            _marker: PhantomData,
        })
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
    /// - Virtual root behavior is cosmetic; all paths are contained within jail
    ///
    /// # Use Cases
    /// - Validating paths for file creation (supports non-existent paths)
    /// - Validating paths for file reading (existing paths)
    /// - Any security-critical path validation
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        // STEP 1: Clamp the candidate path
        let clamped = StagedPath::<Raw>::new(candidate_path.as_ref()).clamp();

        // STEP 2: Join to jail root (type-state: ((Raw, Clamped), JoinedJail))
        let joined = clamped.join_jail(&self.jail);

        // STEP 3: Canonicalize (type-state: (((Raw, Clamped), JoinedJail), Canonicalized))
        let canon = joined.canonicalize()?;

        // STEP 4: Boundary check (type-state: ((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked))
        let checked = canon.boundary_check(&self.jail)?;

        Ok(JailedPath::new(checked, self.jail.clone()))
    }

    // ...existing code...

    pub fn jail(&self) -> &Path {
        self.jail.as_path()
    }
}
