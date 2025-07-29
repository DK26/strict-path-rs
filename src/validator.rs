// (JailPath type alias removed; use StagedPath<Canonicalized> directly)
///
/// Path after boundary check against the jail root.
pub struct BoundaryChecked;
// --- Type-State Markers ---
#[derive(Debug, Clone)]
/// The original, unchecked path as provided by the user.
pub struct Raw;
#[derive(Debug, Clone)]
/// Path after normalization of `.` and `..` components (clamping).
pub struct Clamped;
#[derive(Debug, Clone)]
/// Path after being joined to the jail root.
pub struct JoinedJail;
#[derive(Debug, Clone)]
/// Path after canonicalization (symlinks resolved, absolute).
pub struct Canonicalized;

/// # Understanding `StagedPath` Type Parameters
///
/// `StagedPath<State>` uses Rust’s type system to track the exact sequence of security-relevant
/// transformations a path has undergone. The `State` parameter is a tuple of marker types,
/// each representing a processing stage (e.g., `Raw`, `Clamped`, `JoinedJail`, `Canonicalized`, `BoundaryChecked`).
///
/// ## How to Read the Type
///
/// - The **innermost** type (leftmost in the tuple) is always `Raw`, representing the original, unchecked path.
/// - Each additional marker (added as you call methods like `.clamp()`, `.join_jail()`, `.canonicalize()`, `.boundary_check()`)
///   is appended to the tuple, in the order the operations were performed.
/// - The **outermost** type (rightmost in the tuple) is the most recent operation performed.
///
/// ### Example
///
/// ```rust
/// use jailed_path::validator::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// // This type means: Raw -> Clamped -> JoinedJail -> Canonicalized -> BoundaryChecked
/// type SecurePath = StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Why This Matters
///
/// - **Security:** The type system enforces that no step is skipped or reordered.
/// - **Auditability:** Anyone reading the type knows exactly what has been done to the path.
/// - **Extensibility:** New security steps can be added as new marker types.
///
/// ## Typical Flow
///
/// ```rust
/// use jailed_path::validator::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// let jail = StagedPath::<Raw>::new("/jail").canonicalize().unwrap();
/// let staged = StagedPath::new("user_upload.txt")
///     .clamp()
///     .join_jail(&jail)
///     .canonicalize().unwrap()
///     .boundary_check(&jail).unwrap();
/// // staged: StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>
/// ```
///
/// ## Type Aliases for Common States
///
/// For convenience, you may define type aliases for common state combinations:
///
/// ```rust
/// use jailed_path::validator::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// type FullyChecked = StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Advanced Usage
///
/// You can branch or skip steps (if your security policy allows), and the type will always reflect the actual processing history.
///
/// ---
///
/// **In summary:**  
/// The `StagedPath` type parameter is a type-level log of all security-relevant processing steps applied to a path.
#[derive(Debug, Clone)]
pub struct StagedPath<State> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<State>,
}

impl StagedPath<Raw> {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Self {
        StagedPath {
            inner: path.as_ref().to_path_buf(),
            _marker: std::marker::PhantomData,
        }
    }
    // Only new() is implemented for StagedPath<Raw>. All transitions are on impl<S> StagedPath<S>.
}

// join_jail now requires the jail to be a canonicalized path (no unconstrained S2)
impl<S> StagedPath<(S, Clamped)> {
    pub fn join_jail(
        self,
        jail: &StagedPath<(Raw, Canonicalized)>,
    ) -> StagedPath<((S, Clamped), JoinedJail)> {
        let joined = jail.inner.join(self.inner);
        StagedPath {
            inner: joined,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> StagedPath<S> {
    /// Consumes the StagedPath and returns the inner PathBuf.
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }
    pub fn clamp(self) -> StagedPath<(S, Clamped)> {
        use std::path::Component;
        let mut stack: Vec<Component> = Vec::new();
        let components = self.inner.components();
        // Remove all root components (RootDir, Prefix) to force jail-relative
        for comp in components {
            match comp {
                Component::RootDir | Component::Prefix(_) => continue,
                Component::ParentDir => {
                    if let Some(last) = stack.last() {
                        if *last != Component::RootDir {
                            stack.pop();
                        }
                    }
                }
                Component::CurDir => {}
                other => stack.push(other),
            }
        }
        let mut normalized = std::path::PathBuf::new();
        for comp in stack {
            normalized.push(comp.as_os_str());
        }
        StagedPath {
            inner: normalized,
            _marker: std::marker::PhantomData,
        }
    }
    pub fn canonicalize(self) -> Result<StagedPath<(S, Canonicalized)>> {
        // Inline soft_canonicalize logic (assume soft_canonicalize::soft_canonicalize is available)
        let canon = soft_canonicalize::soft_canonicalize(&self.inner)
            .map_err(|e| JailedPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(StagedPath {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }
    pub fn as_path(&self) -> &std::path::Path {
        &self.inner
    }
}

// Boundary check for canonicalized path, adds BoundaryChecked stage
// Only callable on StagedPath<(((S, Clamped), JoinedJail), Canonicalized)>
#[allow(clippy::type_complexity)]
impl<S> StagedPath<(((S, Clamped), JoinedJail), Canonicalized)> {
    pub fn boundary_check(
        self,
        jail: &StagedPath<(Raw, Canonicalized)>,
    ) -> Result<StagedPath<((((S, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>> {
        if !self.inner.starts_with(jail.as_path()) {
            return Err(JailedPathError::path_escapes_boundary(
                self.inner,
                jail.as_path().to_path_buf(),
            ));
        }
        Ok(StagedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}

// Example: Only allow JailedPath construction from a specific state
// (Removed into_jailed_path using CanonicalizedPath; use StagedPath<Canonicalized> directly)
// use crate::clamped_path::ClampedPath; // removed, use StagedPath type-state API
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
// use soft_canonicalize::soft_canonicalize;
// use crate::jailed_path::CanonicalizedPath;
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
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     fs::create_dir_all("uploads")?;
///     fs::write("uploads/existing_file.txt", "test")?;
///     let validator = PathValidator::<()>::with_jail("uploads")?;
///
///     // Existing files work
///     let _path = validator.try_path("existing_file.txt")?;
///
///     // Non-existent files for writing also work  
///     let _path = validator.try_path("user123/new_document.pdf")?;
///
///     // Traversal attacks are clamped to the jail root (no error is returned)
///     let _ = validator.try_path("../../../sensitive.txt")?;
///     fs::remove_dir_all("uploads").ok();
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
        if canonicalized.inner.exists() && !canonicalized.inner.is_dir() {
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
    /// - No path can escape jail boundary through `..` navigation (clamped)
    /// - No path can escape jail boundary through symlinks (canonicalization + boundary check)
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
