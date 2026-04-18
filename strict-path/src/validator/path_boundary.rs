//! `PathBoundary<Marker>` — the security perimeter for validated path operations.
//!
//! A `PathBoundary` represents a trusted filesystem directory. All `StrictPath` values
//! produced through it are guaranteed, at construction time, to resolve inside that
//! directory. This guarantee is provided by `canonicalize_and_enforce_restriction_boundary`,
//! which canonicalizes the candidate path (resolving symlinks and `..`) and then verifies
//! it starts with the canonicalized boundary. Any path that would escape is rejected with
//! `PathEscapesBoundary` before any I/O occurs.
use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::*;
use crate::Result;

use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

/// Canonicalize a candidate path and enforce the `PathBoundary` boundary, returning a `StrictPath`.
///
/// # Errors
///
/// - `StrictPathError::PathResolutionError`: Canonicalization fails (I/O or resolution error).
/// - `StrictPathError::PathEscapesBoundary`: Resolved path would escape the boundary.
///
/// # Examples
///
/// ```rust
/// # use strict_path::{PathBoundary, Result};
/// # fn main() -> Result<()> {
/// let sandbox = PathBoundary::<()>::try_new_create("./sandbox")?;
/// // Untrusted input from request/CLI/config/etc.
/// let user_input = "sub/file.txt";
/// // Use the public API that exercises the same validation pipeline
/// // as this internal helper.
/// let file = sandbox.strict_join(user_input)?;
/// assert!(file.strictpath_display().to_string().contains("sandbox"));
/// # Ok(())
/// # }
/// ```
pub(crate) fn canonicalize_and_enforce_restriction_boundary<Marker>(
    path: impl AsRef<Path>,
    restriction: &PathBoundary<Marker>,
) -> Result<StrictPath<Marker>> {
    // Relative paths are anchored to the boundary so they cannot be
    // interpreted relative to the process CWD (which is outside our control).
    // Absolute paths are accepted as-is because canonicalization + boundary_check
    // will still reject any path that resolves outside the boundary.
    let target_path = if path.as_ref().is_absolute() {
        path.as_ref().to_path_buf()
    } else {
        restriction.path().join(path.as_ref())
    };

    let canonicalized = PathHistory::<Raw>::new(target_path).canonicalize()?;

    let validated_path = canonicalized.boundary_check(&restriction.path)?;

    Ok(StrictPath::new(
        Arc::new(restriction.clone()),
        validated_path,
    ))
}

/// A path boundary that serves as the secure foundation for validated path operations.
///
/// Represent the trusted filesystem boundary directory for all strict and virtual path
/// operations. All `StrictPath`/`VirtualPath` values derived from a `PathBoundary` are
/// guaranteed to remain within this boundary.
///
/// # Examples
///
/// ```rust
/// # use strict_path::PathBoundary;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let data_dir = PathBoundary::<()>::try_new_create("./data")?;
/// // Untrusted input from request/CLI/config/etc.
/// let requested_file = "logs/app.log";
/// let file = data_dir.strict_join(requested_file)?;
/// let file_display = file.strictpath_display();
/// println!("{file_display}");
/// # Ok(())
/// # }
/// ```
#[must_use = "a PathBoundary is validated and ready to enforce path restrictions — call .strict_join() to validate untrusted input, .into_strictpath() to get the boundary path, or pass to functions that accept &PathBoundary<Marker>"]
#[doc(alias = "jail")]
#[doc(alias = "chroot")]
#[doc(alias = "sandbox")]
#[doc(alias = "sanitize")]
#[doc(alias = "boundary")]
pub struct PathBoundary<Marker = ()> {
    path: Arc<PathHistory<((Raw, Canonicalized), Exists)>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Clone for PathBoundary<Marker> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Marker> Eq for PathBoundary<Marker> {}

impl<M1, M2> PartialEq<PathBoundary<M2>> for PathBoundary<M1> {
    #[inline]
    fn eq(&self, other: &PathBoundary<M2>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> std::hash::Hash for PathBoundary<Marker> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<Marker> PartialOrd for PathBoundary<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for PathBoundary<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path().cmp(other.path())
    }
}

#[cfg(feature = "virtual-path")]
impl<M1, M2> PartialEq<crate::validator::virtual_root::VirtualRoot<M2>> for PathBoundary<M1> {
    #[inline]
    fn eq(&self, other: &crate::validator::virtual_root::VirtualRoot<M2>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> PartialEq<Path> for PathBoundary<Marker> {
    #[inline]
    fn eq(&self, other: &Path) -> bool {
        self.path() == other
    }
}

impl<Marker> PartialEq<std::path::PathBuf> for PathBoundary<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::PathBuf) -> bool {
        self.eq(other.as_path())
    }
}

impl<Marker> PartialEq<&std::path::Path> for PathBoundary<Marker> {
    #[inline]
    fn eq(&self, other: &&std::path::Path) -> bool {
        self.eq(*other)
    }
}

impl<Marker> PathBoundary<Marker> {
    /// Creates a new `PathBoundary` anchored at `restriction_path` (which must already exist and be a directory).
    ///
    /// Create a boundary anchored at an existing directory (must exist and be a directory).
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: Boundary directory is missing, not a directory, or cannot be canonicalized.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let data_dir = PathBoundary::<()>::try_new("./data")?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "this returns a Result containing the validated PathBoundary — handle the Result to detect invalid boundary directories"]
    #[inline]
    pub fn try_new<P: AsRef<Path>>(restriction_path: P) -> Result<Self> {
        let restriction_path = restriction_path.as_ref();
        let raw = PathHistory::<Raw>::new(restriction_path);

        let canonicalized = raw.canonicalize()?;

        let verified_exists = match canonicalized.verify_exists() {
            Some(path) => path,
            None => {
                let io = IoError::new(
                    ErrorKind::NotFound,
                    "The specified PathBoundary path does not exist.",
                );
                return Err(StrictPathError::invalid_restriction(
                    restriction_path.to_path_buf(),
                    io,
                ));
            }
        };

        if !verified_exists.is_dir() {
            let error = IoError::new(
                ErrorKind::InvalidInput,
                "The specified PathBoundary path exists but is not a directory.",
            );
            return Err(StrictPathError::invalid_restriction(
                restriction_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            path: Arc::new(verified_exists),
            _marker: PhantomData,
        })
    }

    /// Creates the directory if missing, then constructs a new `PathBoundary`.
    ///
    /// Ensure the boundary directory exists (create if missing) and construct a new boundary.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: Directory creation/canonicalization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let data_dir = PathBoundary::<()>::try_new_create("./data")?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "this returns a Result containing the validated PathBoundary — handle the Result to detect invalid boundary directories"]
    pub fn try_new_create<P: AsRef<Path>>(boundary_dir: P) -> Result<Self> {
        let boundary_path = boundary_dir.as_ref();
        if !boundary_path.exists() {
            std::fs::create_dir_all(boundary_path).map_err(|e| {
                StrictPathError::invalid_restriction(boundary_path.to_path_buf(), e)
            })?;
        }
        Self::try_new(boundary_path)
    }

    /// Join a candidate path to the boundary and return a validated `StrictPath`.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathResolutionError`, `StrictPathError::PathEscapesBoundary`.
    #[must_use = "strict_join() validates untrusted input against the boundary — always handle the Result to detect path traversal attacks"]
    #[inline]
    pub fn strict_join(&self, candidate_path: impl AsRef<Path>) -> Result<StrictPath<Marker>> {
        canonicalize_and_enforce_restriction_boundary(candidate_path, self)
    }

    /// Consume this boundary and substitute a new marker type.
    ///
    /// Mirrors [`crate::StrictPath::change_marker`] and [`crate::VirtualPath::change_marker`], enabling
    /// marker transformation after authorization checks. Use this when encoding proven
    /// authorization into the type system (e.g., after validating a user's permissions).
    /// The consumption makes marker changes explicit during code review.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// struct ReadOnly;
    /// struct ReadWrite;
    ///
    /// let read_only_dir: PathBoundary<ReadOnly> = PathBoundary::try_new_create("./data")?;
    ///
    /// // After authorization check...
    /// let write_access_dir: PathBoundary<ReadWrite> = read_only_dir.change_marker();
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "change_marker() consumes self — the original PathBoundary is moved; use the returned PathBoundary<NewMarker>"]
    #[inline]
    pub fn change_marker<NewMarker>(self) -> PathBoundary<NewMarker> {
        PathBoundary {
            path: self.path,
            _marker: PhantomData,
        }
    }

    /// Consume this boundary and return a `StrictPath` anchored at the boundary directory.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathResolutionError`: Canonicalization fails (directory removed or inaccessible).
    /// - `StrictPathError::PathEscapesBoundary`: Guard against race conditions that move the directory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// let data_dir: PathBoundary = PathBoundary::try_new_create("./data")?;
    /// let data_path: StrictPath = data_dir.into_strictpath()?;
    /// assert!(data_path.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "into_strictpath() consumes the PathBoundary — use the returned StrictPath for I/O operations"]
    #[inline]
    pub fn into_strictpath(self) -> Result<StrictPath<Marker>> {
        let root_history = self.path.clone();
        let validated = PathHistory::<Raw>::new(root_history.as_ref().to_path_buf())
            .canonicalize()?
            .boundary_check(root_history.as_ref())?;
        Ok(StrictPath::new(Arc::new(self), validated))
    }

    /// Returns the canonicalized PathBoundary directory path. Kept crate-private to avoid leaking raw path.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Internal: returns the canonicalized PathHistory of the PathBoundary directory for boundary checks.
    #[cfg(feature = "virtual-path")]
    #[inline]
    pub(crate) fn stated_path(&self) -> &PathHistory<((Raw, Canonicalized), Exists)> {
        &self.path
    }

    /// Returns true if the PathBoundary directory exists.
    ///
    /// This is always true for a constructed PathBoundary, but we query the filesystem for robustness.
    #[must_use]
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Return the boundary directory path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop (no allocation).
    #[must_use = "pass interop_path() directly to third-party APIs requiring AsRef<Path> — never wrap it in Path::new() or PathBuf::from() as that defeats boundary safety"]
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }

    /// Returns a Display wrapper that shows the PathBoundary directory system path.
    #[must_use = "strictpath_display() shows the real system path (admin/debug use) — for user-facing output prefer VirtualPath::virtualpath_display() which hides internal paths"]
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path().display()
    }

    /// Return filesystem metadata for the boundary directory.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(self.path())
    }

    /// Create a symbolic link at `link_path` pointing to this boundary's directory.
    ///
    pub fn strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(std::io::Error::other)?;

        root.strict_symlink(link_path)
    }

    /// Create a hard link at `link_path` pointing to this boundary's directory.
    ///
    /// Accepts the same `link_path: impl AsRef<Path>` parameter as `strict_symlink` and returns `io::Result<()>`.
    pub fn strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(std::io::Error::other)?;

        root.strict_hard_link(link_path)
    }

    /// Create a Windows NTFS directory junction at `link_path` pointing to this boundary's directory.
    ///
    /// - Windows-only and behind the `junctions` crate feature.
    /// - Junctions are directory-only.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn strict_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(std::io::Error::other)?;

        root.strict_junction(link_path)
    }

    /// Read directory entries under the boundary directory (discovery only).
    #[inline]
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(self.path())
    }

    /// Iterate directory entries under the boundary, yielding validated `StrictPath` values.
    ///
    /// Unlike `read_dir()` which returns raw `std::fs::DirEntry` values requiring manual
    /// re-validation, this method yields `StrictPath` entries directly. Each entry is
    /// automatically validated through `strict_join()` so you can use it immediately
    /// for I/O operations without additional validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// # let temp = tempfile::tempdir()?;
    /// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// # data_dir.strict_join("file.txt")?.write("test")?;
    ///
    /// // Auto-validated iteration - no manual re-join needed!
    /// for entry in data_dir.strict_read_dir()? {
    ///     let child = entry?;
    ///     println!("Found: {}", child.strictpath_display());
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn strict_read_dir(&self) -> std::io::Result<BoundaryReadDir<'_, Marker>> {
        Ok(BoundaryReadDir {
            inner: std::fs::read_dir(self.path())?,
            boundary: self,
        })
    }

    /// Remove the boundary directory (non-recursive); fails if not empty.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(self.path())
    }

    /// Recursively remove the boundary directory and its contents.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.path())
    }

    /// Convert this boundary into a `VirtualRoot` for virtual path operations.
    #[must_use = "virtualize() consumes self — use the returned VirtualRoot for virtual path operations (.virtual_join(), .into_virtualpath())"]
    #[cfg(feature = "virtual-path")]
    #[inline]
    pub fn virtualize(self) -> crate::VirtualRoot<Marker> {
        crate::VirtualRoot {
            root: self,
            _marker: PhantomData,
        }
    }

    // Note: Do not add new crate-private helpers unless necessary; use existing flows.
}

impl<Marker> std::fmt::Debug for PathBoundary<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathBoundary")
            .field("path", &self.path.as_ref())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

impl<Marker: Default> std::str::FromStr for PathBoundary<Marker> {
    type Err = crate::StrictPathError;

    /// Parse a `PathBoundary` from a string path, validating that it already
    /// exists as a directory.
    ///
    /// WHY VALIDATE-ONLY: When `PathBoundary` is parsed from untrusted input
    /// (serde deserialization of a config file, a CLI flag, an environment
    /// variable), the string controls which directory on disk is created. A
    /// `FromStr` that eagerly calls `create_dir_all` would let an attacker who
    /// controls that string touch any directory the process has write access
    /// to. `from_str` intentionally does not create anything; use
    /// [`PathBoundary::try_new_create`] explicitly when directory creation is
    /// the desired side effect.
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let tmp = tempfile::tempdir()?;
    /// # let p = tmp.path().to_string_lossy().to_string();
    /// let data_dir: PathBoundary<()> = p.parse()?;
    /// assert!(data_dir.exists());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_new(path)
    }
}

// ============================================================
// BoundaryReadDir — Iterator for validated directory entries
// ============================================================

/// Iterator over directory entries that yields validated `StrictPath` values.
///
/// Created by `PathBoundary::strict_read_dir()`. Each iteration automatically validates
/// the directory entry through `strict_join()`, so you get `StrictPath` values directly
/// instead of raw `std::fs::DirEntry` that would require manual re-validation.
///
/// # Examples
///
/// ```rust
/// # use strict_path::PathBoundary;
/// # let temp = tempfile::tempdir()?;
/// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
/// # data_dir.strict_join("readme.md")?.write("# Docs")?;
/// for entry in data_dir.strict_read_dir()? {
///     let child = entry?;
///     if child.is_file() {
///         println!("File: {}", child.strictpath_display());
///     }
/// }
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct BoundaryReadDir<'a, Marker> {
    inner: std::fs::ReadDir,
    boundary: &'a PathBoundary<Marker>,
}

impl<Marker> std::fmt::Debug for BoundaryReadDir<'_, Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundaryReadDir")
            .field("boundary", &self.boundary.strictpath_display())
            .finish_non_exhaustive()
    }
}

impl<Marker: Clone> Iterator for BoundaryReadDir<'_, Marker> {
    type Item = std::io::Result<crate::StrictPath<Marker>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(entry) => {
                let file_name = entry.file_name();
                match self.boundary.strict_join(file_name) {
                    Ok(strict_path) => Some(Ok(strict_path)),
                    Err(e) => Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))),
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
//
