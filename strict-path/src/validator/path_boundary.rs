// Content copied from original src/validator/restriction.rs
use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::*;
use crate::Result;

use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

/// SUMMARY:
/// Canonicalize a candidate path and enforce the `PathBoundary` boundary, returning a `StrictPath`.
///
/// PARAMETERS:
/// - `path` (`AsRef<Path>`): Candidate path to validate (absolute or relative).
/// - `restriction` (&`PathBoundary<Marker>`): Boundary to enforce during resolution.
///
/// RETURNS:
/// - `Result<StrictPath<Marker>>`: Canonicalized path proven to be within `restriction`.
///
/// ERRORS:
/// - `StrictPathError::PathResolutionError`: Canonicalization fails (I/O or resolution error).
/// - `StrictPathError::PathEscapesBoundary`: Resolved path would escape the boundary.
///
/// EXAMPLE:
/// ```rust
/// # use strict_path::{PathBoundary, Result};
/// # fn main() -> Result<()> {
/// let boundary = PathBoundary::<()>::try_new_create("./sandbox")?;
/// // Untrusted input from request/CLI/config/etc.
/// let user_input = "sub/file.txt";
/// // Use the public API that exercises the same validation pipeline
/// // as this internal helper.
/// let file = boundary.strict_join(user_input)?;
/// assert!(file.interop_path().to_string_lossy().contains("sandbox"));
/// # Ok(())
/// # }
/// ```
pub(crate) fn canonicalize_and_enforce_restriction_boundary<Marker>(
    path: impl AsRef<Path>,
    restriction: &PathBoundary<Marker>,
) -> Result<StrictPath<Marker>> {
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
/// SUMMARY:
/// Represent the trusted filesystem boundary directory for all strict and virtual path
/// operations. All `StrictPath`/`VirtualPath` values derived from a `PathBoundary` are
/// guaranteed to remain within this boundary.
///
/// EXAMPLE:
/// ```rust
/// # use strict_path::PathBoundary;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let boundary = PathBoundary::<()>::try_new_create("./data")?;
/// // Untrusted input from request/CLI/config/etc.
/// let requested_file = "logs/app.log";
/// let file = boundary.strict_join(requested_file)?;
/// println!("{}", file.strictpath_display());
/// # Ok(())
/// # }
/// ```
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
    /// SUMMARY:
    /// Create a boundary anchored at an existing directory (must exist and be a directory).
    ///
    /// PARAMETERS:
    /// - `restriction_path` (`AsRef<Path>`): Existing directory to anchor the boundary.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: New boundary whose directory is canonicalized and verified to exist.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: Boundary directory is missing, not a directory, or cannot be canonicalized.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let boundary = PathBoundary::<()>::try_new("./data")?;
    /// # Ok(())
    /// # }
    /// ```
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
    /// SUMMARY:
    /// Ensure the boundary directory exists (create if missing) and construct a new boundary.
    ///
    /// PARAMETERS:
    /// - `boundary_dir` (`AsRef<Path>`): Directory to create if needed and use as the boundary directory.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: New boundary anchored at `boundary_dir`.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: Directory creation/canonicalization fails.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let boundary = PathBoundary::<()>::try_new_create("./data")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_new_create<P: AsRef<Path>>(boundary_dir: P) -> Result<Self> {
        let boundary_path = boundary_dir.as_ref();
        if !boundary_path.exists() {
            std::fs::create_dir_all(boundary_path).map_err(|e| {
                StrictPathError::invalid_restriction(boundary_path.to_path_buf(), e)
            })?;
        }
        Self::try_new(boundary_path)
    }

    /// SUMMARY:
    /// Join a candidate path to the boundary and return a validated `StrictPath`.
    ///
    /// PARAMETERS:
    /// - `candidate_path` (`AsRef<Path>`): Absolute or relative path to validate within this boundary.
    ///
    /// RETURNS:
    /// - `Result<StrictPath<Marker>>`: Canonicalized, boundary-checked path.
    ///
    /// ERRORS:
    /// - `StrictPathError::PathResolutionError`, `StrictPathError::PathEscapesBoundary`.
    #[inline]
    pub fn strict_join(&self, candidate_path: impl AsRef<Path>) -> Result<StrictPath<Marker>> {
        canonicalize_and_enforce_restriction_boundary(candidate_path, self)
    }

    /// SUMMARY:
    /// Consume this boundary and substitute a new marker type.
    ///
    /// DETAILS:
    /// Mirrors [`crate::StrictPath::change_marker`] and [`crate::VirtualPath::change_marker`], enabling
    /// marker transformation after authorization checks. Use this when encoding proven
    /// authorization into the type system (e.g., after validating a user's permissions).
    /// The consumption makes marker changes explicit during code review.
    ///
    /// PARAMETERS:
    /// - `NewMarker` (type parameter): Marker to associate with the boundary.
    ///
    /// RETURNS:
    /// - `PathBoundary<NewMarker>`: Same underlying boundary, rebranded with `NewMarker`.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// struct ReadOnly;
    /// struct ReadWrite;
    ///
    /// let read_boundary: PathBoundary<ReadOnly> = PathBoundary::try_new_create("./data")?;
    ///
    /// // After authorization check...
    /// let write_boundary: PathBoundary<ReadWrite> = read_boundary.change_marker();
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn change_marker<NewMarker>(self) -> PathBoundary<NewMarker> {
        PathBoundary {
            path: self.path,
            _marker: PhantomData,
        }
    }

    /// SUMMARY:
    /// Consume this boundary and return a `StrictPath` anchored at the boundary directory.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `Result<StrictPath<Marker>>`: Strict path for the canonicalized boundary directory.
    ///
    /// ERRORS:
    /// - `StrictPathError::PathResolutionError`: Canonicalization fails (directory removed or inaccessible).
    /// - `StrictPathError::PathEscapesBoundary`: Guard against race conditions that move the directory.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// let boundary: PathBoundary = PathBoundary::try_new_create("./data")?;
    /// let boundary_path: StrictPath = boundary.into_strictpath()?;
    /// assert!(boundary_path.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
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
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// SUMMARY:
    /// Return the boundary directory path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop (no allocation).
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }

    /// Returns a Display wrapper that shows the PathBoundary directory system path.
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path().display()
    }

    /// SUMMARY:
    /// Return filesystem metadata for the boundary directory.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(self.path())
    }

    /// SUMMARY:
    /// Create a symbolic link at `link_path` pointing to this boundary's directory.
    ///
    /// PARAMETERS:
    /// - `link_path` (`impl AsRef<Path>`): Destination for the symlink, within the same boundary.
    ///
    /// RETURNS:
    /// - `io::Result<()>`: Mirrors std semantics.
    pub fn strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_symlink(link_path)
    }

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this boundary's directory.
    ///
    /// PARAMETERS and RETURNS mirror `strict_symlink`.
    pub fn strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_hard_link(link_path)
    }

    /// SUMMARY:
    /// Create a Windows NTFS directory junction at `link_path` pointing to this boundary's directory.
    ///
    /// DETAILS:
    /// - Windows-only and behind the `junctions` crate feature.
    /// - Junctions are directory-only.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn strict_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let root = self
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_junction(link_path)
    }

    /// SUMMARY:
    /// Read directory entries under the boundary directory (discovery only).
    #[inline]
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(self.path())
    }

    /// SUMMARY:
    /// Remove the boundary directory (non-recursive); fails if not empty.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(self.path())
    }

    /// SUMMARY:
    /// Recursively remove the boundary directory and its contents.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.path())
    }

    /// SUMMARY:
    /// Convert this boundary into a `VirtualRoot` for virtual path operations.
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

impl<Marker> AsRef<Path> for PathBoundary<Marker> {
    #[inline]
    fn as_ref(&self) -> &Path {
        // PathHistory implements AsRef<Path>, so forward to it
        self.path.as_ref()
    }
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

    /// Parse a PathBoundary from a string path for universal ergonomics.
    ///
    /// Creates the directory if it doesn't exist, enabling seamless integration
    /// with any string-parsing context (clap, config files, environment variables, etc.):
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let boundary: PathBoundary<()> = "./data".parse()?;
    /// assert!(boundary.exists());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_new_create(path)
    }
}
//
