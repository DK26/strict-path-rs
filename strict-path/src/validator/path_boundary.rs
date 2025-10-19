// Content copied from original src/validator/restriction.rs
use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::*;
use crate::Result;

use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "tempfile")]
use tempfile::TempDir;

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
/// // Use the public API that exercises the same validation pipeline
/// // as this internal helper.
/// let file = boundary.strict_join("sub/file.txt")?;
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
/// let file = boundary.strict_join("logs/app.log")?;
/// println!("{}", file.strictpath_display());
/// # Ok(())
/// # }
/// ```
pub struct PathBoundary<Marker = ()> {
    path: Arc<PathHistory<((Raw, Canonicalized), Exists)>>,
    #[cfg(feature = "tempfile")]
    _temp_dir: Option<Arc<TempDir>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Clone for PathBoundary<Marker> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            #[cfg(feature = "tempfile")]
            _temp_dir: self._temp_dir.clone(),
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
    /// Private constructor that allows setting the temp_dir during construction
    #[cfg(feature = "tempfile")]
    fn new_with_temp_dir(
        path: Arc<PathHistory<((Raw, Canonicalized), Exists)>>,
        temp_dir: Option<Arc<TempDir>>,
    ) -> Self {
        Self {
            path,
            _temp_dir: temp_dir,
            _marker: PhantomData,
        }
    }

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
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let tmp_dir = tempfile::tempdir()?;
    /// let tmp_dir = PathBoundary::<()>::try_new(tmp_dir)?; // Clean variable shadowing
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

        #[cfg(feature = "tempfile")]
        {
            Ok(Self::new_with_temp_dir(Arc::new(verified_exists), None))
        }
        #[cfg(not(feature = "tempfile"))]
        {
            Ok(Self {
                path: Arc::new(verified_exists),
                _marker: PhantomData,
            })
        }
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
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let tmp_dir = tempfile::tempdir()?;
    /// let tmp_dir = PathBoundary::<()>::try_new_create(tmp_dir)?; // Clean variable shadowing
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
    /// # let boundary_dir = std::env::temp_dir().join("change-marker-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// struct ReadOnly;
    /// struct ReadWrite;
    ///
    /// let read_boundary: PathBoundary<ReadOnly> = PathBoundary::try_new(&boundary_dir)?;
    ///
    /// // After authorization check...
    /// let write_boundary: PathBoundary<ReadWrite> = read_boundary.change_marker();
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn change_marker<NewMarker>(self) -> PathBoundary<NewMarker> {
        PathBoundary {
            path: self.path,
            #[cfg(feature = "tempfile")]
            _temp_dir: self._temp_dir,
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
    /// # let boundary_dir = std::env::temp_dir().join("into-strictpath-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// let boundary_path: StrictPath = boundary.into_strictpath()?;
    /// assert!(boundary_path.is_dir());
    /// # std::fs::remove_dir_all(&boundary_dir)?;
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

    /// Internal helper: exposes the tempfile RAII handle so `VirtualRoot` constructors can mirror cleanup semantics when constructed from temporary directories.
    #[cfg(feature = "tempfile")]
    #[inline]
    pub(crate) fn temp_dir_arc(&self) -> Option<Arc<TempDir>> {
        self._temp_dir.clone()
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
            #[cfg(feature = "tempfile")]
            _temp_dir: None,
            _marker: PhantomData,
        }
    }

    // Note: Do not add new crate-private helpers unless necessary; use existing flows.

    // OS Standard Directory Constructors
    //
    // These constructors provide secure access to operating system standard directories
    // following platform-specific conventions (XDG on Linux, Known Folder API on Windows,
    // Apple Standard Directories on macOS). Each creates an app-specific subdirectory
    // and enforces path boundaries for secure file operations.

    /// Creates a PathBoundary in the OS standard config directory for the given application.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `~/.config/{app_name}` (XDG Base Directory Specification)
    /// - **Windows**: `%APPDATA%\{app_name}` (Known Folder API - Roaming AppData)
    /// - **macOS**: `~/Library/Application Support/{app_name}` (Apple Standard Directories)
    ///
    /// Respects environment variables like `$XDG_CONFIG_HOME` on Linux systems.
    #[cfg(feature = "dirs")]
    pub fn try_new_os_config(app_name: &str) -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-config".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS config directory not available",
                ),
            })?
            .join(app_name);
        Self::try_new_create(config_dir)
    }

    /// Creates a PathBoundary in the OS standard data directory for the given application.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `~/.local/share/{app_name}` (XDG Base Directory Specification)
    /// - **Windows**: `%APPDATA%\{app_name}` (Known Folder API - Roaming AppData)
    /// - **macOS**: `~/Library/Application Support/{app_name}` (Apple Standard Directories)
    ///
    /// Respects environment variables like `$XDG_DATA_HOME` on Linux systems.
    #[cfg(feature = "dirs")]
    pub fn try_new_os_data(app_name: &str) -> Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-data".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS data directory not available",
                ),
            })?
            .join(app_name);
        Self::try_new_create(data_dir)
    }

    /// Creates a PathBoundary in the OS standard cache directory for the given application.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `~/.cache/{app_name}` (XDG Base Directory Specification)
    /// - **Windows**: `%LOCALAPPDATA%\{app_name}` (Known Folder API - Local AppData)
    /// - **macOS**: `~/Library/Caches/{app_name}` (Apple Standard Directories)
    ///
    /// Respects environment variables like `$XDG_CACHE_HOME` on Linux systems.
    #[cfg(feature = "dirs")]
    pub fn try_new_os_cache(app_name: &str) -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-cache".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS cache directory not available",
                ),
            })?
            .join(app_name);
        Self::try_new_create(cache_dir)
    }

    /// Creates a PathBoundary in the OS local config directory (non-roaming on Windows).
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `~/.config/{app_name}` (same as config_dir)
    /// - **Windows**: `%LOCALAPPDATA%\{app_name}` (Known Folder API - Local AppData)
    /// - **macOS**: `~/Library/Application Support/{app_name}` (same as config_dir)
    #[cfg(feature = "dirs")]
    pub fn try_new_os_config_local(app_name: &str) -> Result<Self> {
        let config_dir = dirs::config_local_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-config-local".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS local config directory not available",
                ),
            })?
            .join(app_name);
        Self::try_new_create(config_dir)
    }

    /// Creates a PathBoundary in the OS local data directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `~/.local/share/{app_name}` (same as data_dir)
    /// - **Windows**: `%LOCALAPPDATA%\{app_name}` (Known Folder API - Local AppData)
    /// - **macOS**: `~/Library/Application Support/{app_name}` (same as data_dir)
    #[cfg(feature = "dirs")]
    pub fn try_new_os_data_local(app_name: &str) -> Result<Self> {
        let data_dir = dirs::data_local_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-data-local".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS local data directory not available",
                ),
            })?
            .join(app_name);
        Self::try_new_create(data_dir)
    }

    /// Creates a PathBoundary in the user's home directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME`
    /// - **Windows**: `%USERPROFILE%` (e.g., `C:\Users\Username`)
    /// - **macOS**: `$HOME`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_home() -> Result<Self> {
        let home_dir =
            dirs::home_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-home".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS home directory not available",
                ),
            })?;
        Self::try_new(home_dir)
    }

    /// Creates a PathBoundary in the user's desktop directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Desktop` or XDG_DESKTOP_DIR
    /// - **Windows**: `%USERPROFILE%\Desktop`
    /// - **macOS**: `$HOME/Desktop`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_desktop() -> Result<Self> {
        let desktop_dir =
            dirs::desktop_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-desktop".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS desktop directory not available",
                ),
            })?;
        Self::try_new(desktop_dir)
    }

    /// Creates a PathBoundary in the user's documents directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Documents` or XDG_DOCUMENTS_DIR
    /// - **Windows**: `%USERPROFILE%\Documents`
    /// - **macOS**: `$HOME/Documents`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_documents() -> Result<Self> {
        let docs_dir =
            dirs::document_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-documents".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS documents directory not available",
                ),
            })?;
        Self::try_new(docs_dir)
    }

    /// Creates a PathBoundary in the user's downloads directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Downloads` or XDG_DOWNLOAD_DIR
    /// - **Windows**: `%USERPROFILE%\Downloads`
    /// - **macOS**: `$HOME/Downloads`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_downloads() -> Result<Self> {
        let downloads_dir =
            dirs::download_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-downloads".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS downloads directory not available",
                ),
            })?;
        Self::try_new(downloads_dir)
    }

    /// Creates a PathBoundary in the user's pictures directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Pictures` or XDG_PICTURES_DIR
    /// - **Windows**: `%USERPROFILE%\Pictures`
    /// - **macOS**: `$HOME/Pictures`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_pictures() -> Result<Self> {
        let pictures_dir =
            dirs::picture_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-pictures".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS pictures directory not available",
                ),
            })?;
        Self::try_new(pictures_dir)
    }

    /// Creates a PathBoundary in the user's music/audio directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Music` or XDG_MUSIC_DIR
    /// - **Windows**: `%USERPROFILE%\Music`
    /// - **macOS**: `$HOME/Music`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_audio() -> Result<Self> {
        let audio_dir =
            dirs::audio_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-audio".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS audio directory not available",
                ),
            })?;
        Self::try_new(audio_dir)
    }

    /// Creates a PathBoundary in the user's videos directory.
    ///
    /// **Cross-Platform Behavior:**
    /// - **Linux**: `$HOME/Videos` or XDG_VIDEOS_DIR  
    /// - **Windows**: `%USERPROFILE%\Videos`
    /// - **macOS**: `$HOME/Movies`
    #[cfg(feature = "dirs")]
    pub fn try_new_os_videos() -> Result<Self> {
        let videos_dir =
            dirs::video_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-videos".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS videos directory not available",
                ),
            })?;
        Self::try_new(videos_dir)
    }

    /// Creates a PathBoundary in the OS executable directory (Linux only).
    ///
    /// **Platform Availability:**
    /// - **Linux**: `~/.local/bin` or $XDG_BIN_HOME
    /// - **Windows**: Returns error (not available)
    /// - **macOS**: Returns error (not available)
    #[cfg(feature = "dirs")]
    pub fn try_new_os_executables() -> Result<Self> {
        let exec_dir =
            dirs::executable_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-executables".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS executables directory not available on this platform",
                ),
            })?;
        Self::try_new(exec_dir)
    }

    /// Creates a PathBoundary in the OS runtime directory (Linux only).
    ///
    /// **Platform Availability:**
    /// - **Linux**: `$XDG_RUNTIME_DIR` (session-specific, user-only access)
    /// - **Windows**: Returns error (not available)
    /// - **macOS**: Returns error (not available)
    #[cfg(feature = "dirs")]
    pub fn try_new_os_runtime() -> Result<Self> {
        let runtime_dir =
            dirs::runtime_dir().ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-runtime".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS runtime directory not available on this platform",
                ),
            })?;
        Self::try_new(runtime_dir)
    }

    /// Creates a PathBoundary in the OS state directory (Linux only).
    ///
    /// **Platform Availability:**
    /// - **Linux**: `~/.local/state/{app_name}` or $XDG_STATE_HOME/{app_name}
    /// - **Windows**: Returns error (not available)
    /// - **macOS**: Returns error (not available)
    #[cfg(feature = "dirs")]
    pub fn try_new_os_state(app_name: &str) -> Result<Self> {
        let state_dir = dirs::state_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "os-state".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "OS state directory not available on this platform",
                ),
            })?
            .join(app_name);
        Self::try_new_create(state_dir)
    }

    /// Creates a PathBoundary in a unique temporary directory with RAII cleanup.
    ///
    /// Returns a `StrictPath` pointing to the temporary boundary directory. The
    /// directory will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempfile")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Get a validated temp directory path directly
    /// let temp_boundary = PathBoundary::<()>::try_new_temp()?;
    /// let user_input = "uploads/document.pdf";
    /// let validated_path = temp_boundary.strict_join(user_input)?; // Returns StrictPath
    /// // Ensure parent directories exist before writing
    /// validated_path.create_parent_dir_all()?;
    /// validated_path.write(b"content")?; // Prefer strict-path helpers over std::fs
    /// // temp_boundary is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tempfile")]
    pub fn try_new_temp() -> Result<Self> {
        let temp_dir =
            tempfile::tempdir().map_err(|e| crate::StrictPathError::InvalidRestriction {
                restriction: "temp".into(),
                source: e,
            })?;

        let temp_path = temp_dir.path();
        let raw = PathHistory::<Raw>::new(temp_path);
        let canonicalized = raw.canonicalize()?;
        let verified_exists = canonicalized.verify_exists().ok_or_else(|| {
            crate::StrictPathError::InvalidRestriction {
                restriction: "temp".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Temp directory verification failed",
                ),
            }
        })?;

        Ok(Self::new_with_temp_dir(
            Arc::new(verified_exists),
            Some(Arc::new(temp_dir)),
        ))
    }

    /// Creates a PathBoundary in a temporary directory with a custom prefix and RAII cleanup.
    ///
    /// Returns a `StrictPath` pointing to the prefixed temporary boundary directory. The
    /// directory will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempfile")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Get a validated temp directory path with session prefix
    /// let upload_boundary = PathBoundary::<()>::try_new_temp_with_prefix("upload_batch")?;
    /// let user_file = upload_boundary.strict_join("user_document.pdf")?; // Validate path
    /// // Process validated path with direct filesystem operations
    /// // upload_boundary is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tempfile")]
    pub fn try_new_temp_with_prefix(prefix: &str) -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .map_err(|e| crate::StrictPathError::InvalidRestriction {
                restriction: "temp".into(),
                source: e,
            })?;

        let temp_path = temp_dir.path();
        let raw = PathHistory::<Raw>::new(temp_path);
        let canonicalized = raw.canonicalize()?;
        let verified_exists = canonicalized.verify_exists().ok_or_else(|| {
            crate::StrictPathError::InvalidRestriction {
                restriction: "temp".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Temp directory verification failed",
                ),
            }
        })?;

        Ok(Self::new_with_temp_dir(
            Arc::new(verified_exists),
            Some(Arc::new(temp_dir)),
        ))
    }

    /// SUMMARY:
    /// Create a boundary using `app-path` semantics (portable app-relative directory) with optional env override.
    ///
    /// PARAMETERS:
    /// - `subdir` (`AsRef<Path>`): Subdirectory path relative to the executable (or override directory).
    /// - `env_override` (Option<&str>): Optional environment variable name; when present and set,
    ///   its value is used as the base directory instead of the executable directory.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: Created/validated boundary at the resolved app-path location.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: If resolution fails or directory cannot be created/validated.
    ///
    /// EXAMPLE:
    /// ```
    /// # #[cfg(feature = "app-path")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Creates ./config/ relative to executable
    /// let config_restriction = PathBoundary::<()>::try_new_app_path("config", None)?;
    ///
    /// // With environment override (checks MYAPP_CONFIG_DIR first)
    /// let config_restriction = PathBoundary::<()>::try_new_app_path("config", Some("MYAPP_CONFIG_DIR"))?;
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "app-path")]
    pub fn try_new_app_path<P: AsRef<std::path::Path>>(
        subdir: P,
        env_override: Option<&str>,
    ) -> Result<Self> {
        let subdir_path = subdir.as_ref();
        // Resolve the override environment variable name (if provided) to its value.
        // app-path expects the override PATH value, not the variable name.
        let override_value: Option<String> = env_override.and_then(|key| std::env::var(key).ok());
        let app_path = app_path::AppPath::try_with_override(subdir_path, override_value.as_deref())
            .map_err(|e| crate::StrictPathError::InvalidRestriction {
                restriction: format!("app-path: {}", subdir_path.display()).into(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
            })?;

        Self::try_new_create(app_path)
    }

    /// SUMMARY:
    /// Create a boundary using `app-path`, always consulting a specific environment variable first.
    ///
    /// PARAMETERS:
    /// - `subdir` (`AsRef<Path>`): Subdirectory used with `app-path` resolution.
    /// - `env_override` (&str): Environment variable name to check for a base directory.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: New boundary anchored using `app-path` semantics.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: If resolution fails or the directory can't be created/validated.
    #[cfg(feature = "app-path")]
    pub fn try_new_app_path_with_env<P: AsRef<std::path::Path>>(
        subdir: P,
        env_override: &str,
    ) -> Result<Self> {
        let subdir_path = subdir.as_ref();
        Self::try_new_app_path(subdir_path, Some(env_override))
    }
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
    /// let temp_dir = tempfile::tempdir()?;
    /// let safe_path = temp_dir.path().join("safe_dir");
    /// let boundary: PathBoundary<()> = safe_path.to_string_lossy().parse()?;
    /// assert!(safe_path.exists());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_new_create(path)
    }
}
//
