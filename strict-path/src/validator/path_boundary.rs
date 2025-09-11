// Content copied from original src/validator/restriction.rs
use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::*;
use crate::Result;

#[cfg(windows)]
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "tempdir")]
use tempfile::TempDir;

#[cfg(windows)]
use std::path::Component;

#[cfg(windows)]
fn is_potential_83_short_name(os: &OsStr) -> bool {
    let s = os.to_string_lossy();
    if let Some(pos) = s.find('~') {
        s[pos + 1..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
    } else {
        false
    }
}

/// Canonicalize a candidate path and enforce the PathBoundary boundary, returning a `StrictPath`.
///
/// What this does:
/// - Windows prefilter: rejects DOS 8.3 short-name segments (e.g., `PROGRA~1`) in relative inputs
///   to avoid aliasing-based escapes before any filesystem calls.
/// - Input interpretation: absolute inputs are validated as-is; relative inputs are joined under
///   the PathBoundary root.
/// - Resolution: canonicalizes the composed path, fully resolving `.`/`..`, symlinks/junctions,
///   and platform prefixes.
/// - Boundary enforcement: verifies the canonicalized result is strictly within the PathBoundary's
///   canonicalized root; rejects any resolution that would escape the boundary.
/// - Returns: a `StrictPath<Marker>` that borrows the PathBoundary and holds the validated system path.
pub(crate) fn canonicalize_and_enforce_restriction_boundary<Marker>(
    path: impl AsRef<Path>,
    restriction: &PathBoundary<Marker>,
) -> Result<StrictPath<Marker>> {
    #[cfg(windows)]
    {
        let original_user_path = path.as_ref().to_path_buf();
        if !path.as_ref().is_absolute() {
            let mut probe = restriction.path().to_path_buf();
            for comp in path.as_ref().components() {
                match comp {
                    Component::CurDir | Component::ParentDir => continue,
                    Component::RootDir | Component::Prefix(_) => continue,
                    Component::Normal(name) => {
                        if is_potential_83_short_name(name) {
                            return Err(StrictPathError::windows_short_name(
                                name.to_os_string(),
                                original_user_path,
                                probe.clone(),
                            ));
                        }
                        probe.push(name);
                    }
                }
            }
        }
    }

    let target_path = if path.as_ref().is_absolute() {
        path.as_ref().to_path_buf()
    } else {
        restriction.path().join(path.as_ref())
    };

    let validated_path = PathHistory::<Raw>::new(target_path)
        .canonicalize()?
        .boundary_check(&restriction.path)?;

    Ok(StrictPath::new(
        Arc::new(restriction.clone()),
        validated_path,
    ))
}

/// A path boundary that serves as the secure foundation for validated path operations.
///
/// `PathBoundary` represents the trusted starting point (like `/home/users/alice`) from which
/// all path operations begin. When you call `path_boundary.strict_join("documents/file.txt")`,
/// you're building outward from this secure boundary with validated path construction.
pub struct PathBoundary<Marker = ()> {
    path: Arc<PathHistory<((Raw, Canonicalized), Exists)>>,
    #[cfg(feature = "tempdir")]
    _temp_dir: Option<Arc<TempDir>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Clone for PathBoundary<Marker> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            #[cfg(feature = "tempdir")]
            _temp_dir: self._temp_dir.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Marker> PartialEq for PathBoundary<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> Eq for PathBoundary<Marker> {}

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

impl<Marker> PartialEq<crate::validator::virtual_root::VirtualRoot<Marker>>
    for PathBoundary<Marker>
{
    #[inline]
    fn eq(&self, other: &crate::validator::virtual_root::VirtualRoot<Marker>) -> bool {
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
    #[cfg(feature = "tempdir")]
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

    /// Creates a new `PathBoundary` rooted at `restriction_path` (which must already exist and be a directory).
    ///
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

        #[cfg(feature = "tempdir")]
        {
            Ok(Self::new_with_temp_dir(Arc::new(verified_exists), None))
        }
        #[cfg(not(feature = "tempdir"))]
        {
            Ok(Self {
                path: Arc::new(verified_exists),
                _marker: PhantomData,
            })
        }
    }

    /// Creates the directory if missing, then constructs a new `PathBoundary`.
    ///
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::PathBoundary;
    /// let tmp_dir = tempfile::tempdir()?;
    /// let tmp_dir = PathBoundary::<()>::try_new_create(tmp_dir)?; // Clean variable shadowing
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();
        if !root_path.exists() {
            std::fs::create_dir_all(root_path)
                .map_err(|e| StrictPathError::invalid_restriction(root_path.to_path_buf(), e))?;
        }
        Self::try_new(root_path)
    }

    /// Joins a path to this restrictor root and validates it remains within the restriction boundary.
    ///
    /// Accepts absolute or relative inputs; ensures the resulting path remains within the restriction.
    #[inline]
    pub fn strict_join(&self, candidate_path: impl AsRef<Path>) -> Result<StrictPath<Marker>> {
        canonicalize_and_enforce_restriction_boundary(candidate_path, self)
    }

    /// Returns the canonicalized PathBoundary root path. Kept crate-private to avoid leaking raw path.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Internal: returns the canonicalized PathHistory of the PathBoundary root for boundary checks.
    #[inline]
    pub(crate) fn stated_path(&self) -> &PathHistory<((Raw, Canonicalized), Exists)> {
        &self.path
    }

    /// Returns true if the PathBoundary root exists.
    ///
    /// This is always true for a constructed PathBoundary, but we query the filesystem for robustness.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Returns the PathBoundary root path for interop with `AsRef<Path>` APIs.
    ///
    /// This provides allocation-free, OS-native string access to the PathBoundary root
    /// for use with standard library APIs that accept `AsRef<Path>`.
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }

    /// Returns a Display wrapper that shows the PathBoundary root system path.
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path().display()
    }

    /// Converts this `PathBoundary` into a `VirtualRoot`.
    ///
    /// This creates a virtual root view of the PathBoundary, allowing virtual path operations
    /// that treat the PathBoundary root as the virtual filesystem root "/".
    #[inline]
    pub fn virtualize(self) -> crate::VirtualRoot<Marker> {
        crate::VirtualRoot {
            root: self,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        }
    }

    // Note: Do not add new crate-private helpers unless necessary; use existing flows.

    // Convenience constructors for system and temporary directories

    /// Creates a PathBoundary in the user's config directory for the given application.
    ///
    /// Creates `~/.config/{app_name}` on Linux/macOS or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    /// Useful for validating config file paths before direct filesystem access.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "dirs")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Validate config file paths
    /// let config_restriction = PathBoundary::<()>::try_new_config("myapp")?;
    /// let user_config = config_restriction.strict_join("settings.toml")?; // Validate path
    /// std::fs::write(user_config.interop_path(), "key = value")?; // Direct access
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "dirs")]
    pub fn try_new_config(app_name: &str) -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "system-config".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system config directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(config_dir)
    }

    /// Creates a PathBoundary in the user's data directory for the given application.
    ///
    /// Creates `~/.local/share/{app_name}` on Linux, `~/Library/Application Support/{app_name}` on macOS,
    /// or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "dirs")]
    pub fn try_new_data(app_name: &str) -> Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "system-data".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system data directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(data_dir)
    }

    /// Creates a PathBoundary in the user's cache directory for the given application.
    ///
    /// Creates `~/.cache/{app_name}` on Linux, `~/Library/Caches/{app_name}` on macOS,
    /// or `%LOCALAPPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "dirs")]
    pub fn try_new_cache(app_name: &str) -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| crate::StrictPathError::InvalidRestriction {
                restriction: "system-cache".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system cache directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(cache_dir)
    }

    /// Creates a PathBoundary in a unique temporary directory with RAII cleanup.
    ///
    /// Returns a `StrictPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempdir")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Get a validated temp directory path directly
    /// let temp_root = PathBoundary::<()>::try_new_temp()?;
    /// let user_input = "uploads/document.pdf";
    /// let validated_path = temp_root.strict_join(user_input)?; // Returns StrictPath
    /// // Ensure parent directories exist before writing
    /// validated_path.create_parent_dir_all()?;
    /// std::fs::write(validated_path.interop_path(), b"content")?; // Direct filesystem access
    /// // temp_root is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tempdir")]
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
    /// Returns a `StrictPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempdir")] {
    /// use strict_path::PathBoundary;
    ///
    /// // Get a validated temp directory path with session prefix
    /// let upload_root = PathBoundary::<()>::try_new_temp_with_prefix("upload_batch")?;
    /// let user_file = upload_root.strict_join("user_document.pdf")?; // Validate path
    /// // Process validated path with direct filesystem operations
    /// // upload_root is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tempdir")]
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

    /// Creates a PathBoundary using app-path for portable applications.
    ///
    /// Creates a directory relative to the executable location, with optional
    /// environment variable override support for deployment flexibility.
    ///
    /// # Example
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
    pub fn try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<Self> {
        let app_path = app_path::AppPath::try_with_override(subdir, env_override).map_err(|e| {
            crate::StrictPathError::InvalidRestriction {
                restriction: format!("app-path: {subdir}").into(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
            }
        })?;

        Self::try_new_create(app_path)
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
