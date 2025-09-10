// Content copied from original src/validator/jail.rs
use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
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

/// Canonicalize a candidate path and enforce the jail boundary, returning a `JailedPath`.
///
/// What this does:
/// - Windows prefilter: rejects DOS 8.3 short-name segments (e.g., `PROGRA~1`) in relative inputs
///   to avoid aliasing-based escapes before any filesystem calls.
/// - Input interpretation: absolute inputs are validated as-is; relative inputs are joined under
///   the jail root.
/// - Resolution: canonicalizes the composed path, fully resolving `.`/`..`, symlinks/junctions,
///   and platform prefixes.
/// - Boundary enforcement: verifies the canonicalized result is strictly within the jail's
///   canonicalized root; rejects any resolution that would escape the boundary.
/// - Returns: a `JailedPath<Marker>` that borrows the jail and holds the validated system path.
pub(crate) fn canonicalize_and_enforce_jail_boundary<Marker>(
    path: impl AsRef<Path>,
    jail: &Jail<Marker>,
) -> Result<JailedPath<Marker>> {
    #[cfg(windows)]
    {
        let original_user_path = path.as_ref().to_path_buf();
        if !path.as_ref().is_absolute() {
            let mut probe = jail.path().to_path_buf();
            for comp in path.as_ref().components() {
                match comp {
                    Component::CurDir | Component::ParentDir => continue,
                    Component::RootDir | Component::Prefix(_) => continue,
                    Component::Normal(name) => {
                        if is_potential_83_short_name(name) {
                            return Err(JailedPathError::windows_short_name(
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
        jail.path().join(path.as_ref())
    };

    let validated_path = PathHistory::<Raw>::new(target_path)
        .canonicalize()?
        .boundary_check(&jail.path)?;

    Ok(JailedPath::new(Arc::new(jail.clone()), validated_path))
}

/// A system-facing validator that holds the jail root and produces `JailedPath`.
pub struct Jail<Marker = ()> {
    path: Arc<PathHistory<((Raw, Canonicalized), Exists)>>,
    #[cfg(feature = "tempdir")]
    _temp_dir: Option<Arc<TempDir>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Clone for Jail<Marker> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            #[cfg(feature = "tempdir")]
            _temp_dir: self._temp_dir.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Marker> PartialEq for Jail<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> Eq for Jail<Marker> {}

impl<Marker> std::hash::Hash for Jail<Marker> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<Marker> PartialOrd for Jail<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for Jail<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path().cmp(other.path())
    }
}

impl<Marker> PartialEq<crate::validator::virtual_root::VirtualRoot<Marker>> for Jail<Marker> {
    #[inline]
    fn eq(&self, other: &crate::validator::virtual_root::VirtualRoot<Marker>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> PartialEq<Path> for Jail<Marker> {
    #[inline]
    fn eq(&self, other: &Path) -> bool {
        self.path() == other
    }
}

impl<Marker> PartialEq<std::path::PathBuf> for Jail<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::PathBuf) -> bool {
        self.eq(other.as_path())
    }
}

impl<Marker> PartialEq<&std::path::Path> for Jail<Marker> {
    #[inline]
    fn eq(&self, other: &&std::path::Path) -> bool {
        self.eq(*other)
    }
}

impl<Marker> Jail<Marker> {
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

    /// Creates a new `Jail` rooted at `jail_path` (which must already exist and be a directory).
    #[inline]
    pub fn try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self> {
        let jail_path = jail_path.as_ref();
        let raw = PathHistory::<Raw>::new(jail_path);

        let canonicalized = raw.canonicalize()?;

        let verified_exists = match canonicalized.verify_exists() {
            Some(path) => path,
            None => {
                let io = IoError::new(
                    ErrorKind::NotFound,
                    "The specified jail path does not exist.",
                );
                return Err(JailedPathError::invalid_jail(jail_path.to_path_buf(), io));
            }
        };

        if !verified_exists.is_dir() {
            let error = IoError::new(
                ErrorKind::InvalidInput,
                "The specified jail path exists but is not a directory.",
            );
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
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

    /// Creates the directory if missing, then constructs a new `Jail`.
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();
        if !root_path.exists() {
            std::fs::create_dir_all(root_path)
                .map_err(|e| JailedPathError::invalid_jail(root_path.to_path_buf(), e))?;
        }
        Self::try_new(root_path)
    }

    /// Joins a path to this jail root and validates it remains within the jail boundary.
    ///
    /// Accepts absolute or relative inputs; ensures the resulting path remains within the jail.
    #[inline]
    pub fn jailed_join(&self, candidate_path: impl AsRef<Path>) -> Result<JailedPath<Marker>> {
        canonicalize_and_enforce_jail_boundary(candidate_path, self)
    }

    /// Returns the canonicalized jail root path. Kept crate-private to avoid leaking raw path.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Internal: returns the canonicalized PathHistory of the jail root for boundary checks.
    #[inline]
    pub(crate) fn stated_path(&self) -> &PathHistory<((Raw, Canonicalized), Exists)> {
        &self.path
    }

    /// Returns true if the jail root exists.
    ///
    /// This is always true for a constructed Jail, but we query the filesystem for robustness.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Returns the jail root path for interop with `AsRef<Path>` APIs.
    ///
    /// This provides allocation-free, OS-native string access to the jail root
    /// for use with standard library APIs that accept `AsRef<Path>`.
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }

    /// Returns a Display wrapper that shows the jail root system path.
    #[inline]
    pub fn jailedpath_display(&self) -> std::path::Display<'_> {
        self.path().display()
    }

    /// Converts this `Jail` into a `VirtualRoot`.
    ///
    /// This creates a virtual root view of the jail, allowing virtual path operations
    /// that treat the jail root as the virtual filesystem root "/".
    #[inline]
    pub fn virtualize(self) -> crate::VirtualRoot<Marker> {
        crate::VirtualRoot {
            jail: self,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        }
    }

    // Note: Do not add new crate-private helpers unless necessary; use existing flows.

    // Convenience constructors for system and temporary directories

    /// Creates a jail in the user's config directory for the given application.
    ///
    /// Creates `~/.config/{app_name}` on Linux/macOS or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    /// Useful for validating config file paths before direct filesystem access.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "dirs")] {
    /// use jailed_path::Jail;
    ///
    /// // Validate config file paths
    /// let config_jail = Jail::<()>::try_new_config("myapp")?;
    /// let user_config = config_jail.jailed_join("settings.toml")?; // Validate path
    /// std::fs::write(user_config.interop_path(), "key = value")?; // Direct access
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "dirs")]
    pub fn try_new_config(app_name: &str) -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| crate::JailedPathError::InvalidJail {
                jail: "system-config".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system config directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(config_dir)
    }

    /// Creates a jail in the user's data directory for the given application.
    ///
    /// Creates `~/.local/share/{app_name}` on Linux, `~/Library/Application Support/{app_name}` on macOS,
    /// or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "dirs")]
    pub fn try_new_data(app_name: &str) -> Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| crate::JailedPathError::InvalidJail {
                jail: "system-data".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system data directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(data_dir)
    }

    /// Creates a jail in the user's cache directory for the given application.
    ///
    /// Creates `~/.cache/{app_name}` on Linux, `~/Library/Caches/{app_name}` on macOS,
    /// or `%LOCALAPPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "dirs")]
    pub fn try_new_cache(app_name: &str) -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| crate::JailedPathError::InvalidJail {
                jail: "system-cache".into(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No system cache directory found",
                ),
            })?
            .join(app_name);
        Self::try_new_create(cache_dir)
    }

    /// Creates a jail in a unique temporary directory with RAII cleanup.
    ///
    /// Returns a `JailedPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `JailedPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempdir")] {
    /// use jailed_path::Jail;
    ///
    /// // Get a validated temp directory path directly
    /// let temp_root = Jail::<()>::try_new_temp()?;
    /// let user_input = "uploads/document.pdf";
    /// let validated_path = temp_root.jailed_join(user_input)?; // Returns JailedPath
    /// // Ensure parent directories exist before writing
    /// validated_path.create_parent_dir_all()?;
    /// std::fs::write(validated_path.interop_path(), b"content")?; // Direct filesystem access
    /// // temp_root is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tempdir")]
    pub fn try_new_temp() -> Result<Self> {
        let temp_dir = tempfile::tempdir().map_err(|e| crate::JailedPathError::InvalidJail {
            jail: "temp".into(),
            source: e,
        })?;

        let temp_path = temp_dir.path();
        let raw = PathHistory::<Raw>::new(temp_path);
        let canonicalized = raw.canonicalize()?;
        let verified_exists =
            canonicalized
                .verify_exists()
                .ok_or_else(|| crate::JailedPathError::InvalidJail {
                    jail: "temp".into(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Temp directory verification failed",
                    ),
                })?;

        Ok(Self::new_with_temp_dir(
            Arc::new(verified_exists),
            Some(Arc::new(temp_dir)),
        ))
    }

    /// Creates a jail in a temporary directory with a custom prefix and RAII cleanup.
    ///
    /// Returns a `JailedPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `JailedPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempdir")] {
    /// use jailed_path::Jail;
    ///
    /// // Get a validated temp directory path with session prefix
    /// let upload_root = Jail::<()>::try_new_temp_with_prefix("upload_batch")?;
    /// let user_file = upload_root.jailed_join("user_document.pdf")?; // Validate path
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
            .map_err(|e| crate::JailedPathError::InvalidJail {
                jail: "temp".into(),
                source: e,
            })?;

        let temp_path = temp_dir.path();
        let raw = PathHistory::<Raw>::new(temp_path);
        let canonicalized = raw.canonicalize()?;
        let verified_exists =
            canonicalized
                .verify_exists()
                .ok_or_else(|| crate::JailedPathError::InvalidJail {
                    jail: "temp".into(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Temp directory verification failed",
                    ),
                })?;

        Ok(Self::new_with_temp_dir(
            Arc::new(verified_exists),
            Some(Arc::new(temp_dir)),
        ))
    }

    /// Creates a jail using app-path for portable applications.
    ///
    /// Creates a directory relative to the executable location, with optional
    /// environment variable override support for deployment flexibility.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "app-path")] {
    /// use jailed_path::Jail;
    ///
    /// // Creates ./config/ relative to executable
    /// let config_jail = Jail::<()>::try_new_app_path("config", None)?;
    ///
    /// // With environment override (checks MYAPP_CONFIG_DIR first)
    /// let config_jail = Jail::<()>::try_new_app_path("config", Some("MYAPP_CONFIG_DIR"))?;
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "app-path")]
    pub fn try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<Self> {
        let app_path = app_path::AppPath::try_with_override(subdir, env_override).map_err(|e| {
            crate::JailedPathError::InvalidJail {
                jail: format!("app-path: {subdir}").into(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
            }
        })?;

        Self::try_new_create(app_path)
    }
}

impl<Marker> AsRef<Path> for Jail<Marker> {
    #[inline]
    fn as_ref(&self) -> &Path {
        // PathHistory implements AsRef<Path>, so forward to it
        self.path.as_ref()
    }
}

impl<Marker> std::fmt::Debug for Jail<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jail")
            .field("root", &self.path.as_ref())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}
