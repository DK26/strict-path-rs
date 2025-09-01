// Content copied from original src/validator/jail.rs
use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
use crate::validator::stated_path::*;
use crate::Result;

#[cfg(windows)]
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "system-jails")]
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

pub(crate) fn validate<Marker>(
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

    let validated_path = StatedPath::<Raw>::new(target_path)
        .canonicalize()?
        .boundary_check(jail.path())?;

    Ok(JailedPath::new(Arc::new(jail.clone()), validated_path))
}

/// A system-facing validator that holds the jail root and produces `JailedPath`.
pub struct Jail<Marker = ()> {
    path: Arc<StatedPath<((Raw, Canonicalized), Exists)>>,
    #[cfg(feature = "system-jails")]
    _temp_dir: Option<Arc<TempDir>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Clone for Jail<Marker> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            #[cfg(feature = "system-jails")]
            _temp_dir: self._temp_dir.clone(),
            _marker: PhantomData,
        }
    }
}

impl<Marker> Jail<Marker> {
    /// Private constructor that allows setting the temp_dir during construction
    #[cfg(feature = "system-jails")]
    fn new_with_temp_dir(
        path: Arc<StatedPath<((Raw, Canonicalized), Exists)>>,
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
        let raw = StatedPath::<Raw>::new(jail_path);

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

        #[cfg(feature = "system-jails")]
        {
            Ok(Self::new_with_temp_dir(Arc::new(verified_exists), None))
        }
        #[cfg(not(feature = "system-jails"))]
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
    pub fn systempath_join(&self, candidate_path: impl AsRef<Path>) -> Result<JailedPath<Marker>> {
        validate(candidate_path, self)
    }

    /// Returns the canonicalized jail root path. Exposing this is safe — validation happens in `systempath_join`.
    #[inline]
    pub fn path(&self) -> &StatedPath<((Raw, Canonicalized), Exists)> {
        &self.path
    }

    // Convenience constructors for system and temporary directories

    /// Creates a jail in the user's config directory for the given application.
    ///
    /// Creates `~/.config/{app_name}` on Linux/macOS or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    /// Useful for validating config file paths before direct filesystem access.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "system-jails")] {
    /// use jailed_path::Jail;
    ///
    /// // Validate config file paths
    /// let config_jail = Jail::<()>::try_new_config("myapp")?;
    /// let user_config = config_jail.systempath_join("settings.toml")?; // Validate path
    /// std::fs::write(user_config.systempath_as_os_str(), "key = value")?; // Direct access
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "system-jails")]
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
    #[cfg(feature = "system-jails")]
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
    #[cfg(feature = "system-jails")]
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
    /// # #[cfg(feature = "system-jails")] {
    /// use jailed_path::Jail;
    ///
    /// // Get a validated temp directory path directly
    /// let temp_root = Jail::<()>::try_new_temp()?;
    /// let user_input = "uploads/document.pdf";
    /// let validated_path = temp_root.systempath_join(user_input)?; // Returns JailedPath
    /// // Ensure parent directories exist before writing
    /// validated_path.create_parent_dir_all()?;
    /// std::fs::write(validated_path.systempath_as_os_str(), b"content")?; // Direct filesystem access
    /// // temp_root is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "system-jails")]
    pub fn try_new_temp() -> Result<Self> {
        let temp_dir = tempfile::tempdir().map_err(|e| crate::JailedPathError::InvalidJail {
            jail: "temp".into(),
            source: e,
        })?;

        let temp_path = temp_dir.path();
        let raw = StatedPath::<Raw>::new(temp_path);
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
    /// # #[cfg(feature = "system-jails")] {
    /// use jailed_path::Jail;
    ///
    /// // Get a validated temp directory path with session prefix
    /// let upload_root = Jail::<()>::try_new_temp_with_prefix("upload_batch")?;
    /// let user_file = upload_root.systempath_join("user_document.pdf")?; // Validate path
    /// // Process validated path with direct filesystem operations
    /// // upload_root is dropped here, directory gets cleaned up automatically
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "system-jails")]
    pub fn try_new_temp_with_prefix(prefix: &str) -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .map_err(|e| crate::JailedPathError::InvalidJail {
                jail: "temp".into(),
                source: e,
            })?;

        let temp_path = temp_dir.path();
        let raw = StatedPath::<Raw>::new(temp_path);
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
    /// # #[cfg(feature = "portable-jails")] {
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
    #[cfg(feature = "portable-jails")]
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
        // StatedPath implements AsRef<Path>, so forward to it
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
