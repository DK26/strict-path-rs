// Content copied from original src/validator/virtual_root.rs
use crate::path::virtual_path::VirtualPath;
use crate::validator::jail::Jail;
use crate::Result;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

#[cfg(feature = "system-jails")]
use std::sync::Arc;

#[cfg(feature = "system-jails")]
use tempfile::TempDir;

/// Virtualizes a path by clamping it to stay within the jail boundary.
///
/// This function performs path normalization and security clamping:
/// - Resolves `..` and `.` components
/// - Clamps parent directory traversals to prevent jail escape
/// - Sanitizes dangerous characters and system paths
/// - Returns a path that is safe to join with the jail root
pub(crate) fn virtualize_to_jail<Marker>(path: impl AsRef<Path>, jail: &Jail<Marker>) -> PathBuf {
    use std::ffi::OsString;
    if path.as_ref().is_absolute() && path.as_ref().starts_with(jail.path()) {
        let mut has_parent_or_cur = false;
        for comp in path.as_ref().components() {
            if matches!(comp, Component::ParentDir | Component::CurDir) {
                has_parent_or_cur = true;
                break;
            }
        }
        if !has_parent_or_cur {
            return path.as_ref().to_path_buf();
        }
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0i32;
    let components = path.as_ref().components();
    let _is_abs_input = path.as_ref().is_absolute();
    #[cfg(unix)]
    let is_abs_input = _is_abs_input;
    for comp in components {
        match comp {
            Component::RootDir | Component::Prefix(_) => continue,
            Component::CurDir => continue,
            Component::ParentDir => {
                if depth > 0 {
                    normalized.pop();
                    depth -= 1;
                }
            }
            Component::Normal(name) => {
                let s = name.to_string_lossy();
                #[cfg(unix)]
                {
                    if is_abs_input && (s == "dev" || s == "proc" || s == "sys") {
                        let mut safe = OsString::from("__external__");
                        safe.push(s.as_ref());
                        normalized.push(safe);
                        depth += 1;
                        continue;
                    }
                }
                let cleaned = s.replace(['\n', ';'], "_");
                if cleaned != s {
                    normalized.push(OsString::from(cleaned));
                    depth += 1;
                    continue;
                }
                normalized.push(name);
                depth += 1;
            }
        }
    }
    jail.path().join(normalized)
}

/// A user-facing virtual root that produces `VirtualPath` values.
#[derive(Clone)]
pub struct VirtualRoot<Marker = ()> {
    jail: Jail<Marker>,
    // Held only to tie RAII of temp directories to the VirtualRoot lifetime
    #[cfg(feature = "system-jails")]
    _temp_dir: Option<Arc<TempDir>>, // mirrors RAII when constructed from temp
    _marker: PhantomData<Marker>,
}

impl<Marker> VirtualRoot<Marker> {
    /// Creates a `VirtualRoot` from an existing directory.
    #[inline]
    pub fn try_new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new(root_path)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates the directory if missing, then returns a `VirtualRoot`.
    #[inline]
    pub fn try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new_create(root_path)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Joins a path to this virtual root, producing a clamped `VirtualPath`.
    ///
    /// Always preserves the virtual root through clamping; input is never rejected.
    #[inline]
    pub fn virtualpath_join<P: AsRef<Path>>(
        &self,
        candidate_path: P,
    ) -> Result<VirtualPath<Marker>> {
        let virtualized = virtualize_to_jail(candidate_path, &self.jail);
        let jailed_path = self.jail.systempath_join(virtualized)?;
        Ok(jailed_path.virtualize())
    }

    /// Returns the underlying jail root as a system path.
    #[inline]
    pub fn path(&self) -> &Path {
        self.jail.path()
    }

    // Convenience constructors for system and temporary directories

    /// Creates a virtual root in the user's config directory for the given application.
    ///
    /// Creates `~/.config/{app_name}` on Linux/macOS or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    /// Provides a sandboxed config environment where applications use standard paths.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "system-jails")] {
    /// use jailed_path::VirtualRoot;
    ///
    /// // Sandbox for app config - app sees normal paths
    /// let config_root = VirtualRoot::<()>::try_new_config("myapp")?;
    /// let settings = config_root.virtualpath_join("settings.toml")?;    // VirtualPath
    /// let themes = config_root.virtualpath_join("themes/dark.css")?;    // App sees normal structure
    /// // Application code doesn't know it's sandboxed in user config dir
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "system-jails")]
    pub fn try_new_config(app_name: &str) -> Result<Self> {
        let jail = crate::Jail::try_new_config(app_name)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates a virtual root in the user's data directory for the given application.
    ///
    /// Creates `~/.local/share/{app_name}` on Linux, `~/Library/Application Support/{app_name}` on macOS,
    /// or `%APPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    /// Provides a sandboxed data environment for application storage.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "system-jails")] {
    /// use jailed_path::VirtualRoot;
    ///
    /// // Sandbox for app data - app sees familiar structure
    /// let data_root = VirtualRoot::<()>::try_new_data("myapp")?;
    /// let database = data_root.virtualpath_join("db/users.sqlite")?;   // VirtualPath
    /// let exports = data_root.virtualpath_join("exports/report.csv")?; // Normal-looking paths
    /// // App manages data without knowing actual location
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "system-jails")]
    pub fn try_new_data(app_name: &str) -> Result<Self> {
        let jail = crate::Jail::try_new_data(app_name)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates a virtual root in the user's cache directory for the given application.
    ///
    /// Creates `~/.cache/{app_name}` on Linux, `~/Library/Caches/{app_name}` on macOS,
    /// or `%LOCALAPPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "system-jails")]
    pub fn try_new_cache(app_name: &str) -> Result<Self> {
        let jail = crate::Jail::try_new_cache(app_name)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates a virtual root using app-path for portable applications.
    ///
    /// Creates a directory relative to the executable location, with optional
    /// environment variable override support for deployment flexibility.
    #[cfg(feature = "portable-jails")]
    pub fn try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<Self> {
        let jail = crate::Jail::try_new_app_path(subdir, env_override)?;
        Ok(Self {
            jail,
            #[cfg(feature = "system-jails")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }
}

impl<Marker> std::fmt::Display for VirtualRoot<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path().display())
    }
}

impl<Marker> AsRef<Path> for VirtualRoot<Marker> {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl<Marker> std::fmt::Debug for VirtualRoot<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualRoot")
            .field("root", &self.path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}
