// Content copied from original src/validator/virtual_root.rs
use crate::path::virtual_path::VirtualPath;
use crate::validator::path_history::PathHistory;
use crate::PathBoundary;
use crate::Result;
use std::marker::PhantomData;
use std::path::Path;
#[cfg(feature = "tempdir")]
use std::sync::Arc;

// keep feature-gated TempDir RAII field using Arc from std::sync
#[cfg(feature = "tempdir")]
use tempfile::TempDir;

/// A user-facing virtual root that produces `VirtualPath` values.
#[derive(Clone)]
pub struct VirtualRoot<Marker = ()> {
    pub(crate) root: PathBoundary<Marker>,
    // Held only to tie RAII of temp directories to the VirtualRoot lifetime
    #[cfg(feature = "tempdir")]
    pub(crate) _temp_dir: Option<Arc<TempDir>>, // mirrors RAII when constructed from temp
    pub(crate) _marker: PhantomData<Marker>,
}

impl<Marker> VirtualRoot<Marker> {
    // no extra constructors; use PathBoundary::virtualize() or VirtualRoot::try_new
    /// Creates a `VirtualRoot` from an existing directory.
    ///
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::VirtualRoot;
    /// let tmp_dir = tempfile::tempdir()?;
    /// let tmp_dir = VirtualRoot::<()>::try_new(tmp_dir)?; // Clean variable shadowing
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let root = PathBoundary::try_new(root_path)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates the directory if missing, then returns a `VirtualRoot`.
    ///
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::VirtualRoot;
    /// let tmp_dir = tempfile::tempdir()?;
    /// let tmp_dir = VirtualRoot::<()>::try_new_create(tmp_dir)?; // Clean variable shadowing
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let root = PathBoundary::try_new_create(root_path)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Joins a path to this virtual root, producing a clamped `VirtualPath`.
    ///
    /// Preserves the virtual root through clamping and validates against the restriction.
    /// May return an error if resolution (e.g., via symlinks) would escape the restriction.
    #[inline]
    pub fn virtual_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>> {
        // 1) Anchor in virtual space (clamps virtual root and resolves relative parts)
        let user_candidate = candidate_path.as_ref().to_path_buf();
        let anchored = PathHistory::new(user_candidate).canonicalize_anchored(&self.root)?;

        // 2) Boundary-check once against the PathBoundary's canonicalized root (no re-canonicalization)
        let validated = anchored.boundary_check(self.root.stated_path())?;

        // 3) Construct a StrictPath directly and then virtualize
        let jp = crate::path::strict_path::StrictPath::new(
            std::sync::Arc::new(self.root.clone()),
            validated,
        );
        Ok(jp.virtualize())
    }

    /// Returns the underlying path boundary root as a system path.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        self.root.path()
    }

    /// Returns the virtual root path for interop with `AsRef<Path>` APIs.
    ///
    /// This provides allocation-free, OS-native string access to the virtual root
    /// for use with standard library APIs that accept `AsRef<Path>`.
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.root.interop_path()
    }

    /// Returns true if the underlying path boundary root exists.
    #[inline]
    pub fn exists(&self) -> bool {
        self.root.exists()
    }

    /// Returns a reference to the underlying `PathBoundary`.
    ///
    /// This allows access to path boundary-specific operations like `strictpath_display()`
    /// while maintaining the borrowed relationship.
    #[inline]
    pub fn as_unvirtual(&self) -> &PathBoundary<Marker> {
        &self.root
    }

    /// Consumes this `VirtualRoot` and returns the underlying `PathBoundary`.
    ///
    /// This provides symmetry with `PathBoundary::virtualize()` and allows conversion
    /// back to the path boundary representation when virtual semantics are no longer needed.
    #[inline]
    pub fn unvirtual(self) -> PathBoundary<Marker> {
        self.root
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
    /// # #[cfg(feature = "dirs")] {
    /// use strict_path::VirtualRoot;
    ///
    /// // Sandbox for app config - app sees normal paths
    /// let config_root: VirtualRoot = VirtualRoot::try_new_config("myapp")?;
    /// let settings = config_root.virtual_join("settings.toml")?;    // VirtualPath
    /// let themes = config_root.virtual_join("themes/dark.css")?;    // App sees normal structure
    /// // Application code doesn't know it's sandboxed in user config dir
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "dirs")]
    pub fn try_new_config(app_name: &str) -> Result<Self> {
        let root = crate::PathBoundary::try_new_config(app_name)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
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
    /// # #[cfg(feature = "dirs")] {
    /// use strict_path::VirtualRoot;
    ///
    /// // Sandbox for app data - app sees familiar structure
    /// let data_root: VirtualRoot = VirtualRoot::try_new_data("myapp")?;
    /// let database = data_root.virtual_join("db/users.sqlite")?;   // VirtualPath
    /// let exports = data_root.virtual_join("exports/report.csv")?; // Normal-looking paths
    /// // App manages data without knowing actual location
    /// # }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "dirs")]
    pub fn try_new_data(app_name: &str) -> Result<Self> {
        let root = crate::PathBoundary::try_new_data(app_name)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates a virtual root in the user's cache directory for the given application.
    ///
    /// Creates `~/.cache/{app_name}` on Linux, `~/Library/Caches/{app_name}` on macOS,
    /// or `%LOCALAPPDATA%\{app_name}` on Windows.
    /// The application directory is created if it doesn't exist.
    #[cfg(feature = "dirs")]
    pub fn try_new_cache(app_name: &str) -> Result<Self> {
        let root = crate::PathBoundary::try_new_cache(app_name)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
            _temp_dir: None,
            _marker: PhantomData,
        })
    }

    /// Creates a virtual root using app-path for portable applications.
    ///
    /// Creates a directory relative to the executable location, with optional
    /// environment variable override support for deployment flexibility.
    #[cfg(feature = "app-path")]
    pub fn try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<Self> {
        let root = crate::PathBoundary::try_new_app_path(subdir, env_override)?;
        Ok(Self {
            root,
            #[cfg(feature = "tempdir")]
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

impl<Marker> PartialEq for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> Eq for VirtualRoot<Marker> {}

impl<Marker> std::hash::Hash for VirtualRoot<Marker> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<Marker> PartialOrd for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for VirtualRoot<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path().cmp(other.path())
    }
}

impl<Marker> PartialEq<crate::PathBoundary<Marker>> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &crate::PathBoundary<Marker>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> PartialEq<std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::Path) -> bool {
        // Compare as virtual root path (always "/")
        // VirtualRoot represents the virtual "/" regardless of underlying system path
        let other_str = other.to_string_lossy();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        "/" == normalized_other
    }
}

impl<Marker> PartialEq<std::path::PathBuf> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::PathBuf) -> bool {
        self.eq(other.as_path())
    }
}

impl<Marker> PartialEq<&std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &&std::path::Path) -> bool {
        self.eq(*other)
    }
}

impl<Marker> PartialOrd<std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &std::path::Path) -> Option<std::cmp::Ordering> {
        // Compare as virtual root path (always "/")
        let other_str = other.to_string_lossy();

        // Handle empty path specially - "/" is greater than ""
        if other_str.is_empty() {
            return Some(std::cmp::Ordering::Greater);
        }

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        Some("/".cmp(&normalized_other))
    }
}

impl<Marker> PartialOrd<&std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &&std::path::Path) -> Option<std::cmp::Ordering> {
        self.partial_cmp(*other)
    }
}

impl<Marker> PartialOrd<std::path::PathBuf> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &std::path::PathBuf) -> Option<std::cmp::Ordering> {
        self.partial_cmp(other.as_path())
    }
}

impl<Marker: Default> std::str::FromStr for VirtualRoot<Marker> {
    type Err = crate::StrictPathError;

    /// Parse a VirtualRoot from a string path for universal ergonomics.
    ///
    /// Creates the directory if it doesn't exist, enabling seamless integration
    /// with any string-parsing context (clap, config files, environment variables, etc.):
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let temp_dir = tempfile::tempdir()?;
    /// let virtual_path = temp_dir.path().join("virtual_dir");
    /// let vroot: VirtualRoot<()> = virtual_path.to_string_lossy().parse()?;
    /// assert!(virtual_path.exists());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_new_create(path)
    }
}
