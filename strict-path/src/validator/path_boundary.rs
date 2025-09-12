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

#[cfg(feature = "tempfile")]
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
    /// Returns a `StrictPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempfile")] {
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
    /// Returns a `StrictPath` pointing to the temp directory root. The directory
    /// will be automatically cleaned up when the `StrictPath` is dropped.
    ///
    /// # Example
    /// ```
    /// # #[cfg(feature = "tempfile")] {
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
