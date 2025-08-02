use crate::error::JailedPathError;
use crate::validator::validated_path::{
    BoundaryChecked, Canonicalized, Clamped, JoinedJail, Raw, ValidatedPath,
};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::Arc;

// --- Struct Definition ---

/// A validated path guaranteed to be within a jail boundary.
///
/// ## Key Concepts
/// - **Virtual paths**: User-facing paths shown as if the jail root is the filesystem root
/// - **Real paths**: Actual filesystem paths (use with caution - may expose system paths)
/// - **Safety**: All operations prevent path traversal attacks and jail escapes
///
/// ## Display Behavior
/// `Display` and `Debug` show virtual paths with forward slashes, never exposing real system paths.
///
/// ## API Categories
/// - **Path queries**: `starts_with()`, `file_name()`, `extension()`
/// - **String conversion**: `virtual_display()`, `virtual_path_to_string()`, `real_path_to_str()` ⚠️
/// - **Path navigation**: `virtual_join()`, `virtual_parent()`, `virtual_with_file_name()`
/// - **Raw access**: `real_path()` ⚠️, `virtual_path()` ✅, `jail_root()`
/// - **Byte operations**: `to_bytes()`, `into_bytes()` ⚠️
///
/// **Legend**: ⚠️ = Exposes real filesystem paths | ✅ = Recommended for user-facing operations
///
/// ## Example
/// ```rust
/// # use jailed_path::PathValidator;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # std::fs::create_dir_all("temp_jail/data")?;
/// # std::fs::write("temp_jail/data/file.txt", "test")?;
/// let validator = PathValidator::<()>::with_jail("temp_jail")?;
/// let jailed_path = validator.try_path("data/file.txt")?;
///
/// // If jail_root is "temp_jail" and real path is "temp_jail/data/file.txt"
/// // Virtual path shows: "/data/file.txt"
/// println!("{jailed_path}"); // Always shows virtual path with forward slashes
/// # std::fs::remove_dir_all("temp_jail").ok();
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail_root: Arc<ValidatedPath<(Raw, Canonicalized)>>,
    _marker: PhantomData<Marker>,
}

// --- Inherent Methods ---

impl<Marker> JailedPath<Marker> {
    // ---- Construction ----

    /// Creates a new JailedPath from a fully validated ValidatedPath with the exact required type-state.
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        jail_root: Arc<ValidatedPath<(Raw, Canonicalized)>>,
        validated_path: ValidatedPath<(
            (((Raw, Clamped), JoinedJail), Canonicalized),
            BoundaryChecked,
        )>,
    ) -> Self {
        // The validated_path is always fully validated and jail-relative (relative to jail root)
        Self {
            path: validated_path.into_inner(),
            jail_root,
            _marker: PhantomData,
        }
    }

    // ---- Path Queries ----

    /// Checks if the real path starts with the given base.
    ///
    /// **⚠️ Caution**: Operates on real filesystem paths, not virtual paths.
    #[inline]
    pub fn starts_with<P: AsRef<Path>>(&self, base: P) -> bool {
        self.path.starts_with(base)
    }

    /// Checks if the virtual path starts with the given base.
    ///
    /// **✅ Recommended**: Use this for user-facing features like search/filtering.
    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, base: P) -> bool {
        self.virtual_path().starts_with(base)
    }

    /// Returns virtual path as display string (always forward slashes).
    ///
    /// **Use case**: UI display, logging, APIs that need consistent path format.
    #[inline]
    pub fn virtual_display(&self) -> String {
        let pb = self.virtual_path();
        // Always produce forward slashes, even on Windows
        let mut s = String::from("");
        for comp in pb.components() {
            s.push('/');
            s.push_str(&comp.as_os_str().to_string_lossy());
        }
        if s.is_empty() {
            s.push('/');
        }
        s
    }

    /// Returns the file name component, if any.
    #[inline]
    pub fn file_name(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Returns the file extension, if any.
    #[inline]
    pub fn extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    /// Returns the real path as `&OsStr`.
    ///
    /// **⚠️ Caution**: Exposes real filesystem path.
    #[inline]
    pub fn as_os_str(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Returns real path as `&str` if valid UTF-8.
    ///
    /// **⚠️ Caution**: Exposes real filesystem path. For user-facing display, use `virtual_path_to_string()` or `Display`.
    #[inline]
    pub fn real_path_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns real path as `Cow<str>`, replacing invalid UTF-8 with U+FFFD.
    ///
    /// **⚠️ Caution**: Exposes real filesystem path. For user-facing display, use `virtual_path_to_string_lossy()` or `Display`.
    #[inline]
    pub fn real_path_to_string_lossy(&self) -> Cow<'_, str> {
        self.path.to_string_lossy()
    }

    /// Returns virtual path as `String` if valid UTF-8 (platform separators).
    ///  
    /// **✅ Recommended**: For user-facing output. Use `Display` for consistent forward slashes.
    #[inline]
    pub fn virtual_path_to_string(&self) -> Option<String> {
        self.virtual_path().into_os_string().into_string().ok()
    }

    /// Returns virtual path as `String`, replacing invalid UTF-8 with U+FFFD (platform separators).
    ///
    /// **✅ Recommended**: For user-facing output. Use `Display` for consistent forward slashes.
    #[inline]
    pub fn virtual_path_to_string_lossy(&self) -> String {
        self.virtual_path().to_string_lossy().into_owned()
    }

    /// Returns reference to the real filesystem path.
    ///
    /// **⚠️ Caution**: Exposes real filesystem path.
    #[inline]
    pub fn real_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns virtual path as `PathBuf` (jail-relative, platform separators).
    ///
    /// **✅ Recommended**: For user-facing path operations. Use `virtual_display()` for consistent forward slashes.
    pub fn virtual_path(&self) -> PathBuf {
        if let Ok(relative) = self.path.strip_prefix(&*self.jail_root) {
            let mut pb = PathBuf::new();
            for comp in relative.components() {
                match comp {
                    Component::Normal(os) => pb.push(os),
                    Component::CurDir => {}
                    Component::ParentDir => pb.push(".."),
                    _ => {}
                }
            }
            pb
        } else {
            PathBuf::from("")
        }
    }

    /// Consumes `JailedPath` and returns the real path as `PathBuf`.
    ///
    /// **⚠️ Caution**: Returns real filesystem path, not virtual path.
    #[inline]
    pub fn unjail(self) -> PathBuf {
        self.path
    }

    /// Safely joins user path to current virtual path, returns `None` on error.
    ///
    /// **Safety**: Path traversal attacks prevented. Input treated as jail-relative.
    /// **Input**: `"../file.txt"`, `"dir/file.txt"`, `"/abs/path"` (treated as jail-relative)
    /// **Never use**: Real system paths or already-jailed paths as input
    pub fn virtual_join<P: AsRef<Path>>(&self, path: P) -> Option<Self> {
        self.try_virtual_join(path).ok()
    }

    /// Safely joins user path to current virtual path, returns `Result`.
    ///
    /// **Safety**: Path traversal attacks prevented. Input treated as jail-relative.
    /// **Input**: `"../file.txt"`, `"dir/file.txt"`, `"/abs/path"` (treated as jail-relative)
    /// **Never use**: Real system paths or already-jailed paths as input
    /// **Errors**: `JailedPathError` if join fails or result escapes jail
    pub fn try_virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self, JailedPathError> {
        let arg = path.as_ref();

        // Get the current virtual path as PathBuf
        let current_virtual_pb = self.virtual_path();
        // If the virtual path is empty (root), use empty PathBuf, else use as-is
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        // Normalize the user's argument to a virtual path
        // The user operates purely in virtual space - they don't know about real jail paths
        let arg_virtual = if arg.is_absolute() {
            // User provided an absolute path like "/some/path"
            // Treat as jail-relative: strip all root components
            let mut virtual_path = PathBuf::new();
            for comp in arg.components() {
                match comp {
                    Component::RootDir | Component::Prefix(_) => continue,
                    _ => virtual_path.push(comp.as_os_str()),
                }
            }
            virtual_path
        } else {
            // User provided a relative path - use as-is
            arg.to_path_buf()
        };

        // Join in virtual space: current virtual path + user's virtual path
        let virtual_joined = current_virtual.join(arg_virtual);

        // Now validate this virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(virtual_joined)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns parent directory as new `JailedPath`, or `None` if at jail root.
    pub fn virtual_parent(&self) -> Option<Self> {
        self.try_virtual_parent().ok()
    }

    /// Returns parent directory as new `JailedPath`, or error if at jail root.
    ///
    /// **Errors**: `JailedPathError` if already at jail root or canonicalization fails
    pub fn try_virtual_parent(&self) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and find its parent
        let current_virtual_pb = self.virtual_path();
        if current_virtual_pb.as_os_str().is_empty() {
            // Already at root, no parent
            return Err(JailedPathError::path_resolution_error(
                self.path.clone(),
                IoError::new(ErrorKind::NotFound, "No parent - already at jail root"),
            ));
        }
        let current_virtual = current_virtual_pb;

        let parent_virtual = current_virtual.parent().ok_or_else(|| {
            JailedPathError::path_resolution_error(
                self.path.clone(),
                IoError::new(ErrorKind::NotFound, "No parent"),
            )
        })?;

        // Validate this parent virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(parent_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns new `JailedPath` with different file name, or `None` on error.
    pub fn virtual_with_file_name<S: AsRef<OsStr>>(&self, name: S) -> Option<Self> {
        self.try_virtual_with_file_name(name).ok()
    }

    /// Returns new `JailedPath` with different file name, or error.
    ///
    /// **Errors**: `JailedPathError` if operation fails or result escapes jail
    pub fn try_virtual_with_file_name<S: AsRef<OsStr>>(
        &self,
        name: S,
    ) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and change file name
        let current_virtual_pb = self.virtual_path();
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        let new_virtual = current_virtual.with_file_name(name);

        // Validate this new virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(new_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns new `JailedPath` with different extension, or `None` on error.
    pub fn virtual_with_extension<S: AsRef<OsStr>>(&self, ext: S) -> Option<Self> {
        self.try_virtual_with_extension(ext).ok()
    }

    /// Returns new `JailedPath` with different extension, or error.
    ///
    /// **Errors**: `JailedPathError` if path has no filename or operation fails
    pub fn try_virtual_with_extension<S: AsRef<OsStr>>(
        &self,
        ext: S,
    ) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and change extension
        let current_virtual_pb = self.virtual_path();
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        // Check if the current path has a filename - if not, we can't add an extension
        if current_virtual.file_name().is_none() {
            return Err(JailedPathError::PathResolutionError {
                path: current_virtual,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cannot add extension to path without filename",
                ),
            });
        }

        let new_virtual = current_virtual.with_extension(ext);

        // Validate this new virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(new_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns real path as bytes (platform-specific encoding).
    ///
    /// **⚠️ Caution**: Exposes real filesystem path.
    pub fn to_bytes(&self) -> Vec<u8> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.path.as_os_str().as_bytes().to_vec()
        }
        #[cfg(windows)]
        {
            self.path.to_string_lossy().as_bytes().to_vec()
        }
    }

    /// Consumes path and returns real path as bytes (platform-specific encoding).
    ///
    /// **⚠️ Caution**: Exposes real filesystem path.
    pub fn into_bytes(self) -> Vec<u8> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.path.into_os_string().as_bytes().to_vec()
        }
        #[cfg(windows)]
        {
            self.path.to_string_lossy().into_owned().into_bytes()
        }
    }

    /// Returns reference to the jail root path.
    pub fn jail_root(&self) -> &Path {
        &self.jail_root
    }
}

// --- Trait Implementations ---
impl<Marker> fmt::Display for JailedPath<Marker> {
    /// Displays virtual path with forward slashes (user-facing, never exposes real paths).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.virtual_display())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format path and jail_root using platform separator for consistency
        let format_path = |p: &Path| {
            let mut s = String::new();
            for (i, c) in p.components().enumerate() {
                if i > 0 {
                    s.push(MAIN_SEPARATOR);
                }
                s.push_str(&c.as_os_str().to_string_lossy());
            }
            s
        };
        f.debug_struct("JailedPath")
            .field("path", &format_path(&self.path))
            .field("jail_root", &format_path(&self.jail_root))
            .finish()
    }
}

impl<Marker> PartialEq for JailedPath<Marker> {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<Marker> Eq for JailedPath<Marker> {}

impl<Marker> Hash for JailedPath<Marker> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<Marker> PartialOrd for JailedPath<Marker> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for JailedPath<Marker> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl<Marker> PartialEq<PathBuf> for JailedPath<Marker> {
    fn eq(&self, other: &PathBuf) -> bool {
        &self.path == other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for PathBuf {
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        self == &other.path
    }
}

impl<Marker> PartialEq<Path> for JailedPath<Marker> {
    fn eq(&self, other: &Path) -> bool {
        self.path.as_path() == other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for Path {
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        self == other.path.as_path()
    }
}
