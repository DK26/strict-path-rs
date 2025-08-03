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
/// - **Path queries**: `starts_with()`, `starts_with_virtual()`, `ends_with()`, `ends_with_virtual()`, `file_name()`, `extension()`
/// - **String conversion**: `virtual_display()`, `virtual_path_to_string()`, `real_path_to_str()` ⚠️
/// - **Path navigation**: `virtual_join()`, `virtual_parent()`, `virtual_with_file_name()`
/// - **Raw access**: `virtual_path()` ✅, `jail()`, `unjail()` ⚠️
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

    /// Checks if the real path ends with the given suffix.
    ///
    /// **⚠️ Caution**: Operates on real filesystem paths, not virtual paths.
    #[inline]
    pub fn ends_with<P: AsRef<Path>>(&self, suffix: P) -> bool {
        self.path.ends_with(suffix)
    }

    /// Checks if the virtual path ends with the given suffix.
    ///
    /// **✅ Recommended**: Use this for user-facing features like search/filtering.
    #[inline]
    pub fn ends_with_virtual<P: AsRef<Path>>(&self, suffix: P) -> bool {
        self.virtual_path().ends_with(suffix)
    }

    /// Returns virtual path as display string (always forward slashes).
    ///
    /// **Use case**: UI display, logging, APIs that need consistent path format.
    #[inline]
    pub fn virtual_display(&self) -> String {
        let virtual_path = self.virtual_path();
        // Optimize: use Vec for better performance than String
        let components: Vec<&std::ffi::OsStr> =
            virtual_path.components().map(|c| c.as_os_str()).collect();

        if components.is_empty() {
            return "/".to_string();
        }

        let total_len = components
            .iter()
            .map(|c| c.len() + 1) // +1 for the slash
            .sum::<usize>();

        let mut result = String::with_capacity(total_len);
        for component in components {
            result.push('/');
            result.push_str(&component.to_string_lossy());
        }
        result
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

    /// Returns virtual path as `PathBuf` (jail-relative, platform separators).
    ///
    /// **✅ Recommended**: For user-facing path operations. Use `virtual_display()` for consistent forward slashes.
    #[inline]
    pub fn virtual_path(&self) -> PathBuf {
        if let Ok(relative) = self.path.strip_prefix(&*self.jail_root) {
            // Optimize: directly clone the relative path instead of rebuilding component by component
            relative.to_path_buf()
        } else {
            PathBuf::new()
        }
    }

    /// Consumes `JailedPath` and returns the real path as `PathBuf`.
    ///
    /// **⚠️ SECURITY WARNING**: This method exposes the real filesystem path, defeating the purpose
    /// of the jail security model. Use with extreme caution and only when absolutely necessary.
    ///
    /// ## ⚠️ ANTI-PATTERNS TO AVOID:
    ///
    /// ```rust
    /// use jailed_path::PathValidator;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("/tmp/unjail_example1")?;
    /// let validator = PathValidator::<()>::with_jail("/tmp/unjail_example1")?;
    /// let jailed_path = validator.try_path("file.txt")?;
    ///
    /// // ❌ WRONG: Unjailing just to check containment
    /// let real_path = jailed_path.unjail();
    /// let contains_safe = real_path.starts_with("/safe");
    /// // This check will fail because real path is "/tmp/unjail_example1/file.txt", not "/safe/..."
    /// assert!(!contains_safe, "This anti-pattern produces wrong results!");
    ///
    /// // ✅ CORRECT: Use built-in method instead
    /// let jailed_path2 = validator.try_path("file.txt")?;
    /// assert!(jailed_path2.starts_with(validator.jail())); // This works correctly
    /// # std::fs::remove_dir_all("/tmp/unjail_example1").ok();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```rust
    /// use jailed_path::PathValidator;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("/tmp/unjail_example2")?;
    /// let validator = PathValidator::<()>::with_jail("/tmp/unjail_example2")?;
    /// let jailed_path = validator.try_path("file.txt")?;
    ///
    /// // ❌ WRONG: Unjailing just to do file operations
    /// let real_path = jailed_path.unjail();
    /// // This exposes internal filesystem paths and defeats security
    /// println!("Exposed real path: {:?}", real_path);
    ///
    /// // ✅ CORRECT: Use built-in safe operations (create new jailed_path for demo)
    /// let jailed_path2 = validator.try_path("file2.txt")?;
    /// jailed_path2.write_bytes(b"secure content")?; // Stays within security model
    /// let content = jailed_path2.read_bytes()?; // Safe and secure
    /// # std::fs::remove_dir_all("/tmp/unjail_example2").ok();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## ✅ LEGITIMATE USES:
    ///
    /// Only use `unjail()` when you need to:
    /// 1. **Integrate with external crates/APIs** that require `PathBuf` and you consume the path immediately
    /// 2. **Pass to functions** that take `PathBuf` ownership and you won't store the result
    ///
    /// ```rust
    /// use jailed_path::PathValidator;
    ///
    /// fn external_api_that_takes_pathbuf(path: std::path::PathBuf) -> String {
    ///     format!("External API processing: {}", path.display())
    /// }
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("/tmp/legitimate_unjail")?;
    /// let validator = PathValidator::<()>::with_jail("/tmp/legitimate_unjail")?;
    /// let jailed_path = validator.try_path("file.txt")?;
    ///
    /// // ✅ OK: Immediate consumption for external API
    /// let result = external_api_that_takes_pathbuf(jailed_path.unjail());
    /// assert!(result.contains("file.txt"));
    /// # std::fs::remove_dir_all("/tmp/legitimate_unjail").ok();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **For logging/debugging, use the built-in Display/Debug implementations instead:**
    /// ```rust
    /// use jailed_path::PathValidator;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("/tmp/display_example")?;
    /// let validator = PathValidator::<()>::with_jail("/tmp/display_example")?;
    /// let jailed_path = validator.try_path("file.txt")?;
    ///
    /// // ✅ PREFERRED: Use Display (shows virtual path)
    /// println!("Processing file: {}", jailed_path);
    ///
    /// // ✅ PREFERRED: Use Debug (shows virtual path + jail info)
    /// println!("Path details: {:?}", jailed_path);
    /// # std::fs::remove_dir_all("/tmp/display_example").ok();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **Remember**: Once you call `unjail()`, you lose all security guarantees. The returned
    /// `PathBuf` can be used unsafely (e.g., joined with `..` to escape the jail).
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn jail(&self) -> &Path {
        &self.jail_root
    }

    // ---- Path Comparison Methods ----

    /// Checks if the virtual path equals the given string.
    ///
    /// **✅ Recommended**: Use this for user-facing path comparisons.
    /// Compares against the virtual path (what users see), not the real filesystem path.
    ///
    /// # Example
    /// ```rust
    /// # use jailed_path::PathValidator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("temp_jail")?;
    /// let validator = PathValidator::<()>::with_jail("temp_jail")?;
    /// let path = validator.try_path("file.txt")?;
    ///
    /// assert!(path.virtual_path_eq("/file.txt"));
    /// assert!(!path.virtual_path_eq("temp_jail/file.txt")); // Real path comparison would be different
    /// # std::fs::remove_dir_all("temp_jail").ok();
    /// # Ok(())
    /// # }
    /// ```
    pub fn virtual_path_eq<S: AsRef<str>>(&self, other: S) -> bool {
        self.virtual_path_to_string_lossy() == other.as_ref()
    }

    /// Checks if the real filesystem path equals the given string.
    ///
    /// **⚠️ Caution**: Compares against the real filesystem path.
    /// For user-facing comparisons, prefer `virtual_path_eq()`.
    ///
    /// # Example  
    /// ```rust
    /// # use jailed_path::PathValidator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # std::fs::create_dir_all("temp_jail")?;
    /// let validator = PathValidator::<()>::with_jail("temp_jail")?;
    /// let path = validator.try_path("file.txt")?;
    ///
    /// assert!(path.real_path_eq("temp_jail/file.txt"));
    /// assert!(!path.real_path_eq("/file.txt")); // Virtual path comparison would be different
    /// # std::fs::remove_dir_all("temp_jail").ok();
    /// # Ok(())
    /// # }
    /// ```
    pub fn real_path_eq<S: AsRef<str>>(&self, other: S) -> bool {
        self.path.to_str().is_some_and(|s| s == other.as_ref())
    }

    // ---- File System Operations ----

    /// Returns true if the path exists on disk.
    #[inline]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Returns true if the path is a file.
    #[inline]
    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    /// Returns true if the path is a directory.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Returns the metadata for the path.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
    }

    /// Reads the entire contents of a file into a string.
    ///
    /// This is a convenience method that wraps `std::fs::read_to_string`.
    ///
    /// # Errors
    ///
    /// This function will return an error if `path` does not exist, is not a file,
    /// or if the contents are not valid UTF-8.
    #[inline]
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the entire contents of a file into a bytes vector.
    ///
    /// This is a convenience method that wraps `std::fs::read`.
    ///
    /// # Errors
    ///
    /// This function will return an error if `path` does not exist or is not a file.
    #[inline]
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Write a slice of bytes as the entire content of a file.
    ///
    /// This function will create a file if it does not exist, and will entirely
    /// replace its contents if it does.
    ///
    /// This is a convenience method that wraps `std::fs::write`.
    #[inline]
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Write a string as the entire content of a file.
    ///
    /// This function will create a file if it does not exist, and will entirely
    /// replace its contents if it does.
    #[inline]
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Creates a directory at this path, including any parent directories.
    ///
    /// This is a convenience method that wraps `std::fs::create_dir_all`.
    #[inline]
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.path)
    }

    /// Removes a file from the filesystem.
    ///
    /// This is a convenience method that wraps `std::fs::remove_file`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file does not exist or if the user lacks permissions to remove it.
    #[inline]
    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    /// Removes an empty directory.
    ///
    /// This is a convenience method that wraps `std::fs::remove_dir`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the directory does not exist, is not empty, or if the user lacks permissions.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.path)
    }

    /// Removes a directory and all its contents recursively.
    ///
    /// This is a convenience method that wraps `std::fs::remove_dir_all`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the directory does not exist or if the user lacks permissions.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(&self.path)
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
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<Marker> Eq for JailedPath<Marker> {}

impl<Marker> Hash for JailedPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<Marker> PartialOrd for JailedPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for JailedPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl<Marker> PartialEq<PathBuf> for JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &PathBuf) -> bool {
        self.path == *other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for PathBuf {
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        *self == other.path
    }
}

impl<Marker> PartialEq<&PathBuf> for JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &&PathBuf) -> bool {
        self.path == **other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for &PathBuf {
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        **self == other.path
    }
}

impl<Marker> PartialEq<PathBuf> for &JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &PathBuf) -> bool {
        self.path == *other
    }
}

impl<Marker> PartialEq<&JailedPath<Marker>> for PathBuf {
    #[inline]
    fn eq(&self, other: &&JailedPath<Marker>) -> bool {
        *self == other.path
    }
}

impl<Marker> PartialEq<Path> for JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &Path) -> bool {
        self.path == *other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for Path {
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        *self == other.path
    }
}

impl<Marker> PartialEq<&Path> for JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &&Path) -> bool {
        self.path == **other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for &Path {
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        **self == other.path
    }
}

impl<Marker> PartialEq<Path> for &JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &Path) -> bool {
        self.path == *other
    }
}

impl<Marker> PartialEq<&JailedPath<Marker>> for Path {
    #[inline]
    fn eq(&self, other: &&JailedPath<Marker>) -> bool {
        *self == other.path
    }
}

impl<Marker, S> PartialEq<Arc<crate::validator::validated_path::ValidatedPath<S>>>
    for JailedPath<Marker>
{
    #[inline]
    fn eq(&self, other: &Arc<crate::validator::validated_path::ValidatedPath<S>>) -> bool {
        self.path == ***other
    }
}

impl<Marker, S> PartialEq<JailedPath<Marker>>
    for Arc<crate::validator::validated_path::ValidatedPath<S>>
{
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        ***self == other.path
    }
}

// ---- String Comparisons (Real Path) ----

impl<Marker> PartialEq<str> for JailedPath<Marker> {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.path.to_str() == Some(other)
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for str {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        other.path.to_str() == Some(self)
    }
}

impl<Marker> PartialEq<&str> for JailedPath<Marker> {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.path.to_str() == Some(*other)
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for &str {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        other.path.to_str() == Some(*self)
    }
}

impl<Marker> PartialEq<String> for JailedPath<Marker> {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.path.to_str().is_some_and(|s| s == other)
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for String {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        other.path.to_str().is_some_and(|s| s == self)
    }
}

impl<Marker> PartialEq<&String> for JailedPath<Marker> {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &&String) -> bool {
        self.path.to_str().is_some_and(|s| s == *other)
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for &String {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        other.path.to_str().is_some_and(|s| s == *self)
    }
}

impl<Marker> PartialEq<String> for &JailedPath<Marker> {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.path.to_str().is_some_and(|s| s == other)
    }
}

impl<Marker> PartialEq<&JailedPath<Marker>> for String {
    /// Compares against the real filesystem path as string.
    ///
    /// **⚠️ Security Note**: This compares against the real path, not the virtual path.
    /// For user-facing comparisons, consider using `virtual_path_to_string()` explicitly.
    #[inline]
    fn eq(&self, other: &&JailedPath<Marker>) -> bool {
        other.path.to_str().is_some_and(|s| s == self)
    }
}
