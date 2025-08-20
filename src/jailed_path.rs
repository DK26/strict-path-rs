use crate::validator::stated_path::{BoundaryChecked, Canonicalized, Raw, StatedPath};
use crate::{JailedPathError, Result};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// --- Struct Definition ---

/// A validated, system-facing path guaranteed to be within a jail boundary.
///
/// ## Key Concepts
/// - **System-Facing**: This type is intended for direct, low-level interactions with the
///   filesystem, such as file I/O, and for integration with external APIs that require
///   real filesystem paths.
/// - **Real Paths**: All path representations (`Display`, `realpath_to_string`, etc.) refer to the
///   actual, canonicalized path on the filesystem (e.g., `/app/storage/user/file.txt`).
/// - **Safety**: All operations are guaranteed to remain within the jail boundary, preventing
///   path traversal attacks.
///
/// ## Display Behavior
/// - `Display` shows the **real filesystem path**.
/// - `Debug` provides a more detailed view, including the jail root.
///
/// ## For User-Facing Paths
///
/// To display paths to users or perform user-centric path manipulation (where the jail is
/// treated as the root `/`), convert this `JailedPath` into a `VirtualPath` using the
/// explicit `JailedPath::virtualize()` method.
///
/// ## Example
///
/// ```rust
/// # use jailed_path::{Jail, VirtualPath};
/// # use std::fs;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # std::fs::create_dir_all("temp_jail_real")?;
/// let jail = Jail::<()>::try_new("temp_jail_real")?;
/// let jailed_path = jail.try_path("data/file.txt")?;
///
/// // Displaying a JailedPath shows the real, canonicalized path.
/// // Note: The exact output of canonicalization is platform-dependent.
/// assert!(jailed_path.to_string().contains("temp_jail_real"));
///
/// // To show a user-friendly virtual path, convert it.
/// // To show a user-friendly virtual path, convert it explicitly.
/// // Use `JailedPath::virtualize()` rather than implicit `From`/`Into`.
/// // Convert to a user-facing virtual path for display purposes.
/// let virtual_path = jailed_path.virtualize();
/// assert_eq!(virtual_path.to_string(), "/data/file.txt");
///
/// # fs::remove_dir_all("temp_jail_real")?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail: Arc<crate::validator::jail::Jail<Marker>>,
    _marker: PhantomData<Marker>,
}

// --- Inherent Methods ---

impl<Marker> JailedPath<Marker> {
    // ---- Construction ----

    /// Creates a new JailedPath from a fully validated ValidatedPath with the exact required type-state.
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        jail: Arc<crate::validator::jail::Jail<Marker>>,
        validated_path: StatedPath<((Raw, Canonicalized), BoundaryChecked)>,
    ) -> Self {
        Self {
            path: validated_path.into_inner(),
            jail,
            _marker: PhantomData,
        }
    }

    // ---- Accessors ----

    /// Returns the real, canonicalized path as a `&Path`.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a reference to the inner `Jail` that created this `JailedPath`.
    #[inline]
    pub(crate) fn jail(&self) -> &crate::validator::jail::Jail<Marker> {
        self.jail.as_ref()
    }

    // ---- String Conversion ----

    /// Returns the real path as a `String` (e.g., `/app/storage/user/file.txt`).
    #[inline]
    pub fn realpath_to_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Returns the real path as an `Option<&str>`.
    #[inline]
    pub fn realpath_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns the real path as an `&OsStr`.
    #[inline]
    pub fn realpath_as_os_str(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Borrowed display adapter, similar to `std::path::Path::display()`.
    ///
    /// This returns the platform display adapter that borrows the internal
    /// `PathBuf` so callers can format it without allocating.
    #[inline]
    pub fn display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// Consumes the `JailedPath` and returns the real path as a `PathBuf`.
    ///
    /// **⚠️ SECURITY WARNING**: This is the primary escape hatch. Once called, all security
    /// guarantees are lost. Only use this for integration with external APIs that
    /// require `PathBuf` ownership.
    #[inline]
    pub fn unjail(self) -> PathBuf {
        self.path
    }

    /// Converts this `JailedPath` into a `VirtualPath` (user-facing view).
    ///
    /// This is an explicit conversion: use `virtualize()` to move from system-facing to
    /// user-facing types rather than relying on implicit `From/Into` conversions.
    #[inline]
    pub fn virtualize(self) -> crate::virtual_path::VirtualPath<Marker> {
        crate::virtual_path::VirtualPath::new(self)
    }

    // ---- Safe Path Manipulation ----

    /// Safely joins a path segment to the current real path.
    #[inline]
    pub fn join_real<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_real = self.path.join(path);
        // pass a reference to the Jail stored in this JailedPath
        crate::validator::jail::validate(new_real, self.jail())
    }

    /// Returns the parent directory interpreted in real-path semantics.
    ///
    /// Returns `Ok(None)` if the current path has no parent.
    pub fn parent_real(&self) -> Result<Option<Self>> {
        match self.path.parent() {
            Some(p) => match crate::validator::jail::validate(p, self.jail()) {
                Ok(p) => Ok(Some(p)),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    /// Returns a new `JailedPath` with the file name replaced.
    #[inline]
    pub fn with_file_name_real<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_real = self.path.with_file_name(file_name);
        crate::validator::jail::validate(new_real, self.jail())
    }

    /// Returns a new `JailedPath` with the extension replaced.
    ///
    /// Returns an error if the path has no file name.
    pub fn with_extension_real<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let rpath = self.path.as_path();
        if rpath.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.path.clone(),
                self.jail().path().to_path_buf(),
            ));
        }
        let new_real = rpath.with_extension(extension);
        crate::validator::jail::validate(new_real, self.jail())
    }

    // ---- Path Components (Real) ----

    /// Returns the final component of the real path, if there is one.
    #[inline]
    pub fn file_name_real(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Returns the file stem of the real path.
    #[inline]
    pub fn file_stem_real(&self) -> Option<&OsStr> {
        self.path.file_stem()
    }

    /// Returns the extension of the real path.
    #[inline]
    pub fn extension_real(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    // ---- Prefix / Suffix Checks ----

    /// Returns true if the *real* filesystem path starts with `p`.
    #[inline]
    pub fn starts_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    /// Returns true if the *real* filesystem path ends with `p`.
    #[inline]
    pub fn ends_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.ends_with(p.as_ref())
    }

    // ---- File System Operations ----

    /// Returns `true` if the path exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Returns `true` if the path is a file.
    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    /// Returns `true` if the path is a directory.
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Returns the metadata for the path.
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
    }

    /// Reads the entire contents of a file into a string.
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the entire contents of a file into a bytes vector.
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Writes a slice of bytes as the entire content of a file.
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Writes a string as the entire content of a file.
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Creates a directory at this path, including any parent directories.
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.path)
    }

    /// Removes a file from the filesystem.
    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    /// Removes an empty directory.
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.path)
    }

    /// Removes a directory and all its contents recursively.
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(&self.path)
    }
}

// --- Trait Implementations ---

impl<Marker> fmt::Display for JailedPath<Marker> {
    /// Displays the **real filesystem path**.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    /// Displays the **real path** for debugging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JailedPath")
            .field("path", &self.path.display())
            .field("jail_root", &&self.jail().path().display())
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
