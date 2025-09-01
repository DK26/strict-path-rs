// Content copied from original src/path/jailed_path.rs
use crate::validator::stated_path::{BoundaryChecked, Canonicalized, Raw, StatedPath};
use crate::{JailedPathError, Result};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A system-facing, validated filesystem path guaranteed to stay within its jail.
///
/// This type never exposes a raw `&Path` to avoid misuse. Use the provided
/// `systempath_*` accessors for strings/OS strings and the safe manipulation methods
/// which re-validate against the jail.
#[derive(Clone)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail: Arc<crate::validator::jail::Jail<Marker>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> JailedPath<Marker> {
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
}

impl<Marker> JailedPath<Marker> {
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub(crate) fn jail(&self) -> &crate::validator::jail::Jail<Marker> {
        self.jail.as_ref()
    }

    /// Returns the underlying system path as a lossy UTF-8 string.
    ///
    /// Mirrors `Path::to_string_lossy()` by returning `Cow<'_, str>` so valid UTF-8
    /// can be borrowed without allocation.
    ///
    /// For interop with APIs that accept `AsRef<Path>`, prefer
    /// `systempath_as_os_str()` to avoid allocation.
    #[inline]
    pub fn systempath_to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.path.to_string_lossy()
    }

    /// Returns the underlying system path as `&str` if valid UTF-8.
    ///
    /// For lossless interop on any platform, prefer `systempath_as_os_str()`.
    #[inline]
    pub fn systempath_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns the underlying system path as `&OsStr` (lossless; implements `AsRef<Path>`).
    ///
    /// Use this when passing to external APIs that accept `AsRef<Path>`.
    #[inline]
    pub fn systempath_as_os_str(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Returns a `Display` wrapper that shows the real system path.
    #[inline]
    pub fn display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// Consumes this `JailedPath` and returns the inner `PathBuf` (escape hatch).
    ///
    /// Prefer borrowing via `systempath_as_os_str()` when possible.
    #[inline]
    pub fn unjail(self) -> PathBuf {
        self.path
    }

    /// Converts this `JailedPath` into a user-facing `VirtualPath`.
    #[inline]
    pub fn virtualize(self) -> crate::path::virtual_path::VirtualPath<Marker> {
        crate::path::virtual_path::VirtualPath::new(self)
    }

    /// Safely joins a system path segment and re-validates against the jail.
    ///
    /// Do not use `Path::join` on leaked paths. Always use this method to ensure
    /// jail containment is preserved.
    #[inline]
    pub fn systempath_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_systempath = self.path.join(path);
        crate::validator::validate(new_systempath, self.jail())
    }

    /// Returns the parent directory as a new `JailedPath`, or `None` if at the jail root.
    pub fn systempath_parent(&self) -> Result<Option<Self>> {
        match self.path.parent() {
            Some(p) => match crate::validator::validate(p, self.jail()) {
                Ok(p) => Ok(Some(p)),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    /// Returns a new `JailedPath` with the file name changed, re-validating against the jail.
    #[inline]
    pub fn systempath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_systempath = self.path.with_file_name(file_name);
        crate::validator::validate(new_systempath, self.jail())
    }

    /// Returns a new `JailedPath` with the extension changed, or an error if at jail root.
    pub fn systempath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let system_path = self.path.as_path();
        if system_path.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.path.clone(),
                self.jail().path().to_path_buf(),
            ));
        }
        let new_systempath = system_path.with_extension(extension);
        crate::validator::validate(new_systempath, self.jail())
    }

    /// Returns the file name component of the system path, if any.
    #[inline]
    pub fn systempath_file_name(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Returns the file stem of the system path, if any.
    #[inline]
    pub fn systempath_file_stem(&self) -> Option<&OsStr> {
        self.path.file_stem()
    }

    /// Returns the extension of the system path, if any.
    #[inline]
    pub fn systempath_extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    /// Returns `true` if the system path starts with the given prefix.
    #[inline]
    pub fn systempath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    /// Returns `true` if the system path ends with the given suffix.
    #[inline]
    pub fn systempath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.ends_with(p.as_ref())
    }

    /// Returns `true` if the system path exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Returns `true` if the system path is a file.
    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    /// Returns `true` if the system path is a directory.
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Returns the metadata for the system path.
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
    }

    /// Reads the file contents as `String`.
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the file contents as raw bytes.
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Writes raw bytes to the file, creating it if it does not exist.
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Writes a UTF-8 string to the file, creating it if it does not exist.
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Creates all directories in the system path if missing (like `std::fs::create_dir_all`).
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.path)
    }

    /// Creates the directory at the system path (non-recursive, like `std::fs::create_dir`).
    ///
    /// Fails if the parent directory does not exist. Use `create_dir_all` to
    /// create missing parent directories recursively.
    pub fn create_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir(&self.path)
    }

    /// Creates only the immediate parent directory of this system path (non-recursive).
    ///
    /// Returns `Ok(())` if at the jail root (no parent). Fails if the parent's
    /// parent is missing. Use `create_parent_dir_all` to create the full chain.
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.systempath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            Err(JailedPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Recursively creates all missing directories up to the immediate parent of this system path.
    ///
    /// Returns `Ok(())` if at the jail root (no parent).
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.systempath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            Err(JailedPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Removes the file at the system path.
    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    /// Removes the directory at the system path.
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.path)
    }

    /// Recursively removes the directory and its contents.
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(&self.path)
    }
}

#[cfg(feature = "serde")]
impl<Marker> serde::Serialize for JailedPath<Marker> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.systempath_to_string_lossy().as_ref())
    }
}

impl<Marker> fmt::Display for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JailedPath")
            .field("path", &self.path)
            .field("jail", &self.jail().path())
            .field("marker", &std::any::type_name::<Marker>())
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

impl<T: AsRef<Path>, Marker> PartialEq<T> for JailedPath<Marker> {
    fn eq(&self, other: &T) -> bool {
        self.path == other.as_ref()
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for JailedPath<Marker> {
    fn partial_cmp(&self, other: &T) -> Option<Ordering> {
        Some(self.path.as_path().cmp(other.as_ref()))
    }
}
