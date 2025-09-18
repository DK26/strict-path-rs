// Content copied from original src/path/restricted_path.rs
use crate::validator::path_history::{BoundaryChecked, Canonicalized, PathHistory, Raw};
use crate::{Result, StrictPathError};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A validated, system-facing filesystem path that is mathematically proven to be within a
/// `PathBoundary` boundary. If this value exists, the path is guaranteed safe.
///
/// Use this type when you need system-facing path display/operations with proof of safety.
/// For user-facing display and virtual operations, consider using `VirtualPath` which provides
/// a rooted view (PathBoundary becomes "/") and virtual joins/navigation.
///
/// Operations like `strict_join`, `strictpath_parent`, etc. preserve the boundary guarantees.
/// Use `interop_path()` for I/O with external APIs. Both this type and `VirtualPath` support I/O.
///
/// Equality/ordering is based on the underlying system path (same as `Path::cmp`).
/// `Display` shows the real system path.
///
/// All string accessors are prefixed with `strictpath_` to avoid confusion:
/// `strictpath_*` accessors for strings/OS strings and the safe manipulation methods
/// which re-validate against the restriction.
#[derive(Clone)]
pub struct StrictPath<Marker = ()> {
    path: PathHistory<((Raw, Canonicalized), BoundaryChecked)>,
    boundary: Arc<crate::PathBoundary<Marker>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> StrictPath<Marker> {
    /// Create a root `StrictPath` anchored at the provided boundary directory.
    ///
    /// Prefer this in simple flows; use `PathBoundary` directly when you need
    /// to reuse policy across many paths or pass it as a parameter.
    pub fn with_boundary<P: AsRef<Path>>(root: P) -> Result<Self> {
        let boundary = crate::PathBoundary::try_new(root)?;
        boundary.strict_join("")
    }

    /// Create a root `StrictPath`, creating the boundary directory if missing.
    ///
    /// Ensures the boundary directory exists by creating it when needed.
    pub fn with_boundary_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let boundary = crate::PathBoundary::try_new_create(root)?;
        boundary.strict_join("")
    }
    pub(crate) fn new(
        boundary: Arc<crate::PathBoundary<Marker>>,
        validated_path: PathHistory<((Raw, Canonicalized), BoundaryChecked)>,
    ) -> Self {
        Self {
            path: validated_path,
            boundary,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn boundary(&self) -> &crate::PathBoundary<Marker> {
        &self.boundary
    }

    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// For interop with APIs that accept `AsRef<Path>`, prefer
    /// `interop_path()` to avoid allocation.
    #[inline]
    pub fn strictpath_to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.path.to_string_lossy()
    }

    /// Returns the underlying system path as `&str` if valid UTF-8.
    ///
    /// For lossless interop on any platform, prefer `interop_path()`.
    #[inline]
    pub fn strictpath_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns the underlying system path as `&OsStr` (lossless; implements `AsRef<Path>`).
    ///
    /// Use this when passing to external APIs that accept `AsRef<Path>`.
    #[inline]
    pub fn interop_path(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Returns a `Display` wrapper that shows the real system path.
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// Consumes this `RestrictedPath` and returns the inner `PathBuf` (escape hatch).
    ///
    /// Prefer borrowing via `interop_path()` when possible.
    #[inline]
    pub fn unstrict(self) -> PathBuf {
        self.path.into_inner()
    }

    /// Converts this `RestrictedPath` into a user-facing `VirtualPath`.
    #[inline]
    pub fn virtualize(self) -> crate::path::virtual_path::VirtualPath<Marker> {
        crate::path::virtual_path::VirtualPath::new(self)
    }

    /// Consumes this `StrictPath` and returns its associated `PathBoundary`.
    ///
    /// This is infallible because a `StrictPath` always carries a boundary reference.
    /// Provided as ergonomic symmetry with other `try_*` constructors.
    #[inline]
    pub fn try_into_boundary(self) -> crate::PathBoundary<Marker> {
        // Clone the underlying boundary reference (cheap, small struct)
        self.boundary.as_ref().clone()
    }

    /// Consumes this `StrictPath` and returns its `PathBoundary`, creating the
    /// underlying directory if it does not exist.
    ///
    /// This is typically a no-op since a `StrictPath` is constructed only from an
    /// existing boundary, but this method is provided for API symmetry and robustness.
    #[inline]
    pub fn try_into_boundary_create(self) -> crate::PathBoundary<Marker> {
        let boundary = self.boundary.as_ref().clone();
        if !boundary.exists() {
            // Best-effort create; ignore error and let later operations surface it
            let _ = std::fs::create_dir_all(boundary.as_ref());
        }
        boundary
    }

    /// Safely joins a system path segment and re-validates against the restriction.
    ///
    /// Do not use `Path::join` on leaked paths. Always use this method to ensure
    /// PathBoundary containment is preserved.
    #[inline]
    pub fn strict_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_systempath = self.path.join(path);
        self.boundary.strict_join(new_systempath)
    }

    /// Returns the parent directory as a new `StrictPath`, or `None` if at the PathBoundary root.
    pub fn strictpath_parent(&self) -> Result<Option<Self>> {
        match self.path.parent() {
            Some(p) => match self.boundary.strict_join(p) {
                Ok(p) => Ok(Some(p)),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    /// Returns a new `StrictPath` with the file name changed, re-validating against the restriction.
    #[inline]
    pub fn strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_systempath = self.path.with_file_name(file_name);
        self.boundary.strict_join(new_systempath)
    }

    /// Returns a new `StrictPath` with the extension changed, or an error if at PathBoundary root.
    pub fn strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let system_path = &self.path;
        if system_path.file_name().is_none() {
            return Err(StrictPathError::path_escapes_boundary(
                self.path.to_path_buf(),
                self.boundary.path().to_path_buf(),
            ));
        }
        let new_systempath = system_path.with_extension(extension);
        self.boundary.strict_join(new_systempath)
    }

    /// Returns the file name component of the system path, if any.
    #[inline]
    pub fn strictpath_file_name(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Returns the file stem of the system path, if any.
    #[inline]
    pub fn strictpath_file_stem(&self) -> Option<&OsStr> {
        self.path.file_stem()
    }

    /// Returns the extension of the system path, if any.
    #[inline]
    pub fn strictpath_extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    /// Returns `true` if the system path starts with the given prefix.
    #[inline]
    pub fn strictpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    /// Returns `true` if the system path ends with the given suffix.
    #[inline]
    pub fn strictpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
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

    /// Reads the directory entries at the system path (like `std::fs::read_dir`).
    ///
    /// This is intended for discovery. Prefer collecting each entry's file name via
    /// `entry.file_name()` and re‑joining it with `strict_join(...)` (or `virtual_join(...)`
    /// when working from a `VirtualRoot`) before performing I/O.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.path)
    }

    /// Reads the file contents as `String`.
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the file contents as raw bytes.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use read() instead")]
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Writes raw bytes to the file, creating it if it does not exist.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use write(...) instead")]
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Writes a UTF-8 string to the file, creating it if it does not exist.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use write(...) instead")]
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    /// Reads the file contents as raw bytes (replacement for `read_bytes`).
    #[inline]
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Writes data to the file, creating it if it does not exist.
    /// Accepts any type that can be viewed as a byte slice (e.g., `&str`, `String`, `&[u8]`, `Vec<u8]`).
    #[inline]
    pub fn write<C: AsRef<[u8]>>(&self, contents: C) -> std::io::Result<()> {
        std::fs::write(&self.path, contents)
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
    /// Returns `Ok(())` if at the restricted path root (no parent). Fails if the parent's
    /// parent is missing. Use `create_parent_dir_all` to create the full chain.
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Recursively creates all missing directories up to the immediate parent of this system path.
    ///
    /// Returns `Ok(())` if at the restricted path root (no parent).
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Creates a symbolic link at this location pointing to `target`.
    ///
    /// Both the link path (`self`) and the target must belong to the same `PathBoundary`. The caller
    /// is responsible for ensuring the parent directory exists. On Windows the target's current
    /// metadata determines whether a file or directory symbolic link is created; if the target does
    /// not yet exist a file symbolic link is attempted first.
    pub fn strict_symlink(&self, link_path: &Self) -> std::io::Result<()> {
        if self.boundary.path() != link_path.boundary.path() {
            let err = StrictPathError::path_escapes_boundary(
                link_path.path().to_path_buf(),
                self.boundary.path().to_path_buf(),
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(self.path(), link_path.path())?;
        }

        #[cfg(windows)]
        {
            create_windows_symlink(self.path(), link_path.path())?;
        }

        Ok(())
    }

    /// Creates a hard link at `link_path` pointing to this path.
    ///
    /// Both paths must belong to the same `PathBoundary`. The caller is responsible for ensuring the
    /// parent directory of `link_path` exists.
    pub fn strict_hard_link(&self, link_path: &Self) -> std::io::Result<()> {
        if self.boundary.path() != link_path.boundary.path() {
            let err = StrictPathError::path_escapes_boundary(
                link_path.path().to_path_buf(),
                self.boundary.path().to_path_buf(),
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
        }

        std::fs::hard_link(self.path(), link_path.path())?;

        Ok(())
    }

    /// Renames or moves this path to a new location within the same `PathBoundary`.
    ///
    /// Relative destinations are interpreted as siblings (resolved against this path's parent
    /// directory), not children. Absolute destinations are validated against the `PathBoundary`.
    /// No parent directories are created implicitly; call `create_parent_dir_all()` on the
    /// desired destination path beforehand if needed.
    pub fn strict_rename<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<()> {
        let dest_ref = dest.as_ref();

        // Compute destination under the parent directory for relative paths; allow absolute too
        let dest_path = if dest_ref.is_absolute() {
            match self.boundary.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary.strict_join("") {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::rename(self.path(), dest_path.path())
    }

    /// Copies this file to a new location within the same `PathBoundary`.
    ///
    /// Semantics mirror `strict_rename` for destination resolution:
    /// - Relative destinations are interpreted as siblings (resolved against this path's parent).
    /// - Absolute destinations are validated against the `PathBoundary`.
    ///
    /// No parent directories are created implicitly; call `create_parent_dir_all()` on the
    /// desired destination path beforehand if needed. Equivalent to
    /// `std::fs::copy(self.interop_path(), dest.interop_path())` but with restriction-aware
    /// destination validation. Returns the number of bytes copied.
    pub fn strict_copy<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<u64> {
        let dest_ref = dest.as_ref();

        // Compute destination under the parent directory for relative paths; allow absolute too
        let dest_path = if dest_ref.is_absolute() {
            match self.boundary.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary.strict_join("") {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::copy(self.path(), dest_path.path())
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
impl<Marker> serde::Serialize for StrictPath<Marker> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.strictpath_to_string_lossy().as_ref())
    }
}

impl<Marker> fmt::Debug for StrictPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictPath")
            .field("path", &self.path)
            .field("boundary", &self.boundary.path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

#[cfg(windows)]
fn create_windows_symlink(src: &Path, link: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    match std::fs::metadata(src) {
        Ok(metadata) => {
            if metadata.is_dir() {
                symlink_dir(src, link)
            } else {
                symlink_file(src, link)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match symlink_file(src, link) {
                Ok(()) => Ok(()),
                Err(file_err) => {
                    if let Some(code) = file_err.raw_os_error() {
                        const ERROR_DIRECTORY: i32 = 267; // target resolved as directory
                        if code == ERROR_DIRECTORY {
                            return symlink_dir(src, link);
                        }
                    }
                    Err(file_err)
                }
            }
        }
        Err(err) => Err(err),
    }
}

impl<Marker> PartialEq for StrictPath<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path.as_ref() == other.path.as_ref()
    }
}

impl<Marker> Eq for StrictPath<Marker> {}

impl<Marker> Hash for StrictPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<Marker> PartialOrd for StrictPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for StrictPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for StrictPath<Marker> {
    fn eq(&self, other: &T) -> bool {
        self.path.as_ref() == other.as_ref()
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for StrictPath<Marker> {
    fn partial_cmp(&self, other: &T) -> Option<Ordering> {
        Some(self.path.as_ref().cmp(other.as_ref()))
    }
}

impl<Marker> PartialEq<crate::path::virtual_path::VirtualPath<Marker>> for StrictPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::virtual_path::VirtualPath<Marker>) -> bool {
        self.path.as_ref() == other.interop_path()
    }
}
