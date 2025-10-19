use crate::validator::path_history::{BoundaryChecked, Canonicalized, PathHistory, Raw};
use crate::{Result, StrictPathError};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// SUMMARY:
/// Hold a validated, system-facing filesystem path guaranteed to be within a `PathBoundary`.
///
/// DETAILS:
/// Use when you need system-facing I/O with safety proofs. For user-facing display and rooted
/// virtual operations prefer `VirtualPath`. Operations like `strict_join` and
/// `strictpath_parent` preserve guarantees. `Display` shows the real system path. String
/// accessors are prefixed with `strictpath_` to avoid confusion.
#[derive(Clone)]
pub struct StrictPath<Marker = ()> {
    path: PathHistory<((Raw, Canonicalized), BoundaryChecked)>,
    boundary: Arc<crate::PathBoundary<Marker>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> StrictPath<Marker> {
    /// SUMMARY:
    /// Create the base `StrictPath` anchored at the provided boundary directory.
    ///
    /// PARAMETERS:
    /// - `dir_path` (`AsRef<Path>`): Boundary directory (must exist).
    ///
    /// RETURNS:
    /// - `Result<StrictPath<Marker>>`: Base path ("" join) within the boundary.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: If the boundary cannot be created/validated.
    ///
    /// NOTE: Prefer passing `PathBoundary` in reusable flows.
    pub fn with_boundary<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let boundary = crate::PathBoundary::try_new(dir_path)?;
        boundary.into_strictpath()
    }

    /// SUMMARY:
    /// Create the base `StrictPath`, creating the boundary directory if missing.
    pub fn with_boundary_create<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let boundary = crate::PathBoundary::try_new_create(dir_path)?;
        boundary.into_strictpath()
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

    #[cfg(feature = "virtual-path")]
    #[inline]
    pub(crate) fn boundary(&self) -> &crate::PathBoundary<Marker> {
        &self.boundary
    }

    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// SUMMARY:
    /// Return a lossy `String` view of the system path. Prefer `.interop_path()` only for unavoidable third-party interop.
    #[inline]
    pub fn strictpath_to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.path.to_string_lossy()
    }

    /// SUMMARY:
    /// Return the underlying system path as `&str` if valid UTF‑8; otherwise `None`.
    #[inline]
    pub fn strictpath_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// SUMMARY:
    /// Return the underlying system path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop.
    #[inline]
    pub fn interop_path(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// SUMMARY:
    /// Return a `Display` wrapper that shows the real system path.
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// SUMMARY:
    /// Consume and return the inner `PathBuf` (escape hatch). Prefer `.interop_path()` (third-party adapters only) to borrow.
    #[inline]
    pub fn unstrict(self) -> PathBuf {
        self.path.into_inner()
    }

    /// SUMMARY:
    /// Convert this `StrictPath` into a user‑facing `VirtualPath`.
    #[cfg(feature = "virtual-path")]
    #[inline]
    pub fn virtualize(self) -> crate::path::virtual_path::VirtualPath<Marker> {
        crate::path::virtual_path::VirtualPath::new(self)
    }

    /// SUMMARY:
    /// Change the compile-time marker while reusing the validated strict path.
    ///
    /// WHEN TO USE:
    /// - After authenticating/authorizing a user and granting them access to a path
    /// - When escalating or downgrading permissions (e.g., ReadOnly → ReadWrite)
    /// - When reinterpreting a path's domain (e.g., TempStorage → UserUploads)
    ///
    /// WHEN NOT TO USE:
    /// - When converting between path types - conversions preserve markers automatically
    /// - When the current marker already matches your needs - no transformation needed
    /// - When you haven't verified authorization - NEVER change markers without checking permissions
    ///
    /// PARAMETERS:
    /// - `_none_`
    ///
    /// RETURNS:
    /// - `StrictPath<NewMarker>`: Same boundary-checked system path encoded with the new marker.
    ///
    /// ERRORS:
    /// - `_none_`
    ///
    /// SECURITY:
    /// The caller MUST ensure the new marker reflects real-world permissions. This method does not
    /// perform any authorization checks.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io;
    /// # struct UserFiles;
    /// # struct ReadOnly;
    /// # struct ReadWrite;
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-change-marker-example");
    /// # std::fs::create_dir_all(&boundary_dir.join("logs"))?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// #
    /// // Verify user can write before granting write access
    /// fn authorize_write_access(
    ///     user_id: &str,
    ///     path: StrictPath<(UserFiles, ReadOnly)>
    /// ) -> Result<StrictPath<(UserFiles, ReadWrite)>, &'static str> {
    ///     if user_id == "admin" {
    ///         Ok(path.change_marker())  // ✅ Transform after authorization check
    ///     } else {
    ///         Err("insufficient permissions")  // ❌ User lacks write permission
    ///     }
    /// }
    ///
    /// // Function requiring write permission - enforces type safety at compile time
    /// fn write_log_entry(path: StrictPath<(UserFiles, ReadWrite)>, content: &str) -> io::Result<()> {
    ///     path.write(content.as_bytes())
    /// }
    ///
    /// // Start with read-only access
    /// let read_only_path: StrictPath<(UserFiles, ReadOnly)> =
    ///     boundary.strict_join("logs/app.log")?.change_marker();
    ///
    /// // Elevate permissions after authorization
    /// let read_write_path = authorize_write_access("admin", read_only_path)
    ///     .expect("user must have sufficient permissions");
    ///
    /// // Now we can call functions requiring write access
    /// write_log_entry(read_write_path, "Application started")?;
    /// #
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// **Type Safety Guarantee:**
    ///
    /// The following code **fails to compile** because you cannot pass a path with one marker
    /// type to a function expecting a different marker type. This compile-time check enforces
    /// that permission changes are explicit and cannot be bypassed accidentally.
    ///
    /// ```compile_fail
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # struct ReadOnly;
    /// # struct WritePermission;
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-change-marker-deny");
    /// # std::fs::create_dir_all(&boundary_dir).unwrap();
    /// # let boundary: PathBoundary<ReadOnly> = PathBoundary::try_new(&boundary_dir).unwrap();
    /// let read_only_path: StrictPath<ReadOnly> = boundary.strict_join("logs/app.log").unwrap();
    /// fn require_write(_: StrictPath<WritePermission>) {}
    /// // ❌ Compile error: expected `StrictPath<WritePermission>`, found `StrictPath<ReadOnly>`
    /// require_write(read_only_path);
    /// ```
    #[inline]
    pub fn change_marker<NewMarker>(self) -> StrictPath<NewMarker> {
        let StrictPath { path, boundary, .. } = self;

        // Try to unwrap the Arc (zero-cost if this is the only reference).
        // If other references exist, clone the boundary (allocation needed).
        let boundary_owned = Arc::try_unwrap(boundary).unwrap_or_else(|arc| (*arc).clone());
        let new_boundary = Arc::new(boundary_owned.change_marker::<NewMarker>());

        StrictPath {
            path,
            boundary: new_boundary,
            _marker: PhantomData,
        }
    }

    /// SUMMARY:
    /// Consume and return a new `PathBoundary` anchored at this strict path.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: Boundary anchored at the strict path's
    ///   system location (must already exist and be a directory).
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: If the strict path does not exist
    ///   or is not a directory.
    #[inline]
    pub fn try_into_boundary(self) -> Result<crate::PathBoundary<Marker>> {
        let StrictPath { path, .. } = self;
        crate::PathBoundary::try_new(path.into_inner())
    }

    /// SUMMARY:
    /// Consume and return a `PathBoundary`, creating the directory if missing.
    ///
    /// RETURNS:
    /// - `Result<PathBoundary<Marker>>`: Boundary anchored at the strict path's
    ///   system location (created if necessary).
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: If creation or canonicalization fails.
    #[inline]
    pub fn try_into_boundary_create(self) -> Result<crate::PathBoundary<Marker>> {
        let StrictPath { path, .. } = self;
        crate::PathBoundary::try_new_create(path.into_inner())
    }

    /// SUMMARY:
    /// Join a path segment and re-validate against the boundary.
    ///
    /// NOTE:
    /// Never wrap `.interop_path()` in `Path::new()` to use `Path::join()` — that defeats all security. Always use this method.
    /// After `.unstrict()` (explicit escape hatch), you own a `PathBuf` and can do whatever you need.
    ///
    /// PARAMETERS:
    /// - `path` (`AsRef<Path>`): Segment or absolute path to validate.
    ///
    /// RETURNS:
    /// - `Result<StrictPath<Marker>>`: Validated path inside the boundary.
    ///
    /// ERRORS:
    /// - `StrictPathError::PathResolutionError`, `StrictPathError::PathEscapesBoundary`.
    #[inline]
    pub fn strict_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_systempath = self.path.join(path);
        self.boundary.strict_join(new_systempath)
    }

    /// SUMMARY:
    /// Return the parent as a new `StrictPath`, or `None` at the boundary root.
    pub fn strictpath_parent(&self) -> Result<Option<Self>> {
        match self.path.parent() {
            Some(p) => match self.boundary.strict_join(p) {
                Ok(p) => Ok(Some(p)),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    /// SUMMARY:
    /// Return a new path with file name changed, re‑validating against the boundary.
    #[inline]
    pub fn strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_systempath = self.path.with_file_name(file_name);
        self.boundary.strict_join(new_systempath)
    }

    /// SUMMARY:
    /// Return a new path with extension changed; error at the boundary root.
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

    /// SUMMARY:
    /// Read directory entries at this path (discovery). Re‑join names through strict/virtual APIs before I/O.
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

    /// SUMMARY:
    /// Write bytes to the file (create if missing). Accepts any `AsRef<[u8]>` (e.g., `&str`, `&[u8]`).
    #[inline]
    pub fn write<C: AsRef<[u8]>>(&self, contents: C) -> std::io::Result<()> {
        std::fs::write(&self.path, contents)
    }

    /// SUMMARY:
    /// Create or truncate the file at this strict path and return a writable handle.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Writable handle scoped to this boundary.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the parent directory is missing or file creation fails.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::Write;
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-create-file-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// let log_path: StrictPath = boundary.strict_join("logs/app.log")?;
    /// log_path.create_parent_dir_all()?;
    /// let mut file = log_path.create_file()?;
    /// file.write_all(b"session started")?;
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::create(&self.path)
    }

    /// SUMMARY:
    /// Open the file at this strict path in read-only mode.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Read-only handle scoped to this boundary.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the file is missing or inaccessible.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::{Read, Write};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-open-file-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// let transcript: StrictPath = boundary.strict_join("logs/session.log")?;
    /// transcript.create_parent_dir_all()?;
    /// transcript.write("session start")?;
    /// let mut file = transcript.open_file()?;
    /// let mut contents = String::new();
    /// file.read_to_string(&mut contents)?;
    /// assert_eq!(contents, "session start");
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(&self.path)
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

    /// SUMMARY:
    /// Create only the immediate parent directory (non‑recursive). `Ok(())` at the boundary root.
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// SUMMARY:
    /// Recursively create all missing directories up to the immediate parent. `Ok(())` at boundary.
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// SUMMARY:
    /// Create a symbolic link at this location pointing to `target` (same boundary required).
    /// On Windows, file vs directory symlink is selected by target metadata (or best‑effort when missing).
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

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this path (same boundary; caller creates parents).
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

    /// SUMMARY:
    /// Create a Windows NTFS directory junction at `link_path` pointing to this path.
    ///
    /// DETAILS:
    /// - Windows-only and behind the `junctions` crate feature.
    /// - Junctions are directory-only. This call will fail if the target is not a directory.
    /// - Both `self` (target) and `link_path` must be within the same `PathBoundary`.
    /// - Parents for `link_path` are not created automatically; call `create_parent_dir_all()` first.
    ///
    /// RETURNS:
    /// - `io::Result<()>`: Mirrors OS semantics (and `junction` crate behavior).
    ///
    /// ERRORS:
    /// - Returns an error if boundaries differ, the target is not a directory, or the OS call fails.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn strict_junction(&self, link_path: &Self) -> std::io::Result<()> {
        if self.boundary.path() != link_path.boundary.path() {
            let err = StrictPathError::path_escapes_boundary(
                link_path.path().to_path_buf(),
                self.boundary.path().to_path_buf(),
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
        }

        // Validate target is a directory (junctions are directory-only)
        let meta = std::fs::metadata(self.path())?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "junction targets must be directories",
            ));
        }

        // Call into the junction crate directly; do not add extra helpers.
        junction::create(self.path(), link_path.path())
    }

    /// SUMMARY:
    /// Rename/move within the same boundary. Relative destinations are siblings; absolute are validated.
    /// Parents are not created automatically.
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
                Ok(None) => match self.boundary.as_ref().clone().into_strictpath() {
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

    /// SUMMARY:
    /// Copy within the same boundary. Relative destinations are siblings; absolute are validated.
    /// Parents are not created automatically. Returns bytes copied.
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
                Ok(None) => match self.boundary.as_ref().clone().into_strictpath() {
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

    /// SUMMARY:
    /// Remove the file at this path.
    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    /// SUMMARY:
    /// Remove the directory at this path.
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.path)
    }

    /// SUMMARY:
    /// Recursively remove the directory and its contents.
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

// Note: No separate helper for junction creation by design — keep surface minimal

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

#[cfg(feature = "virtual-path")]
impl<Marker> PartialEq<crate::path::virtual_path::VirtualPath<Marker>> for StrictPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::virtual_path::VirtualPath<Marker>) -> bool {
        self.path.as_ref() == other.interop_path()
    }
}
