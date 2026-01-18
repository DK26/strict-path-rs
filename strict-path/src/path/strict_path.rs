use crate::validator::path_history::{BoundaryChecked, Canonicalized, PathHistory, Raw};
use crate::{Result, StrictPathError};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Strip the Windows verbatim `\\?\` prefix from a path if present.
///
/// The `junction` crate does not handle verbatim prefix paths correctly - it creates
/// broken junctions that return ERROR_INVALID_NAME (123) when accessed.
/// This helper strips the prefix so junction creation works correctly.
///
/// See: <https://github.com/tesuji/junction/issues/30>
#[cfg(all(windows, feature = "junctions"))]
fn strip_verbatim_prefix(path: &Path) -> std::borrow::Cow<'_, Path> {
    use std::borrow::Cow;
    let s = path.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        Cow::Owned(PathBuf::from(rest))
    } else {
        Cow::Borrowed(path)
    }
}

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
    /// // Start with read-only access from untrusted input
    /// let requested_log = "logs/app.log"; // Untrusted input
    /// let read_only_path: StrictPath<(UserFiles, ReadOnly)> =
    ///     boundary.strict_join(requested_log)?.change_marker();
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
    /// Return the metadata for the system path without following symlinks (like `std::fs::symlink_metadata`).
    ///
    /// DETAILS:
    /// This retrieves metadata about the path entry itself. On symlinks, this reports
    /// information about the link, not the target.
    #[inline]
    pub fn symlink_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(&self.path)
    }

    /// SUMMARY:
    /// Set permissions on the file or directory at this path.
    ///
    /// PARAMETERS:
    /// - `perm` (`std::fs::Permissions`): The permissions to set.
    ///
    /// RETURNS:
    /// - `io::Result<()>`: Success or I/O error.
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file = boundary.strict_join("script.sh")?;
    /// file.write("#!/bin/bash\necho hello")?;
    ///
    /// // Make executable (Unix) or read-only (cross-platform)
    /// let mut perms = file.metadata()?.permissions();
    /// perms.set_readonly(true);
    /// file.set_permissions(perms)?;
    ///
    /// assert!(file.metadata()?.permissions().readonly());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn set_permissions(&self, perm: std::fs::Permissions) -> std::io::Result<()> {
        std::fs::set_permissions(&self.path, perm)
    }

    /// SUMMARY:
    /// Check if the path exists, returning an error on permission issues.
    ///
    /// DETAILS:
    /// Unlike `exists()` which returns `false` on permission errors, this method
    /// distinguishes between "path does not exist" (`Ok(false)`) and "cannot check
    /// due to permission error" (`Err(...)`).
    ///
    /// RETURNS:
    /// - `Ok(true)`: Path exists
    /// - `Ok(false)`: Path does not exist
    /// - `Err(...)`: Permission or other I/O error prevented the check
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// let existing = boundary.strict_join("exists.txt")?;
    /// existing.write("content")?;
    /// assert_eq!(existing.try_exists()?, true);
    ///
    /// let missing = boundary.strict_join("missing.txt")?;
    /// assert_eq!(missing.try_exists()?, false);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn try_exists(&self) -> std::io::Result<bool> {
        self.path.try_exists()
    }

    /// SUMMARY:
    /// Create an empty file if it doesn't exist, or update the modification time if it does.
    ///
    /// DETAILS:
    /// This is a convenience method combining file creation and mtime update.
    /// Uses `OpenOptions` with `create(true).write(true)` which creates the file
    /// if missing or opens it for writing if it exists, updating mtime on close.
    ///
    /// RETURNS:
    /// - `io::Result<()>`: Success or I/O error.
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// let file = boundary.strict_join("marker.txt")?;
    /// assert!(!file.exists());
    ///
    /// file.touch()?;
    /// assert!(file.exists());
    /// assert_eq!(file.read_to_string()?, "");  // Empty file
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn touch(&self) -> std::io::Result<()> {
        // Using truncate(false) to preserve existing content - touch only updates mtime
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.path)?;
        Ok(())
    }

    /// SUMMARY:
    /// Read directory entries at this path (discovery). Re‑join names through strict/virtual APIs before I/O.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.path)
    }

    /// SUMMARY:
    /// Read directory entries as validated `StrictPath` values (auto re-joins each entry).
    ///
    /// DETAILS:
    /// Unlike `read_dir()` which returns raw `std::fs::DirEntry`, this method automatically
    /// validates each directory entry through `strict_join()`, returning an iterator of
    /// `Result<StrictPath<Marker>>`. This eliminates the need for manual re-validation loops.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `io::Result<StrictReadDir<Marker>>`: Iterator yielding validated `StrictPath` entries.
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the directory cannot be read.
    /// - Each yielded item may also be `Err` if validation fails for that entry.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # let temp = tempfile::tempdir()?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// # let dir = boundary.strict_join("data")?;
    /// # dir.create_dir_all()?;
    /// # boundary.strict_join("data/file1.txt")?.write("a")?;
    /// # boundary.strict_join("data/file2.txt")?.write("b")?;
    /// // Iterate with automatic validation
    /// for entry in dir.strict_read_dir()? {
    ///     let child: StrictPath = entry?;
    ///     println!("{}", child.strictpath_display());
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn strict_read_dir(&self) -> std::io::Result<StrictReadDir<'_, Marker>> {
        let inner = std::fs::read_dir(&self.path)?;
        Ok(StrictReadDir {
            inner,
            parent: self,
        })
    }

    /// Reads the file contents as `String`.
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the file contents as raw bytes.
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
    /// Append bytes to the file (create if missing). Accepts any `AsRef<[u8]>` (e.g., `&str`, `&[u8]`).
    ///
    /// PARAMETERS:
    /// - `data` (`AsRef<[u8]>`): Bytes to append to the file.
    ///
    /// RETURNS:
    /// - `()`: Returns nothing on success.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the file cannot be opened or written.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-append-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let log_file = "logs/audit.log";
    /// let log_path: StrictPath = boundary.strict_join(log_file)?;
    /// log_path.create_parent_dir_all()?;
    /// log_path.append("[2025-01-01] Session started\n")?;
    /// log_path.append("[2025-01-01] User logged in\n")?;
    /// let contents = log_path.read_to_string()?;
    /// assert!(contents.contains("Session started"));
    /// assert!(contents.contains("User logged in"));
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn append<C: AsRef<[u8]>>(&self, data: C) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(data.as_ref())
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
    /// // Untrusted input from request/CLI/config/etc.
    /// let requested_file = "logs/app.log";
    /// let log_path: StrictPath = boundary.strict_join(requested_file)?;
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
    /// // Untrusted input from request/CLI/config/etc.
    /// let requested_file = "logs/session.log";
    /// let transcript: StrictPath = boundary.strict_join(requested_file)?;
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

    /// SUMMARY:
    /// Return an options builder for advanced file opening (read+write, append, exclusive create, etc.).
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `StrictOpenOptions<Marker>`: Builder to configure file opening options.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::{Read, Write, Seek, SeekFrom};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-open-with-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let boundary: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let data_file = "data/records.bin";
    /// let file_path: StrictPath = boundary.strict_join(data_file)?;
    /// file_path.create_parent_dir_all()?;
    ///
    /// // Open with read+write access, create if missing
    /// let mut file = file_path.open_with()
    ///     .read(true)
    ///     .write(true)
    ///     .create(true)
    ///     .open()?;
    /// file.write_all(b"header")?;
    /// file.seek(SeekFrom::Start(0))?;
    /// let mut buf = [0u8; 6];
    /// file.read_exact(&mut buf)?;
    /// assert_eq!(&buf, b"header");
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open_with(&self) -> StrictOpenOptions<'_, Marker> {
        StrictOpenOptions::new(self)
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
    /// Create a symbolic link at `link_path` pointing to this path (same boundary required).
    /// On Windows, file vs directory symlink is selected by target metadata (or best‑effort when missing).
    /// Relative paths are resolved as siblings; absolute paths are validated against the boundary.
    pub fn strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary.strict_join(link_ref) {
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
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(self.path(), validated_link.path())?;
        }

        #[cfg(windows)]
        {
            create_windows_symlink(self.path(), validated_link.path())?;
        }

        Ok(())
    }

    /// SUMMARY:
    /// Read the target of a symbolic link and validate it is within the boundary.
    ///
    /// DESIGN NOTE:
    /// This method has limited practical use because `strict_join` resolves symlinks
    /// during canonicalization. A `StrictPath` obtained via `strict_join("link")` already
    /// points to the symlink's target, not the symlink itself.
    ///
    /// To read a symlink target before validation, use `std::fs::read_link` on the raw
    /// path, then validate the target with `strict_join`:
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// // Create a target file
    /// let target = boundary.strict_join("target.txt")?;
    /// target.write("secret")?;
    ///
    /// // Create symlink (may fail on Windows without Developer Mode)
    /// if target.strict_symlink("link.txt").is_ok() {
    ///     // WRONG: strict_join("link.txt") resolves to target.txt
    ///     let resolved = boundary.strict_join("link.txt")?;
    ///     assert_eq!(resolved.strictpath_file_name(), Some("target.txt".as_ref()));
    ///
    ///     // RIGHT: read symlink target from raw path, then validate
    ///     let link_raw_path = temp.path().join("link.txt");
    ///     let symlink_target = std::fs::read_link(&link_raw_path)?;
    ///     let validated = boundary.strict_join(&symlink_target)?;
    ///     assert_eq!(validated.strictpath_file_name(), Some("target.txt".as_ref()));
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn strict_read_link(&self) -> std::io::Result<Self> {
        // Read the raw symlink target
        let raw_target = std::fs::read_link(&self.path)?;

        // If the target is relative, resolve it relative to the symlink's parent
        let resolved_target = if raw_target.is_relative() {
            match self.path.parent() {
                Some(parent) => parent.join(&raw_target),
                None => raw_target,
            }
        } else {
            raw_target
        };

        // Validate the resolved target against the boundary
        self.boundary
            .strict_join(resolved_target)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this path (same boundary; caller creates parents).
    /// Relative paths are resolved as siblings; absolute paths are validated against the boundary.
    pub fn strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary.strict_join(link_ref) {
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
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::hard_link(self.path(), validated_link.path())
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
    /// - Returns an error if the target is not a directory, or the OS call fails.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn strict_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary.strict_join(link_ref) {
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
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        // Validate target is a directory (junctions are directory-only)
        let meta = std::fs::metadata(self.path())?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "junction targets must be directories",
            ));
        }

        // The junction crate does not handle verbatim `\\?\` prefix paths correctly.
        // It creates broken junctions that return ERROR_INVALID_NAME (123) when accessed.
        // Strip the prefix before passing to the junction crate.
        // See: https://github.com/tesuji/junction/issues/30
        let target_path = strip_verbatim_prefix(self.path());
        let link_path = strip_verbatim_prefix(validated_link.path());

        junction::create(target_path.as_ref(), link_path.as_ref())
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

// ============================================================
// StrictOpenOptions — Builder for advanced file opening
// ============================================================

/// SUMMARY:
/// Builder for opening files with custom options (read, write, append, create, truncate, create_new).
///
/// DETAILS:
/// Use `StrictPath::open_with()` to get an instance. Chain builder methods to configure
/// options, then call `.open()` to obtain the file handle. This mirrors `std::fs::OpenOptions`
/// but operates on a validated `StrictPath`, so the path is guaranteed to be within its boundary.
///
/// EXAMPLE:
/// ```rust
/// # use strict_path::{PathBoundary, StrictPath};
/// # use std::io::Write;
/// # let temp = tempfile::tempdir()?;
/// # let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
/// let log_path: StrictPath = boundary.strict_join("app.log")?;
/// let mut file = log_path.open_with()
///     .create(true)
///     .append(true)
///     .open()?;
/// file.write_all(b"log entry\n")?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct StrictOpenOptions<'a, Marker> {
    path: &'a StrictPath<Marker>,
    options: std::fs::OpenOptions,
}

impl<'a, Marker> StrictOpenOptions<'a, Marker> {
    /// Create a new builder with default options (all flags false).
    #[inline]
    fn new(path: &'a StrictPath<Marker>) -> Self {
        Self {
            path,
            options: std::fs::OpenOptions::new(),
        }
    }

    /// Sets the option for read access.
    ///
    /// When `true`, the file will be readable after opening.
    #[inline]
    pub fn read(mut self, read: bool) -> Self {
        self.options.read(read);
        self
    }

    /// Sets the option for write access.
    ///
    /// When `true`, the file will be writable after opening.
    /// If the file exists, writes will overwrite existing content starting at the beginning
    /// unless `.append(true)` is also set.
    #[inline]
    pub fn write(mut self, write: bool) -> Self {
        self.options.write(write);
        self
    }

    /// Sets the option for append mode.
    ///
    /// When `true`, all writes will append to the end of the file instead of overwriting.
    /// Implies `.write(true)`.
    #[inline]
    pub fn append(mut self, append: bool) -> Self {
        self.options.append(append);
        self
    }

    /// Sets the option for truncating the file.
    ///
    /// When `true`, the file will be truncated to zero length upon opening.
    /// Requires `.write(true)`.
    #[inline]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.options.truncate(truncate);
        self
    }

    /// Sets the option to create the file if it doesn't exist.
    ///
    /// When `true`, the file will be created if missing. Requires `.write(true)` or `.append(true)`.
    #[inline]
    pub fn create(mut self, create: bool) -> Self {
        self.options.create(create);
        self
    }

    /// Sets the option for exclusive creation (fail if file exists).
    ///
    /// When `true`, the file must not exist; opening will fail with `AlreadyExists` if it does.
    /// Requires `.write(true)` and implies `.create(true)`.
    #[inline]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.options.create_new(create_new);
        self
    }

    /// Open the file with the configured options.
    ///
    /// RETURNS:
    /// - `std::io::Result<std::fs::File>`: The opened file handle.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors (file not found, permission denied, already exists, etc.).
    #[inline]
    pub fn open(self) -> std::io::Result<std::fs::File> {
        self.options.open(&self.path.path)
    }
}

// ============================================================
// StrictReadDir — Iterator for validated directory entries
// ============================================================

/// SUMMARY:
/// Iterator over directory entries that yields validated `StrictPath` values.
///
/// DETAILS:
/// Created by `StrictPath::strict_read_dir()`. Each iteration automatically validates
/// the directory entry through `strict_join()`, so you get `StrictPath` values directly
/// instead of raw `std::fs::DirEntry` that would require manual re-validation.
///
/// EXAMPLE:
/// ```rust
/// # use strict_path::{PathBoundary, StrictPath};
/// # let temp = tempfile::tempdir()?;
/// # let boundary: PathBoundary = PathBoundary::try_new(temp.path())?;
/// # let dir = boundary.strict_join("docs")?;
/// # dir.create_dir_all()?;
/// # boundary.strict_join("docs/readme.md")?.write("# Docs")?;
/// for entry in dir.strict_read_dir()? {
///     let child: StrictPath = entry?;
///     if child.is_file() {
///         println!("File: {}", child.strictpath_display());
///     }
/// }
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct StrictReadDir<'a, Marker> {
    inner: std::fs::ReadDir,
    parent: &'a StrictPath<Marker>,
}

impl<Marker> std::fmt::Debug for StrictReadDir<'_, Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictReadDir")
            .field("parent", &self.parent.strictpath_display())
            .finish_non_exhaustive()
    }
}

impl<Marker: Clone> Iterator for StrictReadDir<'_, Marker> {
    type Item = std::io::Result<StrictPath<Marker>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(entry) => {
                let file_name = entry.file_name();
                match self.parent.strict_join(file_name) {
                    Ok(strict_path) => Some(Ok(strict_path)),
                    Err(e) => Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))),
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
