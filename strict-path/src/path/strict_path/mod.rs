//! `StrictPath<Marker>` — a path canonicalized and boundary-checked at construction time.
//!
//! A `StrictPath` is produced exclusively through `PathBoundary::strict_join()` or
//! `StrictPath::with_boundary()`. Once in hand, the path is guaranteed to resolve inside
//! its boundary. All path-composition methods (`strict_join`, `strictpath_parent`, etc.)
//! re-validate the result, maintaining the invariant across every operation.
mod fs;
mod iter;
mod links;
mod traits;

pub use iter::{StrictOpenOptions, StrictReadDir};

use crate::validator::path_history::{BoundaryChecked, Canonicalized, PathHistory, Raw};
use crate::{Result, StrictPathError};
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Strip the Windows verbatim `\\?\` (and DOS device `\\.\`) prefix from a path.
///
/// The `junction` crate does not handle verbatim/device-namespace paths correctly —
/// it creates broken junctions that return ERROR_INVALID_NAME (123) when accessed.
/// This helper strips the prefix so junction creation works correctly.
///
/// Delegates to `dunce::simplified`, which pattern-matches `std::path::Prefix`
/// variants (no lossy UTF-8 round-trip) and refuses to strip when the target
/// would be unsafe — reserved device names (`COM1`, `NUL`, ...), paths longer
/// than `MAX_PATH`, and names ending in a dot/space.
#[cfg(all(windows, feature = "junctions"))]
pub(super) fn strip_verbatim_prefix(path: &Path) -> std::borrow::Cow<'_, Path> {
    std::borrow::Cow::Borrowed(dunce::simplified(path))
}

/// Hold a validated, system-facing filesystem path guaranteed to be within a `PathBoundary`.
///
/// Use when you need system-facing I/O with safety proofs. For user-facing display and rooted
/// virtual operations prefer `VirtualPath`. Operations like `strict_join` and
/// `strictpath_parent` preserve guarantees. `Display` shows the real system path. String
/// accessors are prefixed with `strictpath_` to avoid confusion.
#[derive(Clone)]
#[must_use = "a StrictPath is boundary-validated and ready for I/O — use .strict_join() to compose child paths, built-in I/O helpers (.read(), .write(), .create_file()), or pass to functions accepting &StrictPath<Marker>"]
#[doc(alias = "jailed_path")]
#[doc(alias = "safe_path")]
#[doc(alias = "sanitized_path")]
#[doc(alias = "sandboxed_path")]
pub struct StrictPath<Marker = ()> {
    path: PathHistory<((Raw, Canonicalized), BoundaryChecked)>,
    boundary: Arc<crate::PathBoundary<Marker>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> StrictPath<Marker> {
    /// Create the base `StrictPath` anchored at the provided boundary directory.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: If the boundary cannot be created/validated.
    ///
    /// Prefer passing `PathBoundary` in reusable flows.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::StrictPath;
    /// let base: StrictPath = StrictPath::with_boundary(std::env::temp_dir())?;
    /// assert!(base.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "with_boundary() returns the boundary root as a StrictPath — handle the Result, then use .strict_join() to validate untrusted input"]
    pub fn with_boundary<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let validated_dir = crate::PathBoundary::try_new(dir_path)?;
        validated_dir.into_strictpath()
    }

    /// Create the base `StrictPath`, creating the boundary directory if missing.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: If the directory cannot be created or canonicalized.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::StrictPath;
    /// let dir = std::env::temp_dir().join("strict-path-wbc-example");
    /// let base: StrictPath = StrictPath::with_boundary_create(&dir)?;
    /// assert!(base.is_dir());
    /// # std::fs::remove_dir_all(&dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "with_boundary_create() returns the boundary root as a StrictPath — handle the Result, then use .strict_join() to validate untrusted input"]
    pub fn with_boundary_create<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let validated_dir = crate::PathBoundary::try_new_create(dir_path)?;
        validated_dir.into_strictpath()
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

    /// Return the boundary path (always available, used internally by Debug and other impls).
    #[inline]
    pub(crate) fn boundary_path(&self) -> &Path {
        self.boundary.path()
    }

    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Return the underlying system path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # fn third_party_api(_p: impl AsRef<std::path::Path>) {}
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("data.bin")?;
    /// third_party_api(file_path.interop_path()); // AsRef<Path> satisfied
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "pass interop_path() directly to third-party APIs requiring AsRef<Path> — never wrap it in Path::new() or PathBuf::from() as that defeats boundary safety"]
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }

    /// Return a `Display` wrapper that shows the real system path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("notes.txt")?;
    /// println!("Path: {}", file_path.strictpath_display());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "strictpath_display() shows the real system path (admin/debug use) — for user-facing output prefer VirtualPath::virtualpath_display() which hides internal paths"]
    #[inline]
    pub fn strictpath_display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    /// Consume and return the inner `PathBuf` (escape hatch). Prefer `.interop_path()` (third-party adapters only) to borrow.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("output.bin")?;
    /// let raw: std::path::PathBuf = file_path.unstrict();
    /// // raw is now a plain PathBuf — use only for unavoidable interop
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "unstrict() consumes self and relinquishes boundary guarantees — use the returned PathBuf, or prefer .interop_path() to borrow without consuming"]
    #[inline]
    pub fn unstrict(self) -> PathBuf {
        self.path.into_inner()
    }

    /// Convert this `StrictPath` into a user‑facing `VirtualPath`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("docs/readme.md")?;
    /// let vpath = file_path.virtualize();
    /// let display = vpath.virtualpath_display();
    /// println!("{display}");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "virtualize() consumes self — use the returned VirtualPath for user-facing display (.virtualpath_display()) and virtual path operations"]
    #[cfg(feature = "virtual-path")]
    #[inline]
    pub fn virtualize(self) -> crate::path::virtual_path::VirtualPath<Marker> {
        crate::path::virtual_path::VirtualPath::new(self)
    }

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
    /// SECURITY:
    /// The caller MUST ensure the new marker reflects real-world permissions. This method does not
    /// perform any authorization checks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io;
    /// # struct UserFiles;
    /// # struct ReadOnly;
    /// # struct ReadWrite;
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-change-marker-example");
    /// # std::fs::create_dir_all(&boundary_dir.join("logs"))?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
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
    ///     data_dir.strict_join(requested_log)?.change_marker();
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
    /// # let data_dir: PathBoundary<ReadOnly> = PathBoundary::try_new(&boundary_dir).unwrap();
    /// let read_only_path: StrictPath<ReadOnly> = data_dir.strict_join("logs/app.log").unwrap();
    /// fn require_write(_: StrictPath<WritePermission>) {}
    /// // ❌ Compile error: expected `StrictPath<WritePermission>`, found `StrictPath<ReadOnly>`
    /// require_write(read_only_path);
    /// ```
    #[must_use = "change_marker() consumes self — the original StrictPath is moved; use the returned StrictPath<NewMarker>"]
    #[inline]
    pub fn change_marker<NewMarker>(self) -> StrictPath<NewMarker> {
        let StrictPath { path, boundary, .. } = self;

        // Unwrap the Arc (zero-cost if this is the only reference).
        // If other references exist, clone the boundary (allocation needed).
        let boundary_owned = Arc::unwrap_or_clone(boundary);
        let new_boundary = Arc::new(boundary_owned.change_marker::<NewMarker>());

        StrictPath {
            path,
            boundary: new_boundary,
            _marker: PhantomData,
        }
    }

    /// Consume and return a new `PathBoundary` anchored at this strict path.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: If the strict path does not exist
    ///   or is not a directory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("uploads")?;
    /// subdir.create_dir()?;
    /// let sub_boundary: PathBoundary = subdir.try_into_boundary()?;
    /// let _ = sub_boundary.strict_join("file.bin")?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "try_into_boundary() consumes self — use the returned PathBoundary for creating a new path restriction"]
    #[inline]
    pub fn try_into_boundary(self) -> Result<crate::PathBoundary<Marker>> {
        let StrictPath { path, .. } = self;
        crate::PathBoundary::try_new(path.into_inner())
    }

    /// Consume and return a `PathBoundary`, creating the directory if missing.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: If creation or canonicalization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("cache")?;
    /// // Directory does not exist yet — try_into_boundary_create will create it
    /// let sub_boundary: PathBoundary = subdir.try_into_boundary_create()?;
    /// let _ = sub_boundary.strict_join("item.bin")?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "try_into_boundary_create() consumes self — use the returned PathBoundary for creating a new path restriction"]
    #[inline]
    pub fn try_into_boundary_create(self) -> Result<crate::PathBoundary<Marker>> {
        let StrictPath { path, .. } = self;
        crate::PathBoundary::try_new_create(path.into_inner())
    }

    /// Join a path segment and re-validate against the boundary.
    ///
    /// Never wrap `.interop_path()` in `Path::new()` to use `Path::join()` — that defeats all
    /// security. After `.unstrict()` (explicit escape hatch), you own a `PathBuf`.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathResolutionError`, `StrictPathError::PathEscapesBoundary`.
    #[must_use = "strict_join() validates untrusted input against the boundary — always handle the Result to detect path traversal attacks"]
    #[inline]
    pub fn strict_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_systempath = self.path.join(path);
        self.boundary.strict_join(new_systempath)
    }

    /// Return the parent as a new `StrictPath`, or `None` at the boundary root.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathResolutionError`: If the parent path cannot be resolved.
    /// - `StrictPathError::PathEscapesBoundary`: If the parent escapes the boundary (cannot occur in practice).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("logs/app.log")?;
    /// if let Some(parent) = file_path.strictpath_parent()? {
    ///     assert!(parent.strictpath_display().to_string().ends_with("logs"));
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "strictpath_parent() returns Result<Option> — handle the error, then match Some(parent) for traversal or None at the boundary root"]
    pub fn strictpath_parent(&self) -> Result<Option<Self>> {
        // WHY: If `self` is the boundary root itself, `Path::parent()` returns
        // the *filesystem* parent (one level above the boundary). Passing that
        // to `strict_join` correctly rejects it with `PathEscapesBoundary`, but
        // from the caller's perspective "parent of the root" is semantically
        // `None`, not an error. Detect the root case explicitly so the
        // documented contract holds and downstream link/copy/rename fallbacks
        // that pattern-match `Ok(None)` are actually reachable.
        if self.path.as_ref() == self.boundary.path() {
            return Ok(None);
        }
        match self.path.parent() {
            Some(p) => self.boundary.strict_join(p).map(Some),
            None => Ok(None),
        }
    }

    /// Return a new path with file name changed, re‑validating against the boundary.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathResolutionError`: If the resulting path cannot be resolved.
    /// - `StrictPathError::PathEscapesBoundary`: If the new name would escape the boundary.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let original = data_dir.strict_join("docs/old.txt")?;
    /// let renamed = original.strictpath_with_file_name("new.txt")?;
    /// assert!(renamed.strictpath_display().to_string().ends_with("new.txt"));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "returns a new validated StrictPath with the file name replaced — the original is unchanged; handle the Result to detect boundary escapes"]
    #[inline]
    pub fn strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_systempath = self.path.with_file_name(file_name);
        self.boundary.strict_join(new_systempath)
    }

    /// Return a new path with extension changed; error at the boundary root.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::PathEscapesBoundary`: If called on the boundary root (no file name).
    /// - `StrictPathError::PathResolutionError`: If the resulting path cannot be resolved.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let original = data_dir.strict_join("report.txt")?;
    /// let converted = original.strictpath_with_extension("md")?;
    /// assert!(converted.strictpath_display().to_string().ends_with("report.md"));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "returns a new validated StrictPath with the extension changed — the original is unchanged; handle the Result to detect boundary escapes"]
    pub fn strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let system_path = &self.path;
        if system_path.file_name().is_none() {
            return Err(StrictPathError::path_escapes_boundary(
                self.path.to_path_buf(),
                self.boundary.path().to_path_buf(),
            ));
        }
        // WHY: `Path::with_extension` panics when the extension contains a
        // path separator. Untrusted callers must get an `Err`, never a crash.
        let new_systempath = crate::path::with_validated_extension(system_path, extension.as_ref())?;
        self.boundary.strict_join(new_systempath)
    }

    /// Return the file name component of the system path, if any.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("notes.txt")?;
    /// assert_eq!(file_path.strictpath_file_name().unwrap(), "notes.txt");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn strictpath_file_name(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Return the file stem of the system path, if any.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("report.txt")?;
    /// assert_eq!(file_path.strictpath_file_stem().unwrap(), "report");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn strictpath_file_stem(&self) -> Option<&OsStr> {
        self.path.file_stem()
    }

    /// Return the extension of the system path, if any.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("archive.tar.gz")?;
    /// assert_eq!(file_path.strictpath_extension().unwrap(), "gz");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn strictpath_extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    /// Return `true` if the system path starts with the given prefix.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("logs/app.log")?;
    /// // Use the boundary's canonical path (interop_path) as the prefix to compare against
    /// assert!(file_path.strictpath_starts_with(data_dir.interop_path()));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn strictpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    /// Return `true` if the system path ends with the given suffix.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("reports/summary.csv")?;
    /// assert!(file_path.strictpath_ends_with("summary.csv"));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn strictpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.ends_with(p.as_ref())
    }

    /// Return `true` if the system path exists.
    ///
    /// Permission errors return `false`; use `try_exists` to distinguish.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("data.txt")?;
    /// assert!(!file_path.exists());
    /// file_path.write("hello")?;
    /// assert!(file_path.exists());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Return `true` if the system path is a file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("item.txt")?;
    /// file_path.write("x")?;
    /// assert!(file_path.is_file());
    /// assert!(!data_dir.strict_join(".")?.is_file());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    /// Return `true` if the system path is a directory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("sub")?;
    /// subdir.create_dir()?;
    /// assert!(subdir.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Return the metadata for the system path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("info.txt")?;
    /// file_path.write("hello")?;
    /// let meta = file_path.metadata()?;
    /// assert_eq!(meta.len(), 5);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
    }

    /// Return the metadata for the system path without following symlinks (like `std::fs::symlink_metadata`).
    ///
    /// This retrieves metadata about the path entry itself. On symlinks, this reports
    /// information about the link, not the target.
    #[inline]
    pub fn symlink_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(&self.path)
    }

    /// Set permissions on the file or directory at this path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file = data_dir.strict_join("script.sh")?;
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

    /// Check if the path exists, returning an error on permission issues.
    ///
    /// Unlike `exists()` which returns `false` on permission errors, this method
    /// distinguishes between "path does not exist" (`Ok(false)`) and "cannot check
    /// due to permission error" (`Err(...)`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// let existing = data_dir.strict_join("exists.txt")?;
    /// existing.write("content")?;
    /// assert_eq!(existing.try_exists()?, true);
    ///
    /// let missing = data_dir.strict_join("missing.txt")?;
    /// assert_eq!(missing.try_exists()?, false);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn try_exists(&self) -> std::io::Result<bool> {
        self.path.try_exists()
    }

    /// Create an empty file if it doesn't exist, or update the modification time if it does.
    ///
    /// This is a convenience method combining file creation and mtime update.
    /// Uses `OpenOptions` with `create(true).write(true)` which creates the file
    /// if missing or opens it for writing if it exists, updating mtime on close.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// let file = data_dir.strict_join("marker.txt")?;
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

    /// Read directory entries at this path (discovery). Re‑join names through strict/virtual APIs before I/O.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the path is not a directory or cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// data_dir.strict_join("file.txt")?.write("x")?;
    /// for entry in data_dir.strict_join(".")?.read_dir()? {
    ///     let entry = entry?;
    ///     let child = data_dir.strict_join(entry.file_name())?;
    ///     let child_display = child.strictpath_display();
    ///     println!("{child_display}");
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.path)
    }

    /// Read directory entries as validated `StrictPath` values (auto re-joins each entry).
    ///
    /// Unlike `read_dir()` which returns raw `std::fs::DirEntry`, this method automatically
    /// validates each directory entry through `strict_join()`, returning an iterator of
    /// `Result<StrictPath<Marker>>`. This eliminates the need for manual re-validation loops.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the directory cannot be read.
    /// - Each yielded item may also be `Err` if validation fails for that entry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// # let dir = data_dir.strict_join("data")?;
    /// # dir.create_dir_all()?;
    /// # data_dir.strict_join("data/file1.txt")?.write("a")?;
    /// # data_dir.strict_join("data/file2.txt")?.write("b")?;
    /// // Iterate with automatic validation
    /// for entry in dir.strict_read_dir()? {
    ///     let child: StrictPath = entry?;
    ///     let child_display = child.strictpath_display();
    ///     println!("{child_display}");
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
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the file cannot be read or contains invalid UTF-8.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("hello.txt")?;
    /// file_path.write("hello world")?;
    /// assert_eq!(file_path.read_to_string()?, "hello world");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    /// Reads the file contents as raw bytes.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the file cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("data.bin")?;
    /// file_path.write(b"\x00\x01\x02")?;
    /// assert_eq!(file_path.read()?, vec![0, 1, 2]);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Write bytes to the file (create if missing). Accepts any `AsRef<[u8]>` (e.g., `&str`, `&[u8]`).
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the file cannot be created or written (e.g., parent missing, permission denied).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("config.toml")?;
    /// file_path.write("[server]\nport = 8080\n")?;
    /// assert_eq!(file_path.read_to_string()?, "[server]\nport = 8080\n");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn write<C: AsRef<[u8]>>(&self, contents: C) -> std::io::Result<()> {
        std::fs::write(&self.path, contents)
    }

    /// Append bytes to the file (create if missing). Accepts any `AsRef<[u8]>` (e.g., `&str`, `&[u8]`).
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: Propagates OS errors when the file cannot be opened or written.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-append-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let log_file = "logs/audit.log";
    /// let log_path: StrictPath = data_dir.strict_join(log_file)?;
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
}
