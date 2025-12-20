// Content copied from original src/path/virtual_path.rs
use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::{Canonicalized, PathHistory};
use crate::PathBoundary;
use crate::Result;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// SUMMARY:
/// Hold a user‑facing path clamped to a virtual root (`"/"`) over a `PathBoundary`.
///
/// DETAILS:
/// `virtualpath_display()` shows rooted, forward‑slashed paths (e.g., `"/a/b.txt"`).
/// Use virtual manipulation methods to compose paths while preserving clamping, then convert to
/// `StrictPath` with `unvirtual()` for system‑facing I/O.
#[derive(Clone)]
pub struct VirtualPath<Marker = ()> {
    inner: StrictPath<Marker>,
    virtual_path: PathBuf,
}

#[inline]
fn clamp<Marker, H>(
    restriction: &PathBoundary<Marker>,
    anchored: PathHistory<(H, Canonicalized)>,
) -> crate::Result<crate::path::strict_path::StrictPath<Marker>> {
    restriction.strict_join(anchored.into_inner())
}

impl<Marker> VirtualPath<Marker> {
    /// SUMMARY:
    /// Create the virtual root (`"/"`) for the given filesystem root.
    pub fn with_root<P: AsRef<Path>>(root: P) -> Result<Self> {
        let vroot = crate::validator::virtual_root::VirtualRoot::try_new(root)?;
        vroot.into_virtualpath()
    }

    /// SUMMARY:
    /// Create the virtual root, creating the filesystem root if missing.
    pub fn with_root_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let vroot = crate::validator::virtual_root::VirtualRoot::try_new_create(root)?;
        vroot.into_virtualpath()
    }
    #[inline]
    pub(crate) fn new(strict_path: StrictPath<Marker>) -> Self {
        fn compute_virtual<Marker>(
            system_path: &std::path::Path,
            restriction: &crate::PathBoundary<Marker>,
        ) -> std::path::PathBuf {
            use std::ffi::OsString;
            use std::path::Component;

            #[cfg(windows)]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                let s = p.as_os_str().to_string_lossy();
                if let Some(trimmed) = s.strip_prefix("\\\\?\\") {
                    return std::path::PathBuf::from(trimmed);
                }
                if let Some(trimmed) = s.strip_prefix("\\\\.\\") {
                    return std::path::PathBuf::from(trimmed);
                }
                std::path::PathBuf::from(s.to_string())
            }

            #[cfg(not(windows))]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                p.to_path_buf()
            }

            let system_norm = strip_verbatim(system_path);
            let jail_norm = strip_verbatim(restriction.path());

            if let Ok(stripped) = system_norm.strip_prefix(&jail_norm) {
                let mut cleaned = std::path::PathBuf::new();
                for comp in stripped.components() {
                    if let Component::Normal(name) = comp {
                        let s = name.to_string_lossy();
                        let cleaned_s = s.replace(['\n', ';'], "_");
                        if cleaned_s == s {
                            cleaned.push(name);
                        } else {
                            cleaned.push(OsString::from(cleaned_s));
                        }
                    }
                }
                return cleaned;
            }

            let mut strictpath_comps: Vec<_> = system_norm
                .components()
                .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect();
            let mut boundary_comps: Vec<_> = jail_norm
                .components()
                .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect();

            #[cfg(windows)]
            fn comp_eq(a: &Component, b: &Component) -> bool {
                match (a, b) {
                    (Component::Normal(x), Component::Normal(y)) => {
                        x.to_string_lossy().to_ascii_lowercase()
                            == y.to_string_lossy().to_ascii_lowercase()
                    }
                    _ => false,
                }
            }

            #[cfg(not(windows))]
            fn comp_eq(a: &Component, b: &Component) -> bool {
                a == b
            }

            while !strictpath_comps.is_empty()
                && !boundary_comps.is_empty()
                && comp_eq(&strictpath_comps[0], &boundary_comps[0])
            {
                strictpath_comps.remove(0);
                boundary_comps.remove(0);
            }

            let mut vb = std::path::PathBuf::new();
            for c in strictpath_comps {
                if let Component::Normal(name) = c {
                    let s = name.to_string_lossy();
                    let cleaned = s.replace(['\n', ';'], "_");
                    if cleaned == s {
                        vb.push(name);
                    } else {
                        vb.push(OsString::from(cleaned));
                    }
                }
            }
            vb
        }

        let virtual_path = compute_virtual(strict_path.path(), strict_path.boundary());

        Self {
            inner: strict_path,
            virtual_path,
        }
    }

    /// SUMMARY:
    /// Convert this `VirtualPath` back into a system‑facing `StrictPath`.
    #[inline]
    pub fn unvirtual(self) -> StrictPath<Marker> {
        self.inner
    }

    /// SUMMARY:
    /// Change the compile-time marker while keeping the virtual and strict views in sync.
    ///
    /// WHEN TO USE:
    /// - After authenticating/authorizing a user and granting them access to a virtual path
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
    /// - `VirtualPath<NewMarker>`: Same clamped path encoded with the new marker.
    ///
    /// ERRORS:
    /// - `_none_`
    ///
    /// SECURITY:
    /// This method performs no permission checks. Only elevate markers after verifying real
    /// authorization out-of-band.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualPath;
    /// # struct GuestAccess;
    /// # struct UserAccess;
    /// # let root_dir = std::env::temp_dir().join("virtual-change-marker-example");
    /// # std::fs::create_dir_all(&root_dir)?;
    /// # let guest_root: VirtualPath<GuestAccess> = VirtualPath::with_root(&root_dir)?;
    /// // Simulated authorization: verify user credentials before granting access
    /// fn grant_user_access(user_token: &str, path: VirtualPath<GuestAccess>) -> Option<VirtualPath<UserAccess>> {
    ///     if user_token == "valid-token-12345" {
    ///         Some(path.change_marker())  // ✅ Only after token validation
    ///     } else {
    ///         None  // ❌ Invalid token
    ///     }
    /// }
    ///
    /// // Untrusted input from request/CLI/config/etc.
    /// let requested_file = "docs/readme.md";
    /// let guest_path: VirtualPath<GuestAccess> = guest_root.virtual_join(requested_file)?;
    /// let user_path = grant_user_access("valid-token-12345", guest_path).expect("authorized");
    /// assert_eq!(user_path.virtualpath_display().to_string(), "/docs/readme.md");
    /// # std::fs::remove_dir_all(&root_dir)?;
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
    /// # use strict_path::VirtualPath;
    /// # struct GuestAccess;
    /// # struct EditorAccess;
    /// # let root_dir = std::env::temp_dir().join("virtual-change-marker-deny");
    /// # std::fs::create_dir_all(&root_dir).unwrap();
    /// # let guest_root: VirtualPath<GuestAccess> = VirtualPath::with_root(&root_dir).unwrap();
    /// fn require_editor(_: VirtualPath<EditorAccess>) {}
    /// let guest_file = guest_root.virtual_join("docs/manual.txt").unwrap();
    /// // ❌ Compile error: expected `VirtualPath<EditorAccess>`, found `VirtualPath<GuestAccess>`
    /// require_editor(guest_file);
    /// ```
    #[inline]
    pub fn change_marker<NewMarker>(self) -> VirtualPath<NewMarker> {
        let VirtualPath {
            inner,
            virtual_path,
        } = self;

        VirtualPath {
            inner: inner.change_marker(),
            virtual_path,
        }
    }

    /// SUMMARY:
    /// Consume and return the `VirtualRoot` for its boundary (no directory creation).
    ///
    /// RETURNS:
    /// - `Result<VirtualRoot<Marker>>`: Virtual root anchored at the strict path's directory.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: Propagated from `try_into_boundary` when the
    ///   strict path does not exist or is not a directory.
    #[inline]
    pub fn try_into_root(self) -> Result<crate::validator::virtual_root::VirtualRoot<Marker>> {
        Ok(self.inner.try_into_boundary()?.virtualize())
    }

    /// SUMMARY:
    /// Consume and return a `VirtualRoot`, creating the underlying directory if missing.
    ///
    /// RETURNS:
    /// - `Result<VirtualRoot<Marker>>`: Virtual root anchored at the strict path's directory
    ///   (created if necessary).
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: Propagated from `try_into_boundary` or directory
    ///   creation failures wrapped in `InvalidRestriction`.
    #[inline]
    pub fn try_into_root_create(
        self,
    ) -> Result<crate::validator::virtual_root::VirtualRoot<Marker>> {
        let strict_path = self.inner;
        let boundary = strict_path.try_into_boundary_create()?;
        Ok(boundary.virtualize())
    }

    /// SUMMARY:
    /// Borrow the underlying system‑facing `StrictPath` (no allocation).
    #[inline]
    pub fn as_unvirtual(&self) -> &StrictPath<Marker> {
        &self.inner
    }

    /// SUMMARY:
    /// Return the underlying system path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop.
    #[inline]
    pub fn interop_path(&self) -> &OsStr {
        self.inner.interop_path()
    }

    /// SUMMARY:
    /// Join a virtual path segment (virtual semantics) and re‑validate within the same restriction.
    ///
    /// DETAILS:
    /// Applies virtual path clamping: absolute paths are interpreted relative to the virtual root,
    /// and traversal attempts are clamped to prevent escaping the boundary. This method maintains
    /// the security guarantee that all `VirtualPath` instances stay within their virtual root.
    ///
    /// PARAMETERS:
    /// - `path` (`impl AsRef<Path>`): Path segment to join. Absolute paths are clamped to virtual root.
    ///
    /// RETURNS:
    /// - `Result<VirtualPath<Marker>>`: New virtual path within the same restriction.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    /// let base = vroot.virtual_join("data")?;
    ///
    /// // Absolute paths are clamped to virtual root
    /// let abs = base.virtual_join("/etc/config")?;
    /// assert_eq!(abs.virtualpath_display().to_string(), "/etc/config");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        // Compose candidate in virtual space (do not pre-normalize lexically to preserve symlink semantics)
        let candidate = self.virtual_path.join(path.as_ref());
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.boundary())?;
        let boundary_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(boundary_path))
    }

    // No local clamping helpers; virtual flows should route through
    // PathHistory::virtualize_to_jail + PathBoundary::strict_join to avoid drift.

    /// SUMMARY:
    /// Return the parent virtual path, or `None` at the virtual root.
    pub fn virtualpath_parent(&self) -> Result<Option<Self>> {
        match self.virtual_path.parent() {
            Some(parent_virtual_path) => {
                let anchored = crate::validator::path_history::PathHistory::new(
                    parent_virtual_path.to_path_buf(),
                )
                .canonicalize_anchored(self.inner.boundary())?;
                let validated_path = clamp(self.inner.boundary(), anchored)?;
                Ok(Some(VirtualPath::new(validated_path)))
            }
            None => Ok(None),
        }
    }

    /// SUMMARY:
    /// Return a new virtual path with file name changed, preserving clamping.
    #[inline]
    pub fn virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let candidate = self.virtual_path.with_file_name(file_name);
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.boundary())?;
        let validated_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(validated_path))
    }

    /// SUMMARY:
    /// Return a new virtual path with the extension changed, preserving clamping.
    pub fn virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        if self.virtual_path.file_name().is_none() {
            return Err(StrictPathError::path_escapes_boundary(
                self.virtual_path.clone(),
                self.inner.boundary().path().to_path_buf(),
            ));
        }

        let candidate = self.virtual_path.with_extension(extension);
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.boundary())?;
        let validated_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(validated_path))
    }

    /// SUMMARY:
    /// Return the file name component of the virtual path, if any.
    #[inline]
    pub fn virtualpath_file_name(&self) -> Option<&OsStr> {
        self.virtual_path.file_name()
    }

    /// SUMMARY:
    /// Return the file stem of the virtual path, if any.
    #[inline]
    pub fn virtualpath_file_stem(&self) -> Option<&OsStr> {
        self.virtual_path.file_stem()
    }

    /// SUMMARY:
    /// Return the extension of the virtual path, if any.
    #[inline]
    pub fn virtualpath_extension(&self) -> Option<&OsStr> {
        self.virtual_path.extension()
    }

    /// SUMMARY:
    /// Return `true` if the virtual path starts with the given prefix (virtual semantics).
    #[inline]
    pub fn virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.starts_with(p)
    }

    /// SUMMARY:
    /// Return `true` if the virtual path ends with the given suffix (virtual semantics).
    #[inline]
    pub fn virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.ends_with(p)
    }

    /// SUMMARY:
    /// Return a Display wrapper that shows a rooted virtual path (e.g., `"/a/b.txt").
    #[inline]
    pub fn virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker> {
        VirtualPathDisplay(self)
    }

    /// SUMMARY:
    /// Return `true` if the underlying system path exists.
    #[inline]
    pub fn exists(&self) -> bool {
        self.inner.exists()
    }

    /// SUMMARY:
    /// Return `true` if the underlying system path is a file.
    #[inline]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    /// SUMMARY:
    /// Return `true` if the underlying system path is a directory.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    /// SUMMARY:
    /// Return metadata for the underlying system path.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata()
    }

    /// SUMMARY:
    /// Read the file contents as `String` from the underlying system path.
    #[inline]
    pub fn read_to_string(&self) -> std::io::Result<String> {
        self.inner.read_to_string()
    }

    /// SUMMARY:
    /// Read raw bytes from the underlying system path.
    #[inline]
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read()
    }

    /// SUMMARY:
    /// Return metadata for the underlying system path without following symlinks.
    #[inline]
    pub fn symlink_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata()
    }

    /// SUMMARY:
    /// Read directory entries (discovery). Re‑join names with `virtual_join(...)` to preserve clamping.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        self.inner.read_dir()
    }

    /// SUMMARY:
    /// Write bytes to the underlying system path. Accepts `&str`, `String`, `&[u8]`, `Vec<u8]`, etc.
    #[inline]
    pub fn write<C: AsRef<[u8]>>(&self, contents: C) -> std::io::Result<()> {
        self.inner.write(contents)
    }

    /// SUMMARY:
    /// Append bytes to the underlying system path (create if missing). Accepts `&str`, `&[u8]`, etc.
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
    /// # use strict_path::VirtualRoot;
    /// # let root = std::env::temp_dir().join("strict-path-vpath-append");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let log_file = "logs/activity.log";
    /// let vpath = vroot.virtual_join(log_file)?;
    /// vpath.create_parent_dir_all()?;
    /// vpath.append("[2025-01-01] Operation A\n")?;
    /// vpath.append("[2025-01-01] Operation B\n")?;
    /// let contents = vpath.read_to_string()?;
    /// assert!(contents.contains("Operation A"));
    /// assert!(contents.contains("Operation B"));
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn append<C: AsRef<[u8]>>(&self, data: C) -> std::io::Result<()> {
        self.inner.append(data)
    }

    /// SUMMARY:
    /// Create or truncate the file at this virtual path and return a writable handle.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Writable handle scoped to the same virtual root restriction.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates operating-system errors when the parent directory is missing or file creation fails.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # use std::io::Write;
    /// # let root = std::env::temp_dir().join("strict-path-virtual-create-file");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// let report = vroot.virtual_join("reports/summary.txt")?;
    /// report.create_parent_dir_all()?;
    /// let mut file = report.create_file()?;
    /// file.write_all(b"summary")?;
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create_file(&self) -> std::io::Result<std::fs::File> {
        self.inner.create_file()
    }

    /// SUMMARY:
    /// Open the file at this virtual path in read-only mode.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Read-only handle scoped to the same virtual root restriction.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates operating-system errors when the file is missing or inaccessible.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # use std::io::{Read, Write};
    /// # let root = std::env::temp_dir().join("strict-path-virtual-open-file");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// let report = vroot.virtual_join("reports/summary.txt")?;
    /// report.create_parent_dir_all()?;
    /// report.write("summary")?;
    /// let mut file = report.open_file()?;
    /// let mut contents = String::new();
    /// file.read_to_string(&mut contents)?;
    /// assert_eq!(contents, "summary");
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open_file(&self) -> std::io::Result<std::fs::File> {
        self.inner.open_file()
    }

    /// SUMMARY:
    /// Create all directories in the underlying system path if missing.
    #[inline]
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        self.inner.create_dir_all()
    }

    /// SUMMARY:
    /// Create the directory at this virtual location (non‑recursive). Fails if parent missing.
    #[inline]
    pub fn create_dir(&self) -> std::io::Result<()> {
        self.inner.create_dir()
    }

    /// SUMMARY:
    /// Create only the immediate parent of this virtual path (non‑recursive). `Ok(())` at virtual root.
    #[inline]
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.virtualpath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            Err(crate::StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// SUMMARY:
    /// Recursively create all missing directories up to the immediate parent. `Ok(())` at virtual root.
    #[inline]
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.virtualpath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            Err(crate::StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// SUMMARY:
    /// Remove the file at the underlying system path.
    #[inline]
    pub fn remove_file(&self) -> std::io::Result<()> {
        self.inner.remove_file()
    }

    /// SUMMARY:
    /// Remove the directory at the underlying system path.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        self.inner.remove_dir()
    }

    /// SUMMARY:
    /// Recursively remove the directory and its contents at the underlying system path.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        self.inner.remove_dir_all()
    }

    /// SUMMARY:
    /// Create a symlink at `link_path` pointing to this virtual path (same virtual root required).
    ///
    /// DETAILS:
    /// Both `self` (target) and `link_path` must be `VirtualPath` instances created via `virtual_join()`,
    /// which ensures all paths are clamped to the virtual root. Absolute paths like `"/etc/config"`
    /// passed to `virtual_join()` are automatically clamped to `vroot/etc/config`, ensuring symlinks
    /// cannot escape the virtual root boundary.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    ///
    /// // Create target file
    /// let target = vroot.virtual_join("/etc/config/app.conf")?;
    /// target.create_parent_dir_all()?;
    /// target.write(b"config data")?;
    ///
    /// // Ensure link parent directory exists (Windows requires this for symlink creation)
    /// let link = vroot.virtual_join("/links/config.link")?;
    /// link.create_parent_dir_all()?;
    ///
    /// // Create symlink - may fail on Windows without Developer Mode/admin privileges
    /// if let Err(e) = target.virtual_symlink("/links/config.link") {
    ///     // Skip test if we don't have symlink privileges (Windows ERROR_PRIVILEGE_NOT_HELD = 1314)
    ///     #[cfg(windows)]
    ///     if e.raw_os_error() == Some(1314) { return Ok(()); }
    ///     return Err(e.into());
    /// }
    ///
    /// assert_eq!(link.read_to_string()?, "config data");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();
        let validated_link = if link_ref.is_absolute() {
            match self.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            // Resolve as sibling
            let parent = match self.virtualpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self
                    .inner
                    .boundary()
                    .clone()
                    .virtualize()
                    .into_virtualpath()
                {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        self.inner.strict_symlink(validated_link.inner.path())
    }

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this virtual path (same virtual root required).
    ///
    /// DETAILS:
    /// Both `self` (target) and `link_path` must be `VirtualPath` instances created via `virtual_join()`,
    /// which ensures all paths are clamped to the virtual root. Absolute paths like `"/etc/data"`
    /// passed to `virtual_join()` are automatically clamped to `vroot/etc/data`, ensuring hard links
    /// cannot escape the virtual root boundary.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    ///
    /// // Create target file
    /// let target = vroot.virtual_join("/shared/data.dat")?;
    /// target.create_parent_dir_all()?;
    /// target.write(b"shared data")?;
    ///
    /// // Ensure link parent directory exists (Windows requires this for hard link creation)
    /// let link = vroot.virtual_join("/backup/data.dat")?;
    /// link.create_parent_dir_all()?;
    ///
    /// // Create hard link
    /// target.virtual_hard_link("/backup/data.dat")?;
    ///
    /// // Read through link path, verify through target (hard link behavior)
    /// link.write(b"modified")?;
    /// assert_eq!(target.read_to_string()?, "modified");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();
        let validated_link = if link_ref.is_absolute() {
            match self.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            // Resolve as sibling
            let parent = match self.virtualpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self
                    .inner
                    .boundary()
                    .clone()
                    .virtualize()
                    .into_virtualpath()
                {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        self.inner.strict_hard_link(validated_link.inner.path())
    }

    /// SUMMARY:
    /// Create a Windows NTFS directory junction at `link_path` pointing to this virtual path.
    ///
    /// DETAILS:
    /// - Windows-only and behind the `junctions` feature.
    /// - Directory-only semantics; both paths must share the same virtual root.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn virtual_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        // Mirror virtual semantics used by symlink/hard-link helpers:
        // - Absolute paths are interpreted in the VIRTUAL namespace and clamped to this root
        // - Relative paths are resolved as siblings (or from the virtual root when at root)
        let link_ref = link_path.as_ref();
        let validated_link = if link_ref.is_absolute() {
            match self.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.virtualpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self
                    .inner
                    .boundary()
                    .clone()
                    .virtualize()
                    .into_virtualpath()
                {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.virtual_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        // Delegate to strict helper after validating link location in virtual space
        self.inner.strict_junction(validated_link.inner.path())
    }

    /// SUMMARY:
    /// Rename/move within the same virtual root. Relative destinations are siblings; absolute are clamped to root.
    ///
    /// DETAILS:
    /// Accepts `impl AsRef<Path>` for the destination. Absolute paths (starting with `"/"`) are
    /// automatically clamped to the virtual root via internal `virtual_join()` call, ensuring the
    /// destination cannot escape the virtual boundary. Relative paths are resolved as siblings.
    /// Parent directories are not created automatically.
    ///
    /// PARAMETERS:
    /// - `dest` (`impl AsRef<Path>`): Destination path. Absolute paths like `"/archive/file.txt"`
    ///   are clamped to `vroot/archive/file.txt`.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    ///
    /// let source = vroot.virtual_join("temp/file.txt")?;
    /// source.create_parent_dir_all()?;
    /// source.write(b"content")?;
    ///
    /// // Absolute destination path is clamped to virtual root
    /// let dest_dir = vroot.virtual_join("/archive")?;
    /// dest_dir.create_dir_all()?;
    /// source.virtual_rename("/archive/file.txt")?;
    ///
    /// let renamed = vroot.virtual_join("/archive/file.txt")?;
    /// assert_eq!(renamed.read_to_string()?, "content");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_rename<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<()> {
        let dest_ref = dest.as_ref();
        let dest_v = if dest_ref.is_absolute() {
            match self.virtual_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            // Resolve as sibling under the current virtual parent (or root if at "/")
            let parent = match self.virtualpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self
                    .inner
                    .boundary()
                    .clone()
                    .virtualize()
                    .into_virtualpath()
                {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.virtual_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        // Perform the actual rename via StrictPath
        self.inner.strict_rename(dest_v.inner.path())
    }

    /// SUMMARY:
    /// Copy within the same virtual root. Relative destinations are siblings; absolute are clamped to root.
    ///
    /// DETAILS:
    /// Accepts `impl AsRef<Path>` for the destination. Absolute paths (starting with `"/"`) are
    /// automatically clamped to the virtual root via internal `virtual_join()` call, ensuring the
    /// destination cannot escape the virtual boundary. Relative paths are resolved as siblings.
    /// Parent directories are not created automatically. Returns the number of bytes copied.
    ///
    /// PARAMETERS:
    /// - `dest` (`impl AsRef<Path>`): Destination path. Absolute paths like `"/backup/file.txt"`
    ///   are clamped to `vroot/backup/file.txt`.
    ///
    /// RETURNS:
    /// - `u64`: Number of bytes copied.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    ///
    /// let source = vroot.virtual_join("data/source.txt")?;
    /// source.create_parent_dir_all()?;
    /// source.write(b"data to copy")?;
    ///
    /// // Absolute destination path is clamped to virtual root
    /// let dest_dir = vroot.virtual_join("/backup")?;
    /// dest_dir.create_dir_all()?;
    /// let bytes = source.virtual_copy("/backup/copy.txt")?;
    ///
    /// let copied = vroot.virtual_join("/backup/copy.txt")?;
    /// assert_eq!(copied.read_to_string()?, "data to copy");
    /// assert_eq!(bytes, 12);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_copy<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<u64> {
        let dest_ref = dest.as_ref();
        let dest_v = if dest_ref.is_absolute() {
            match self.virtual_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            // Resolve as sibling under the current virtual parent (or root if at "/")
            let parent = match self.virtualpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self
                    .inner
                    .boundary()
                    .clone()
                    .virtualize()
                    .into_virtualpath()
                {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.virtual_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        // Perform the actual copy via StrictPath
        std::fs::copy(self.inner.path(), dest_v.inner.path())
    }
}

pub struct VirtualPathDisplay<'a, Marker>(&'a VirtualPath<Marker>);

impl<'a, Marker> fmt::Display for VirtualPathDisplay<'a, Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ensure leading slash and normalize to forward slashes for display
        let s_lossy = self.0.virtual_path.to_string_lossy();
        let s_norm: std::borrow::Cow<'_, str> = {
            #[cfg(windows)]
            {
                std::borrow::Cow::Owned(s_lossy.replace('\\', "/"))
            }
            #[cfg(not(windows))]
            {
                std::borrow::Cow::Borrowed(&s_lossy)
            }
        };
        if s_norm.starts_with('/') {
            write!(f, "{s_norm}")
        } else {
            write!(f, "/{s_norm}")
        }
    }
}

impl<Marker> fmt::Debug for VirtualPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualPath")
            .field("system_path", &self.inner.path())
            .field("virtual", &format!("{}", self.virtualpath_display()))
            .field("boundary", &self.inner.boundary().path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

impl<Marker> PartialEq for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.path() == other.inner.path()
    }
}

impl<Marker> Eq for VirtualPath<Marker> {}

impl<Marker> Hash for VirtualPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.path().hash(state);
    }
}

impl<Marker> PartialEq<crate::path::strict_path::StrictPath<Marker>> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::strict_path::StrictPath<Marker>) -> bool {
        self.inner.path() == other.path()
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &T) -> bool {
        // Compare virtual paths - the user-facing representation
        // If you want system path comparison, use as_unvirtual()
        let virtual_str = format!("{}", self.virtualpath_display());
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_str();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        normalized_virtual == normalized_other
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for VirtualPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        // Compare virtual paths - the user-facing representation
        let virtual_str = format!("{}", self.virtualpath_display());
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_str();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        Some(normalized_virtual.cmp(&normalized_other))
    }
}

impl<Marker> PartialOrd for VirtualPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for VirtualPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.path().cmp(other.inner.path())
    }
}
