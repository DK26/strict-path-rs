//! `VirtualPath<Marker>` — a user-facing path clamped to a virtual root.
//!
//! `VirtualPath` wraps a `StrictPath` and adds a virtual path component rooted at `"/"`.
//! The virtual path is what users see (e.g., `"/uploads/logo.png"`); the real system path
//! is never exposed. Use `virtualpath_display()` for safe user-visible output and
//! `as_unvirtual()` to obtain the underlying `StrictPath` for system-facing I/O.
mod display;
mod fs;
mod iter;
mod links;
mod traits;

pub use display::VirtualPathDisplay;
pub use iter::VirtualReadDir;

use crate::error::StrictPathError;
use crate::path::strict_path::StrictPath;
use crate::validator::path_history::{Canonicalized, PathHistory};
use crate::PathBoundary;
use crate::Result;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Hold a user‑facing path clamped to a virtual root (`"/"`) over a `PathBoundary`.
///
/// `virtualpath_display()` shows rooted, forward‑slashed paths (e.g., `"/a/b.txt"`).
/// Use virtual manipulation methods to compose paths while preserving clamping, then convert to
/// `StrictPath` with `unvirtual()` for system‑facing I/O.
#[derive(Clone)]
#[must_use = "a VirtualPath is boundary-validated and user-facing — use .virtualpath_display() for safe user output, .virtual_join() to compose paths, or .as_unvirtual() for system-facing I/O"]
#[doc(alias = "jailed_path")]
#[doc(alias = "sandboxed_path")]
#[doc(alias = "contained_path")]
pub struct VirtualPath<Marker = ()> {
    pub(crate) inner: StrictPath<Marker>,
    pub(crate) virtual_path: PathBuf,
}

/// Replace C0 / DEL control bytes and `;` with `_` for safe Display output.
///
/// WHY: `virtualpath_display` is the one API surface whose output the crate
/// actively encourages embedding in user-facing channels (HTTP responses,
/// logs, terminal prints). Every byte below 0x20 and the DEL byte is a known
/// injection primitive in one of those channels:
///   - `\n`, `\r` — CRLF header splitting, log-line splitting
///   - `\x1b` — ANSI escape sequences (screen clear, cursor control, fake prompts)
///   - `\t`, `\x08`, `\x0c` — layout mangling that can hide characters
///   - NUL, other C0 — terminal quirks and tool-specific parser glitches
///   - `\x7f` (DEL) — terminal erase behavior on some emulators
/// `;` is kept in the list because shell display of the path may feed into a
/// downstream command line reader.
fn sanitize_display_component(component: &str) -> String {
    let mut out = String::with_capacity(component.len());
    for ch in component.chars() {
        let needs_replace = ch == ';'
            || ch == '\x7f'
            || (ch as u32) < 0x20;
        if needs_replace {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Re-validate a canonicalized path against the boundary after virtual-space manipulation.
///
/// Every virtual mutation (join, parent, with_*) produces a candidate in virtual space that
/// must be re-anchored and boundary-checked before it becomes a real `StrictPath`. This
/// centralizes that re-validation so each caller does not duplicate the check.
#[inline]
fn clamp<Marker, H>(
    restriction: &PathBoundary<Marker>,
    anchored: PathHistory<(H, Canonicalized)>,
) -> crate::Result<crate::path::strict_path::StrictPath<Marker>> {
    restriction.strict_join(anchored.into_inner())
}

impl<Marker> VirtualPath<Marker> {
    /// Create the virtual root (`"/"`) for the given filesystem root.
    #[must_use = "this returns a Result containing the validated VirtualPath — handle the Result to detect invalid roots"]
    pub fn with_root<P: AsRef<Path>>(root: P) -> Result<Self> {
        let vroot = crate::validator::virtual_root::VirtualRoot::try_new(root)?;
        vroot.into_virtualpath()
    }

    /// Create the virtual root, creating the filesystem root if missing.
    #[must_use = "this returns a Result containing the validated VirtualPath — handle the Result to detect invalid roots"]
    pub fn with_root_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let vroot = crate::validator::virtual_root::VirtualRoot::try_new_create(root)?;
        vroot.into_virtualpath()
    }

    #[inline]
    pub(crate) fn new(strict_path: StrictPath<Marker>) -> Self {
        /// Derive the user-facing virtual path from the real system path and boundary.
        ///
        /// WHY: Users must never see the real host path (leaks tenant IDs, infra details).
        /// This function strips the boundary prefix from the system path and sanitizes
        /// the remaining components to produce a safe, rooted virtual view.
        fn compute_virtual<Marker>(
            system_path: &std::path::Path,
            restriction: &crate::PathBoundary<Marker>,
        ) -> std::path::PathBuf {
            use std::ffi::OsString;
            use std::path::Component;

            // WHY: Windows canonicalization adds a `\\?\` verbatim prefix that breaks
            // `strip_prefix` comparisons between system_path and jail_norm. `dunce`
            // strips it via `std::path::Prefix` matching (no lossy UTF-8 round-trip)
            // and declines to strip when doing so would be unsafe (reserved device
            // names, >MAX_PATH, trailing dots). On non-Windows it is a no-op.
            #[cfg(windows)]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                dunce::simplified(p).to_path_buf()
            }

            #[cfg(not(windows))]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                p.to_path_buf()
            }

            let system_norm = strip_verbatim(system_path);
            let jail_norm = strip_verbatim(restriction.path());

            // Fast path: strip the boundary prefix directly. This works when both
            // paths share a common prefix after verbatim normalization.
            if let Ok(stripped) = system_norm.strip_prefix(&jail_norm) {
                let mut cleaned = std::path::PathBuf::new();
                for comp in stripped.components() {
                    if let Component::Normal(name) = comp {
                        let s = name.to_string_lossy();
                        let cleaned_s = sanitize_display_component(&s);
                        if cleaned_s == s {
                            cleaned.push(name);
                        } else {
                            cleaned.push(OsString::from(cleaned_s));
                        }
                    }
                }
                return cleaned;
            }

            // Fallback: when strip_prefix fails (e.g., case differences on
            // Windows, or UNC vs local prefix mismatch), walk components
            // manually and skip the shared prefix with platform-aware comparison.
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
                    let cleaned = sanitize_display_component(&s);
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

    /// Convert this `VirtualPath` back into a system‑facing `StrictPath`.
    #[must_use = "unvirtual() consumes self — use the returned StrictPath for system-facing I/O, or prefer .as_unvirtual() to borrow without consuming"]
    #[inline]
    pub fn unvirtual(self) -> StrictPath<Marker> {
        self.inner
    }

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
    /// SECURITY:
    /// This method performs no permission checks. Only elevate markers after verifying real
    /// authorization out-of-band.
    ///
    /// # Examples
    ///
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
    #[must_use = "change_marker() consumes self — the original VirtualPath is moved; use the returned VirtualPath<NewMarker>"]
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

    /// Consume and return the `VirtualRoot` for its boundary (no directory creation).
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: Propagated from `try_into_boundary` when the
    ///   strict path does not exist or is not a directory.
    #[must_use = "try_into_root() consumes self — use the returned VirtualRoot to restrict future path operations"]
    #[inline]
    pub fn try_into_root(self) -> Result<crate::validator::virtual_root::VirtualRoot<Marker>> {
        Ok(self.inner.try_into_boundary()?.virtualize())
    }

    /// Consume and return a `VirtualRoot`, creating the underlying directory if missing.
    ///
    /// # Errors
    ///
    /// - `StrictPathError::InvalidRestriction`: Propagated from `try_into_boundary` or directory
    ///   creation failures wrapped in `InvalidRestriction`.
    #[must_use = "try_into_root_create() consumes self — use the returned VirtualRoot to restrict future path operations"]
    #[inline]
    pub fn try_into_root_create(
        self,
    ) -> Result<crate::validator::virtual_root::VirtualRoot<Marker>> {
        let strict_path = self.inner;
        let validated_dir = strict_path.try_into_boundary_create()?;
        Ok(validated_dir.virtualize())
    }

    /// Borrow the underlying system‑facing `StrictPath` (no allocation).
    #[must_use = "as_unvirtual() borrows the system-facing StrictPath — use it for system I/O or pass to functions accepting &StrictPath<Marker>"]
    #[inline]
    pub fn as_unvirtual(&self) -> &StrictPath<Marker> {
        &self.inner
    }

    /// Return the underlying system path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop.
    #[must_use = "pass interop_path() directly to third-party APIs requiring AsRef<Path> — never wrap it in Path::new() or PathBuf::from(); NEVER expose this in user-facing output (use .virtualpath_display() instead)"]
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.inner.interop_path()
    }

    /// Join a virtual path segment (virtual semantics) and re‑validate within the same restriction.
    ///
    /// Applies virtual path clamping: absolute paths are interpreted relative to the virtual root,
    /// and traversal attempts are clamped to prevent escaping the boundary. This method maintains
    /// the security guarantee that all `VirtualPath` instances stay within their virtual root.
    ///
    /// # Examples
    ///
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
    #[must_use = "virtual_join() validates untrusted input against the virtual root — always handle the Result to detect escape attempts"]
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

    /// Return the parent virtual path, or `None` at the virtual root.
    #[must_use = "returns a Result<Option> — handle both the error case and the None (at virtual root) case"]
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

    /// Return a new virtual path with file name changed, preserving clamping.
    #[must_use = "returns a new validated VirtualPath with the file name replaced — the original is unchanged; handle the Result to detect boundary escapes"]
    #[inline]
    pub fn virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let candidate = self.virtual_path.with_file_name(file_name);
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.boundary())?;
        let validated_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(validated_path))
    }

    /// Return a new virtual path with the extension changed, preserving clamping.
    #[must_use = "returns a new validated VirtualPath with the extension changed — the original is unchanged; handle the Result to detect boundary escapes"]
    pub fn virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        if self.virtual_path.file_name().is_none() {
            return Err(StrictPathError::path_escapes_boundary(
                self.virtual_path.clone(),
                self.inner.boundary().path().to_path_buf(),
            ));
        }

        // WHY: `Path::with_extension` panics when the extension contains a
        // path separator. Untrusted callers must get an `Err`, never a crash.
        let candidate =
            crate::path::with_validated_extension(&self.virtual_path, extension.as_ref())?;
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.boundary())?;
        let validated_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(validated_path))
    }

    /// Return the file name component of the virtual path, if any.
    #[must_use]
    #[inline]
    pub fn virtualpath_file_name(&self) -> Option<&OsStr> {
        self.virtual_path.file_name()
    }

    /// Return the file stem of the virtual path, if any.
    #[must_use]
    #[inline]
    pub fn virtualpath_file_stem(&self) -> Option<&OsStr> {
        self.virtual_path.file_stem()
    }

    /// Return the extension of the virtual path, if any.
    #[must_use]
    #[inline]
    pub fn virtualpath_extension(&self) -> Option<&OsStr> {
        self.virtual_path.extension()
    }

    /// Return `true` if the virtual path starts with the given prefix (virtual semantics).
    #[must_use]
    #[inline]
    pub fn virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.starts_with(p)
    }

    /// Return `true` if the virtual path ends with the given suffix (virtual semantics).
    #[must_use]
    #[inline]
    pub fn virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.ends_with(p)
    }

    /// Return a Display wrapper that shows a rooted virtual path (e.g., `"/a/b.txt").
    #[must_use = "virtualpath_display() returns a safe user-facing path representation — use this (not interop_path()) in API responses, logs, and UI"]
    #[inline]
    pub fn virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker> {
        VirtualPathDisplay(self)
    }

    /// Return `true` if the underlying system path exists.
    #[must_use]
    #[inline]
    pub fn exists(&self) -> bool {
        self.inner.exists()
    }

    /// Return `true` if the underlying system path is a file.
    #[must_use]
    #[inline]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    /// Return `true` if the underlying system path is a directory.
    #[must_use]
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    /// Return metadata for the underlying system path.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata()
    }

    /// Read the file contents as `String` from the underlying system path.
    #[inline]
    pub fn read_to_string(&self) -> std::io::Result<String> {
        self.inner.read_to_string()
    }

    /// Read raw bytes from the underlying system path.
    #[inline]
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read()
    }

    /// Return metadata for the underlying system path without following symlinks.
    #[inline]
    pub fn symlink_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata()
    }

    /// Set permissions on the file or directory at this path.
    ///
    #[inline]
    pub fn set_permissions(&self, perm: std::fs::Permissions) -> std::io::Result<()> {
        self.inner.set_permissions(perm)
    }

    /// Check if the path exists, returning an error on permission issues.
    ///
    /// Unlike `exists()` which returns `false` on permission errors, this method
    /// distinguishes between "path does not exist" (`Ok(false)`) and "cannot check
    /// due to permission error" (`Err(...)`).
    ///
    #[inline]
    pub fn try_exists(&self) -> std::io::Result<bool> {
        self.inner.try_exists()
    }

    /// Create an empty file if it doesn't exist, or update the modification time if it does.
    ///
    /// This is a convenience method combining file creation and mtime update.
    /// Uses `OpenOptions` with `create(true).write(true)` which creates the file
    /// if missing or opens it for writing if it exists, updating mtime on close.
    ///
    pub fn touch(&self) -> std::io::Result<()> {
        self.inner.touch()
    }

    /// Read directory entries (discovery). Re‑join names with `virtual_join(...)` to preserve clamping.
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        self.inner.read_dir()
    }

    /// Read directory entries as validated `VirtualPath` values (auto re-joins each entry).
    ///
    /// Unlike `read_dir()` which returns raw `std::fs::DirEntry`, this method automatically
    /// validates each directory entry through `virtual_join()`, returning an iterator of
    /// `Result<VirtualPath<Marker>>`. This eliminates the need for manual re-validation loops
    /// while preserving the virtual path semantics.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the directory cannot be read.
    /// - Each yielded item may also be `Err` if validation fails for that entry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{VirtualRoot, VirtualPath};
    /// # let temp = tempfile::tempdir()?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(temp.path())?;
    /// # let dir = vroot.virtual_join("uploads")?;
    /// # dir.create_dir_all()?;
    /// # vroot.virtual_join("uploads/file1.txt")?.write("a")?;
    /// # vroot.virtual_join("uploads/file2.txt")?.write("b")?;
    /// // Iterate with automatic validation
    /// for entry in dir.virtual_read_dir()? {
    ///     let child: VirtualPath = entry?;
    ///     let child_display = child.virtualpath_display();
    ///     println!("{child_display}");
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_read_dir(&self) -> std::io::Result<VirtualReadDir<'_, Marker>> {
        let inner = std::fs::read_dir(self.inner.path())?;
        Ok(VirtualReadDir {
            inner,
            parent: self,
        })
    }
}
