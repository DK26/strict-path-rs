use crate::validator::validated_path::{
    BoundaryChecked, Canonicalized, Clamped, JoinedJail, Raw, ValidatedPath,
};
use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
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
/// - `Display` shows the user-friendly **virtual path** (e.g., `/user/file.txt`).
/// - `Debug` shows the **real path** for debugging purposes (e.g., `/app/storage/user/file.txt`).
///
/// ## Example
/// ```rust
/// # use jailed_path::Jail;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # std::fs::create_dir_all("temp_jail")?;
/// let jail = Jail::<()>::try_new("temp_jail")?;
/// let jailed_path = jail.try_path("file.txt")?;
///
/// // If jail_root is "temp_jail" and path is "file.txt"
/// // Virtual path shows: "/file.txt"
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
        Self {
            path: validated_path.into_inner(),
            jail_root,
            _marker: PhantomData,
        }
    }

    // No accessors which return `&Path` or expose the jail root are provided here.
    // The ROADMAP explicitly forbids exposing Path references from `JailedPath`.

    // ---- Private Helpers ----

    /// Returns the virtual path, which is the real path stripped of the jail root.
    fn virtual_path(&self) -> PathBuf {
        // This should not fail if logic is correct, as self.path is guaranteed to be inside jail_root
        self.path
            .strip_prefix(&*self.jail_root)
            .unwrap_or(&self.path)
            .to_path_buf()
    }

    /// Re-validates a new virtual path derived from the current one.
    fn revalidate(&self, new_virtual_path: PathBuf) -> Option<Self> {
        let validated = ValidatedPath::<Raw>::new(new_virtual_path)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()
            .ok()?
            .boundary_check(&self.jail_root)
            .ok()?;
        // Build new instance and construct its cached virtual_display in `new()`.
        Some(Self::new(self.jail_root.clone(), validated))
    }

    // ---- String Conversion ----

    /// Returns the virtual path as a string (e.g., `/user/file.txt`).
    ///
    /// This is the recommended way to display paths to users.
    pub fn to_string_virtual(&self) -> String {
        let virtual_path = self.virtual_path();
        let components: Vec<_> = virtual_path.components().map(|c| c.as_os_str()).collect();

        if components.is_empty() {
            return "/".to_string();
        }

        let total_len = components.iter().map(|c| c.len() + 1).sum();
        let mut result = String::with_capacity(total_len);
        for component in components {
            result.push('/');
            result.push_str(&component.to_string_lossy());
        }
        result
    }

    // NOTE: `to_str_virtual(&self) -> Option<&str>` intentionally omitted.
    //
    // Rationale:
    // - Returning a borrowed `&str` that lives for `&self` requires storing the
    //   computed virtual-path string inside the `JailedPath` instance (a cache).
    // - Caching has non-trivial trade-offs (per-instance memory overhead, thread-safety
    //   considerations, and API/representation changes such as using `Arc` or `OnceLock`).
    // - Alternative, low-overhead APIs could be added later to cover common needs
    //   without changing the `JailedPath` layout (these are NOT implemented here):
    //     * `to_string_virtual(&self) -> String` -- convenience, allocates each call (currently implemented)
    //     * `write_virtual_to(&self, out: &mut String)` -- caller-provided buffer, zero per-instance (proposed)
    //     * `virtual_arc(&self) -> Arc<String>` -- ergonomic shareable owned value (allocates) (proposed)
    //     * feature-gated lazy cache (opt-in) if zero-copy `&str` semantics are required (proposed)
    //
    // For now we avoid adding a method that returns `Option<&str>` to prevent confusing
    // semantics (a method that would simply return `None` is misleading). This decision
    // can be revisited when we decide whether to accept the structural changes required
    // for efficient, borrow-backed returns.

    /// Returns the real path as a string (e.g., `/app/storage/user/file.txt`).
    ///
    /// **⚠️ Caution**: Exposes the real filesystem path. Use with care.
    pub fn to_string_real(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    // Keep JailedPath API strictly to the names in the roadmap. No helpers that
    // expose path-like data or duplicate names are added here.

    /// Returns the real path as an `Option<&str>`.
    ///
    /// **⚠️ Caution**: Exposes the real filesystem path.
    #[inline]
    pub fn to_str_real(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns the real path as an `&OsStr`.
    ///
    /// **⚠️ Caution**: Exposes the real filesystem path.
    #[inline]
    pub fn as_os_str_real(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Returns the virtual path as an `OsString`.
    #[inline]
    pub fn as_os_str_virtual(&self) -> OsString {
        self.virtual_path().into()
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

    // ---- Safe Path Manipulation ----

    /// Safely joins a path segment to the current virtual path.
    ///
    /// Returns `None` if the resulting path would escape the jail.
    pub fn join<P: AsRef<Path>>(&self, path: P) -> Option<Self> {
        let new_virtual = self.virtual_path().join(path);
        self.revalidate(new_virtual)
    }

    /// Returns the parent directory as a new `JailedPath`.
    ///
    /// Returns `None` if the current path is the jail root.
    pub fn parent(&self) -> Option<Self> {
        self.virtual_path()
            .parent()
            .and_then(|p| self.revalidate(p.to_path_buf()))
    }

    /// Returns a new `JailedPath` with the file name replaced.
    ///
    /// Returns `None` if the operation is not possible (e.g., on an empty path).
    pub fn with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Option<Self> {
        let new_virtual = self.virtual_path().with_file_name(file_name);
        self.revalidate(new_virtual)
    }

    /// Returns a new `JailedPath` with the extension replaced.
    ///
    /// Returns `None` if the path has no file name.
    pub fn with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Option<Self> {
        let vpath = self.virtual_path();
        // If there's no file name (we're at the jail root), adding an extension is invalid.
        vpath.file_name()?;
        let new_virtual = vpath.with_extension(extension);
        self.revalidate(new_virtual)
    }

    // ---- Path Components (Virtual) ----

    /// Returns the final component of the virtual path, if there is one.
    #[inline]
    pub fn file_name(&self) -> Option<OsString> {
        self.virtual_path().file_name().map(|s| s.to_os_string())
    }

    /// Returns the file stem of the virtual path.
    #[inline]
    pub fn file_stem(&self) -> Option<OsString> {
        self.virtual_path().file_stem().map(|s| s.to_os_string())
    }

    /// Returns the extension of the virtual path.
    #[inline]
    pub fn extension(&self) -> Option<OsString> {
        self.virtual_path().extension().map(|s| s.to_os_string())
    }

    // ---- Prefix / Suffix Checks ----

    /// Returns true if the *real* filesystem path starts with `p`.
    ///
    /// This compares against the internal real `PathBuf` and is equivalent
    /// to calling `Path::starts_with` on the real path.
    #[inline]
    pub fn starts_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    /// Returns true if the *virtual* path starts with `p`.
    ///
    /// This is the check you typically want in tests that assert containment
    /// within the virtual/jail-relative namespace.
    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path().starts_with(p.as_ref())
    }

    /// Returns true if the *real* filesystem path ends with `p`.
    #[inline]
    pub fn ends_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.ends_with(p.as_ref())
    }

    /// Returns true if the *virtual* path ends with `p`.
    ///
    /// This method is intentionally explicit to avoid accidental exposure of
    /// the real filesystem path. Use `ends_with_real` when you need to compare
    /// against the underlying real path. Prefer `ends_with_virtual` in tests
    /// and user-facing checks to ensure comparisons are performed only on the
    /// virtual, user-visible path and do not leak or depend on real-path
    /// details (separators, canonicalization differences, etc.).
    #[inline]
    pub fn ends_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path().ends_with(p.as_ref())
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
    /// Displays the user-friendly **virtual path**.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_virtual())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    /// Displays the **real path** for debugging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JailedPath")
            .field("path", &self.path.display())
            .field("jail_root", &&self.jail_root.display())
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
