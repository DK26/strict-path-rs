use crate::jailed_path::JailedPath;
use crate::validator::jail;
use crate::{JailedPathError, Result};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

// --- Struct Definition ---

/// A user-facing, validated path that is guaranteed to be within a virtual root.
///
/// ## Key Concepts
/// - **Virtual Path**: This type represents a path as the user should see it, where the jail
///   boundary (the `VirtualRoot`) is treated as the filesystem root (`/`).
/// - **Display Behavior**: The `Display` trait is implemented to always show the safe,
///   user-friendly virtual path (e.g., `/user/file.txt`).
/// - **System Operations**: This type is for UX and path manipulation. For direct file system
///   operations (like reading or writing files), you must first convert it into a `JailedPath`
///   using `.unvirtual()`.
///
/// ## Example
/// ```rust
/// # use jailed_path::VirtualRoot;
/// # use std::fs;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # fs::create_dir_all("temp_vp_example")?;
/// let vroot = VirtualRoot::<()>::try_new("temp_vp_example")?;
/// // Use the public VirtualRoot API to construct virtual paths from user input
/// let virtual_path = vroot.try_path_virtual("user/docs/report.pdf")?;
///
/// // Displaying the path shows it relative to the virtual root.
/// assert_eq!(virtual_path.to_string(), "/user/docs/report.pdf");
///
/// // Manipulate the path virtually.
/// let parent = virtual_path.parent_virtual()?.unwrap();
/// assert_eq!(parent.to_string(), "/user/docs");
///
/// // To perform file I/O, convert it to a system-facing JailedPath.
/// let jailed_path = parent.unvirtual();
/// jailed_path.create_dir_all()?; // Creates the real directory
/// assert!(jailed_path.is_dir());
/// # fs::remove_dir_all("temp_vp_example")?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VirtualPath<Marker = ()> {
    inner: JailedPath<Marker>,
    virtual_path: std::path::PathBuf,
}

// --- Inherent Methods ---

impl<Marker> VirtualPath<Marker> {
    /// Internal constructor from a `JailedPath`.
    /// Prefer `VirtualRoot::try_path_virtual` or the explicit `JailedPath::virtualize()` for public construction.
    #[inline]
    pub(crate) fn new(jailed_path: JailedPath<Marker>) -> Self {
        // Compute virtual path by subtracting jail components from the real path
        fn compute_virtual(real: &std::path::Path, jail: &std::path::Path) -> std::path::PathBuf {
            use std::path::Component;

            // Normalize Windows verbatim/extended prefixes (e.g., `\\?\`) so
            // strip_prefix has a better chance of matching. This is a best-effort
            // normalization that avoids touching the filesystem.
            #[cfg(windows)]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                let s = p.as_os_str().to_string_lossy();
                // Handle extended local paths like "\\?\C:\..." and device paths like "\\.\"
                if let Some(trimmed) = s.strip_prefix("\\\\?\\") {
                    // Remove the leading "\\?\"
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

            let real_norm = strip_verbatim(real);
            let jail_norm = strip_verbatim(jail);

            // Fast path: if `real_norm` starts with `jail_norm`, use strip_prefix which is simple and
            // handles most common cases.
            if let Ok(stripped) = real_norm.strip_prefix(&jail_norm) {
                return stripped.to_path_buf();
            }

            // Fallback: compare components after removing Prefix/RootDir. On Windows, do a
            // case-insensitive comparison to be resilient to canonicalization differences.
            let mut real_comps: Vec<_> = real_norm
                .components()
                .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect();
            let mut jail_comps: Vec<_> = jail_norm
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

            while !real_comps.is_empty()
                && !jail_comps.is_empty()
                && comp_eq(&real_comps[0], &jail_comps[0])
            {
                real_comps.remove(0);
                jail_comps.remove(0);
            }

            let mut vb = std::path::PathBuf::new();
            for c in real_comps {
                if let Component::Normal(name) = c {
                    vb.push(name);
                }
            }
            vb
        }

        let virtual_path = compute_virtual(jailed_path.path(), jailed_path.jail_path());

        Self {
            inner: jailed_path,
            virtual_path,
        }
    }

    /// Explicitly convert this `VirtualPath` back into a `JailedPath`.
    #[inline]
    pub fn unvirtual(self) -> JailedPath<Marker> {
        self.inner
    }
    // ---- Construction & Conversion ----

    /// Creates a `VirtualPath` from a `JailedPath`.
    ///
    /// Note: prefer `VirtualRoot::try_path_virtual` for public construction flows.
    pub fn from_jailed(jailed_path: JailedPath<Marker>) -> Self {
        // Delegate to the internal constructor which computes and stores
        // the virtual path derived from the jailed (real) path and the jail root.
        Self::new(jailed_path)
    }

    /// Explicitly returns a reference to the underlying `JailedPath` for delegation.
    pub fn as_jailed(&self) -> &JailedPath<Marker> {
        &self.inner
    }

    // ---- Private Helpers ----

    /// Returns the virtual path, which is the real path stripped of the jail root.
    fn virtual_path_buf(&self) -> PathBuf {
        self.virtual_path.clone()
    }

    // ---- String Conversion ----

    /// Returns the virtual path as a string (e.g., `/user/file.txt`).
    ///
    /// This is the recommended way to display paths to users. It always uses forward slashes.
    pub fn to_string_virtual(&self) -> String {
        let virtual_path = self.virtual_path_buf();
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

    /// Returns the virtual path as an `OsString`.
    #[inline]
    pub fn as_os_str_virtual(&self) -> OsString {
        // Return an OS-independent, user-facing representation: leading `/` and
        // forward slashes as separators. Tests and UIs expect this form.
        OsString::from(self.to_string_virtual())
    }

    /// Returns the virtual path as an `Option<String>` if valid UTF-8.
    ///
    /// Use the `virtualpath_to_str()` alias instead of the historical `to_str_virtual()` name.
    /// We return an owned `String` to avoid returning references into temporary `PathBuf`s.
    #[inline]
    pub fn virtualpath_to_str(&self) -> Option<String> {
        Some(self.to_string_virtual())
    }

    /// Alias with explicit `virtualpath_` prefix returning owned `String`.
    #[inline]
    pub fn virtualpath_to_string(&self) -> String {
        self.to_string_virtual()
    }

    /// Returns the virtual path as an `OsString` with explicit `virtualpath_` prefix.
    #[inline]
    pub fn virtualpath_as_os_str(&self) -> OsString {
        self.as_os_str_virtual()
    }

    // ---- Safe Path Manipulation ----

    /// Safely joins a path segment to the current virtual path.
    #[inline]
    pub fn join_virtual<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_virtual = self.virtual_path_buf().join(path);
        let virtualized = jail::virtualize_to_jail(new_virtual, self.inner.jail_path());
        jail::validate(virtualized, self.inner.jail_path_arc()).map(|p| p.virtualize())
    }

    /// Returns the parent directory as a new `VirtualPath`.
    ///
    /// Returns `Ok(None)` if the current path is the virtual root.
    pub fn parent_virtual(&self) -> Result<Option<Self>> {
        match self.virtual_path_buf().parent() {
            Some(p) => {
                let virtualized = jail::virtualize_to_jail(p, self.inner.jail_path());
                match jail::validate(virtualized, self.inner.jail_path_arc()) {
                    Ok(p) => Ok(Some(p.virtualize())),
                    Err(e) => Err(e),
                }
            }
            None => Ok(None),
        }
    }

    /// Returns a new `VirtualPath` with the file name replaced.
    #[inline]
    pub fn with_file_name_virtual<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_virtual = self.virtual_path_buf().with_file_name(file_name);
        let virtualized = jail::virtualize_to_jail(new_virtual, self.inner.jail_path());
        jail::validate(virtualized, self.inner.jail_path_arc()).map(|p| p.virtualize())
    }

    /// Returns a new `VirtualPath` with the extension replaced.
    ///
    /// Returns an error if the path has no file name (e.g., is the virtual root).
    pub fn with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let vpath = self.virtual_path_buf();
        if vpath.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                vpath,
                self.inner.jail_path().to_path_buf(),
            ));
        }
        let new_virtual = vpath.with_extension(extension);
        let virtualized = jail::virtualize_to_jail(new_virtual, self.inner.jail_path());
        jail::validate(virtualized, self.inner.jail_path_arc()).map(|p| p.virtualize())
    }

    // ---- Path Components (Virtual) ----

    /// Returns the final component of the virtual path, if there is one.
    #[inline]
    pub fn file_name_virtual(&self) -> Option<OsString> {
        self.virtual_path_buf()
            .file_name()
            .map(|s| s.to_os_string())
    }

    /// Returns the file stem of the virtual path.
    #[inline]
    pub fn file_stem_virtual(&self) -> Option<OsString> {
        self.virtual_path_buf()
            .file_stem()
            .map(|s| s.to_os_string())
    }

    /// Returns the extension of the virtual path.
    #[inline]
    pub fn extension_virtual(&self) -> Option<OsString> {
        self.virtual_path_buf()
            .extension()
            .map(|s| s.to_os_string())
    }

    // ---- Prefix / Suffix Checks ----

    /// Returns true if the *virtual* path starts with `p`.
    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path_buf().starts_with(p.as_ref())
    }

    /// Returns true if the *virtual* path ends with `p`.
    #[inline]
    pub fn ends_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path_buf().ends_with(p.as_ref())
    }
}

// --- Trait Implementations ---

impl<Marker> fmt::Display for VirtualPath<Marker> {
    /// Displays the user-friendly **virtual path**.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_virtual())
    }
}

// Conversions are explicit: use `JailedPath::virtualize()` and `VirtualPath::unvirtual()`.
