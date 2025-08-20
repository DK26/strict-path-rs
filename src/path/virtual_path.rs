use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
use crate::validator;
use crate::Result;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

// --- Struct Definition ---

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
///
/// A user-facing, validated path that is guaranteed to be within a virtual root.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VirtualPath<Marker = ()> {
    inner: JailedPath<Marker>,
    virtual_path: PathBuf,
}

// --- Inherent Methods ---

impl<Marker> VirtualPath<Marker> {
    /// Internal constructor from a `JailedPath`.
    /// Prefer `VirtualRoot::try_path_virtual` or the explicit `JailedPath::virtualize()` for public construction.
    #[inline]
    pub(crate) fn new(jailed_path: JailedPath<Marker>) -> Self {
        // Compute virtual path by subtracting jail components from the real path
        fn compute_virtual<Marker>(
            real: &std::path::Path,
            jail: &validator::jail::Jail<Marker>,
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

            let real_norm = strip_verbatim(real);
            let jail_norm = strip_verbatim(jail.path());

            if let Ok(stripped) = real_norm.strip_prefix(&jail_norm) {
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
                    // Sanitize dangerous characters for the virtual display.
                    // Replace newlines and semicolons with '_' to avoid injection
                    // or misleading displays in user-facing paths.
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

        let virtual_path = compute_virtual(jailed_path.path(), jailed_path.jail());

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

    pub fn jail(&self) -> &crate::validator::jail::Jail<Marker> {
        self.inner.jail()
    }

    // ---- String Conversion ----

    /// Returns the virtual path as a string (e.g., `/user/file.txt`).
    ///
    /// This is the recommended way to display paths to users. It always uses forward slashes.
    pub fn virtualpath_to_string(&self) -> String {
        // Use the display adapter to produce the presentation-formatted virtual path
        // (ensures a leading '/' and normalized separators) rather than returning the
        // raw stored PathBuf which may omit the leading '/'.
        format!("{}", self.display())
    }

    /// Returns the virtual path as an `Option<String>` if valid UTF-8.
    ///
    /// This returns an owned `String` to avoid returning references into temporary `PathBuf`s.
    #[inline]
    pub fn virtualpath_to_str(&self) -> Option<&str> {
        self.virtual_path.to_str()
    }

    /// Returns the virtual path as an `OsString` with explicit `virtualpath_` prefix.
    #[inline]
    pub fn virtualpath_as_os_str(&self) -> &OsStr {
        self.virtual_path.as_os_str()
    }

    // ---- Safe Path Manipulation ----

    /// Safely joins a path segment to the current virtual path.
    #[inline]
    pub fn join_virtual<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_virtual = self.virtual_path.join(path);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    /// Returns the parent directory as a new `VirtualPath`.
    ///
    /// Returns `Ok(None)` if the current path is the virtual root.
    pub fn parent_virtual(&self) -> Result<Option<Self>> {
        match self.virtual_path.parent() {
            Some(p) => {
                let virtualized = validator::virtualize_to_jail(p, self.inner.jail());
                match validator::validate(virtualized, self.inner.jail()) {
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
        let new_virtual = self.virtual_path.with_file_name(file_name);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    /// Returns a new `VirtualPath` with the extension replaced.
    ///
    /// Returns an error if the path has no file name (e.g., is the virtual root).
    pub fn with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        if self.virtual_path.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.virtual_path.clone(),
                self.inner.jail().path().to_path_buf(),
            ));
        }
        let new_virtual = self.virtual_path.with_extension(extension);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    // ---- Path Components (Virtual) ----

    /// Returns the final component of the virtual path, if there is one.
    ///
    /// Returns a borrowed `OsStr` reference into the stored `virtual_path` to
    /// avoid unnecessary allocations. Callers that need an owned `OsString`
    /// can call `.to_os_string()` on the returned value.
    #[inline]
    pub fn file_name_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.file_name()
    }

    /// Returns the file stem of the virtual path.
    ///
    /// Borrowed reference into the stored `virtual_path`.
    #[inline]
    pub fn file_stem_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.file_stem()
    }

    /// Returns the extension of the virtual path.
    ///
    /// Borrowed reference into the stored `virtual_path`.
    #[inline]
    pub fn extension_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.extension()
    }

    // ---- Prefix / Suffix Checks ----

    /// Returns true if the *virtual* path starts with `p`.
    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.starts_with(p)
    }

    /// Returns true if the *virtual* path ends with `p`.
    #[inline]
    pub fn ends_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.ends_with(p)
    }

    /// Returns a borrowed display adapter that implements `fmt::Display`.
    ///
    /// This performs presentation formatting (normalize separators, ensure
    /// a leading '/') when formatted, but doesn't allocate an owned `String`.
    /// Example: `println!("{}", vp.display())` or `let s = vp.display().to_string();`.
    #[inline]
    pub fn display(&self) -> VirtualPathDisplay<'_, Marker> {
        VirtualPathDisplay(self)
    }
}

// --- Trait Implementations ---

/// Borrowed display adapter for `VirtualPath`.
///
/// This mirrors `VirtualPath::display()` presentation logic but writes
/// directly into the `Formatter` without producing an owned `String`.
pub struct VirtualPathDisplay<'a, Marker>(&'a VirtualPath<Marker>);

impl<'a, Marker> fmt::Display for VirtualPathDisplay<'a, Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reuse the same presentation logic as `VirtualPath::display()`
        let s = self.0.virtual_path.as_os_str().to_string_lossy();
        if cfg!(windows) {
            // On Windows, normalize backslashes to forward slashes.
            if s.is_empty() {
                return write!(f, "/");
            }
            if !s.starts_with('/') {
                write!(f, "/")?;
            }
            for ch in s.chars() {
                if ch == '\\' {
                    write!(f, "/")?;
                } else {
                    write!(f, "{ch}")?;
                }
            }
            Ok(())
        } else {
            // Unix-like: preserve backslashes and write directly.
            if s.is_empty() {
                write!(f, "/")
            } else if !s.starts_with('/') {
                write!(f, "/{s}")
            } else {
                write!(f, "{s}")
            }
        }
    }
}

impl<Marker: Clone> fmt::Display for VirtualPath<Marker> {
    /// Displays the user-friendly **virtual path** by forwarding to
    /// `VirtualPath::display()` to keep presentation logic in one place.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

// Conversions are explicit: use `JailedPath::virtualize()` and `VirtualPath::unvirtual()`.
