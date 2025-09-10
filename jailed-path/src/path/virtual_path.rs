// Content copied from original src/path/virtual_path.rs
use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
use crate::validator;
use crate::validator::jail::Jail;
use crate::validator::path_history::{Canonicalized, PathHistory};
use crate::Result;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// A user-facing path clamped to the virtual root of a jail.
///
/// `virtualpath_display()` and `virtualpath_to_string_lossy()` show a rooted, forward-slashed path
/// (e.g., `"/a/b.txt"`). Use virtual manipulation methods to compose paths
/// while preserving clamping, and convert to `JailedPath` with `unvirtual()`
/// for system-facing I/O.
#[derive(Clone)]
pub struct VirtualPath<Marker = ()> {
    inner: JailedPath<Marker>,
    virtual_path: PathBuf,
}

#[inline]
fn clamp<Marker, H>(
    jail: &Jail<Marker>,
    anchored: PathHistory<(H, Canonicalized)>,
) -> crate::Result<crate::path::jailed_path::JailedPath<Marker>> {
    jail.jailed_join(anchored.into_inner())
}

impl<Marker> VirtualPath<Marker> {
    #[inline]
    pub(crate) fn new(jailed_path: JailedPath<Marker>) -> Self {
        fn compute_virtual<Marker>(
            system_path: &std::path::Path,
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

            let system_norm = strip_verbatim(system_path);
            let jail_norm = strip_verbatim(jail.path());

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

            let mut jailedpath_comps: Vec<_> = system_norm
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

            while !jailedpath_comps.is_empty()
                && !jail_comps.is_empty()
                && comp_eq(&jailedpath_comps[0], &jail_comps[0])
            {
                jailedpath_comps.remove(0);
                jail_comps.remove(0);
            }

            let mut vb = std::path::PathBuf::new();
            for c in jailedpath_comps {
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

        let virtual_path = compute_virtual(jailed_path.path(), jailed_path.jail());

        Self {
            inner: jailed_path,
            virtual_path,
        }
    }

    /// Converts this `VirtualPath` back into a system-facing `JailedPath`.
    #[inline]
    pub fn unvirtual(self) -> JailedPath<Marker> {
        self.inner
    }

    /// Borrows the underlying system-facing `JailedPath` (no allocation).
    ///
    /// Use this to pass a `&VirtualPath` to APIs that accept `&JailedPath`.
    #[inline]
    pub fn as_unvirtual(&self) -> &JailedPath<Marker> {
        &self.inner
    }

    /// Returns the rooted, forward-slashed virtual path string for UI/display.
    ///
    /// Returns `Cow<'_, str>` and avoids allocation when possible (e.g., on
    /// Unix when the underlying string is valid UTF-8 and already rooted).
    pub fn virtualpath_to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow;

        let s_lossy = self.virtual_path.to_string_lossy();

        #[cfg(windows)]
        {
            let normalized = s_lossy.replace('\\', "/");
            if normalized.starts_with('/') {
                Cow::Owned(normalized)
            } else {
                Cow::Owned(format!("/{normalized}"))
            }
        }

        #[cfg(not(windows))]
        {
            if s_lossy.starts_with('/') {
                s_lossy
            } else {
                Cow::Owned(format!("/{s_lossy}"))
            }
        }
    }

    #[inline]
    // Note: We intentionally do not expose borrowed &str/&OsStr virtual accessors to
    // avoid confusion; use `virtualpath_to_string_lossy()` or `virtualpath_display()` for rooted output.
    /// Returns the underlying system path as a lossy UTF-8 string (delegates to `JailedPath`).
    pub fn jailedpath_to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.inner.jailedpath_to_string_lossy()
    }

    /// Returns the underlying system path as `&str` if valid UTF-8 (delegates to `JailedPath`).
    #[inline]
    pub fn jailedpath_to_str(&self) -> Option<&str> {
        self.inner.jailedpath_to_str()
    }

    /// Returns the underlying system path as `&OsStr` for `AsRef<Path>` interop.
    #[inline]
    pub fn interop_path(&self) -> &OsStr {
        self.inner.interop_path()
    }

    /// Safely joins a virtual path segment (virtual semantics) and re-validates.
    #[inline]
    pub fn virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        // Compose candidate in virtual space (do not pre-normalize lexically to preserve symlink semantics)
        let candidate = self.virtual_path.join(path.as_ref());
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.jail())?;
        let jailed_path = clamp(self.inner.jail(), anchored)?;
        Ok(VirtualPath::new(jailed_path))
    }

    // No local clamping helpers; virtual flows should route through
    // PathHistory::virtualize_to_jail + Jail::jailed_join to avoid drift.

    /// Returns the parent virtual path, or `None` if at the virtual root.
    pub fn virtualpath_parent(&self) -> Result<Option<Self>> {
        match self.virtual_path.parent() {
            Some(parent_virtual_path) => {
                let anchored = crate::validator::path_history::PathHistory::new(
                    parent_virtual_path.to_path_buf(),
                )
                .canonicalize_anchored(self.inner.jail())?;
                let jailed_path = clamp(self.inner.jail(), anchored)?;
                Ok(Some(VirtualPath::new(jailed_path)))
            }
            None => Ok(None),
        }
    }

    /// Returns a new `VirtualPath` with the file name changed, preserving clamping.
    #[inline]
    pub fn virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let candidate = self.virtual_path.with_file_name(file_name);
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.jail())?;
        let jailed_path = clamp(self.inner.jail(), anchored)?;
        Ok(VirtualPath::new(jailed_path))
    }

    /// Returns a new `VirtualPath` with the extension changed, preserving clamping.
    pub fn virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        if self.virtual_path.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.virtual_path.clone(),
                self.inner.jail().path().to_path_buf(),
            ));
        }

        let candidate = self.virtual_path.with_extension(extension);
        let anchored = crate::validator::path_history::PathHistory::new(candidate)
            .canonicalize_anchored(self.inner.jail())?;
        let jailed_path = clamp(self.inner.jail(), anchored)?;
        Ok(VirtualPath::new(jailed_path))
    }

    /// Returns the file name component of the virtual path, if any.
    #[inline]
    pub fn virtualpath_file_name(&self) -> Option<&OsStr> {
        self.virtual_path.file_name()
    }

    /// Returns the file stem of the virtual path, if any.
    #[inline]
    pub fn virtualpath_file_stem(&self) -> Option<&OsStr> {
        self.virtual_path.file_stem()
    }

    /// Returns the extension of the virtual path, if any.
    #[inline]
    pub fn virtualpath_extension(&self) -> Option<&OsStr> {
        self.virtual_path.extension()
    }

    /// Returns `true` if the virtual path starts with the given prefix (virtual semantics).
    #[inline]
    pub fn virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.starts_with(p)
    }

    /// Returns `true` if the virtual path ends with the given suffix (virtual semantics).
    #[inline]
    pub fn virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.ends_with(p)
    }

    /// Returns a Display wrapper that shows a rooted virtual path (e.g., `"/a/b.txt"`).
    #[inline]
    pub fn virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker> {
        VirtualPathDisplay(self)
    }

    /// Returns `true` if the underlying system path exists.
    #[inline]
    pub fn exists(&self) -> bool {
        self.inner.exists()
    }

    /// Returns `true` if the underlying system path is a file.
    #[inline]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    /// Returns `true` if the underlying system path is a directory.
    #[inline]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    /// Returns metadata for the underlying system path.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata()
    }

    /// Reads the file contents as `String` from the underlying system path.
    #[inline]
    pub fn read_to_string(&self) -> std::io::Result<String> {
        self.inner.read_to_string()
    }

    /// Reads the file contents as raw bytes from the underlying system path.
    #[inline]
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read_bytes()
    }

    /// Writes raw bytes to the underlying system path.
    #[inline]
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(data)
    }

    /// Writes a UTF-8 string to the underlying system path.
    #[inline]
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        self.inner.write_string(data)
    }

    /// Creates all directories in the underlying system path if missing.
    #[inline]
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        self.inner.create_dir_all()
    }

    /// Creates the directory at this virtual location (non-recursive).
    ///
    /// Mirrors `std::fs::create_dir` and fails if the parent does not exist.
    #[inline]
    pub fn create_dir(&self) -> std::io::Result<()> {
        self.inner.create_dir()
    }

    /// Creates only the immediate parent directory of this virtual path (non-recursive).
    ///
    /// Acts in the virtual dimension: the parent is derived via `virtualpath_parent()`
    /// and then created on the underlying system path. Returns `Ok(())` at virtual root.
    #[inline]
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.virtualpath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            Err(crate::JailedPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Recursively creates all missing directories up to the immediate parent of this virtual path.
    ///
    /// Acts in the virtual dimension; returns `Ok(())` at virtual root.
    #[inline]
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.virtualpath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            Err(crate::JailedPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    /// Removes the file at the underlying system path.
    #[inline]
    pub fn remove_file(&self) -> std::io::Result<()> {
        self.inner.remove_file()
    }

    /// Removes the directory at the underlying system path.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        self.inner.remove_dir()
    }

    /// Recursively removes the directory and its contents at the underlying system path.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        self.inner.remove_dir_all()
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
            .field("system_path", &self.inner.jailedpath_to_string_lossy())
            .field("virtual", &self.virtualpath_to_string_lossy())
            .field("jail", &self.inner.jail().path())
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

impl<Marker> PartialEq<crate::path::jailed_path::JailedPath<Marker>> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::jailed_path::JailedPath<Marker>) -> bool {
        self.inner.path() == other.path()
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &T) -> bool {
        // Compare virtual paths - the user-facing representation
        // If you want system path comparison, use as_unvirtual()
        let virtual_str = self.virtualpath_to_string_lossy();
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_ref();

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
        let virtual_str = self.virtualpath_to_string_lossy();
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_ref();

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

#[cfg(feature = "serde")]
impl<Marker> serde::Serialize for VirtualPath<Marker> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.virtualpath_to_string_lossy().as_ref())
    }
}
