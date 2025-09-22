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
        vroot.virtual_join("")
    }

    /// SUMMARY:
    /// Create the virtual root, creating the filesystem root if missing.
    pub fn with_root_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let vroot = crate::validator::virtual_root::VirtualRoot::try_new_create(root)?;
        vroot.virtual_join("")
    }
    #[inline]
    pub(crate) fn new(restricted_path: StrictPath<Marker>) -> Self {
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

        let virtual_path = compute_virtual(restricted_path.path(), restricted_path.boundary());

        Self {
            inner: restricted_path,
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
    /// Consume and return the `VirtualRoot` for its boundary (no directory creation).
    #[inline]
    pub fn try_into_root(self) -> crate::validator::virtual_root::VirtualRoot<Marker> {
        self.inner.try_into_boundary().virtualize()
    }

    /// SUMMARY:
    /// Consume and return a `VirtualRoot`, creating the underlying directory if missing.
    #[inline]
    pub fn try_into_root_create(self) -> crate::validator::virtual_root::VirtualRoot<Marker> {
        let boundary = self.inner.try_into_boundary();
        if !boundary.exists() {
            // Best-effort create; ignore error and let later operations surface it
            let _ = std::fs::create_dir_all(boundary.as_ref());
        }
        boundary.virtualize()
    }

    /// SUMMARY:
    /// Borrow the underlying system‑facing `StrictPath` (no allocation).
    #[inline]
    pub fn as_unvirtual(&self) -> &StrictPath<Marker> {
        &self.inner
    }

    /// SUMMARY:
    /// Return the underlying system path as `&OsStr` for `AsRef<Path>` interop.
    #[inline]
    pub fn interop_path(&self) -> &OsStr {
        self.inner.interop_path()
    }

    /// SUMMARY:
    /// Join a virtual path segment (virtual semantics) and re‑validate within the same restriction.
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
                let restricted_path = clamp(self.inner.boundary(), anchored)?;
                Ok(Some(VirtualPath::new(restricted_path)))
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
        let restricted_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(restricted_path))
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
        let restricted_path = clamp(self.inner.boundary(), anchored)?;
        Ok(VirtualPath::new(restricted_path))
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

    /// Reads the file contents as raw bytes from the underlying system path.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use read() instead")]
    #[inline]
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read()
    }

    /// Writes raw bytes to the underlying system path.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use write(...) instead")]
    #[inline]
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write(data)
    }

    /// Writes a UTF-8 string to the underlying system path.
    #[deprecated(since = "0.1.0-alpha.5", note = "Use write(...) instead")]
    #[inline]
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        self.inner.write(data)
    }

    /// SUMMARY:
    /// Read raw bytes from the underlying system path (replacement for `read_bytes`).
    #[inline]
    pub fn read(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read()
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
    /// Create a symlink at this virtual location pointing to `target` (same virtual root required).
    pub fn virtual_symlink(&self, link_path: &Self) -> std::io::Result<()> {
        if self.inner.boundary().path() != link_path.inner.boundary().path() {
            let err = StrictPathError::path_escapes_boundary(
                link_path.inner.path().to_path_buf(),
                self.inner.boundary().path().to_path_buf(),
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
        }

        self.inner.strict_symlink(&link_path.inner)
    }

    /// SUMMARY:
    /// Create a hard link at this virtual location pointing to `target` (same virtual root).
    pub fn virtual_hard_link(&self, link_path: &Self) -> std::io::Result<()> {
        if self.inner.boundary().path() != link_path.inner.boundary().path() {
            let err = StrictPathError::path_escapes_boundary(
                link_path.inner.path().to_path_buf(),
                self.inner.boundary().path().to_path_buf(),
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
        }

        self.inner.strict_hard_link(&link_path.inner)
    }

    /// SUMMARY:
    /// Rename/move within the same virtual root. Relative destinations are siblings; absolute are from root.
    /// Parents are not created automatically.
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
                Ok(None) => match self.virtual_join("") {
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
    /// Copy within the same virtual root. Relative destinations are siblings; absolute are from root.
    /// Parents are not created automatically. Returns bytes copied.
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
                Ok(None) => match self.virtual_join("") {
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

#[cfg(feature = "serde")]
impl<Marker> serde::Serialize for VirtualPath<Marker> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self.virtualpath_display()))
    }
}
