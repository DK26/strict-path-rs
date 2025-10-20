// Content copied from original src/validator/virtual_root.rs
use crate::path::virtual_path::VirtualPath;
use crate::validator::path_history::PathHistory;
use crate::PathBoundary;
use crate::Result;
use std::marker::PhantomData;
use std::path::Path;

/// SUMMARY:
/// Provide a user‑facing virtual root that produces `VirtualPath` values clamped to a boundary.
#[derive(Clone)]
pub struct VirtualRoot<Marker = ()> {
    pub(crate) root: PathBoundary<Marker>,
    pub(crate) _marker: PhantomData<Marker>,
}

impl<Marker> VirtualRoot<Marker> {
    // no extra constructors; use PathBoundary::virtualize() or VirtualRoot::try_new
    /// SUMMARY:
    /// Create a `VirtualRoot` from an existing directory.
    ///
    /// PARAMETERS:
    /// - `root_path` (`AsRef<Path>`): Existing directory to anchor the virtual root.
    ///
    /// RETURNS:
    /// - `Result<VirtualRoot<Marker>>`: New virtual root with clamped operations.
    ///
    /// ERRORS:
    /// - `StrictPathError::InvalidRestriction`: Root invalid or cannot be canonicalized.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::VirtualRoot;
    /// let vroot = VirtualRoot::<()>::try_new("./data")?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let root = PathBoundary::try_new(root_path)?;
        Ok(Self {
            root,
            _marker: PhantomData,
        })
    }

    /// SUMMARY:
    /// Return filesystem metadata for the underlying root directory.
    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.root.metadata()
    }

    /// SUMMARY:
    /// Consume this virtual root and return the rooted `VirtualPath` ("/").
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `Result<VirtualPath<Marker>>`: Virtual root path clamped to this boundary.
    ///
    /// ERRORS:
    /// - `StrictPathError::PathResolutionError`: Canonicalization fails (root removed or inaccessible).
    /// - `StrictPathError::PathEscapesBoundary`: Root moved outside the boundary between checks.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::{VirtualPath, VirtualRoot};
    /// # let root = std::env::temp_dir().join("into-virtualpath-example");
    /// # std::fs::create_dir_all(&root)?;
    /// let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// let root_virtual: VirtualPath = vroot.into_virtualpath()?;
    /// assert_eq!(root_virtual.virtualpath_display().to_string(), "/");
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn into_virtualpath(self) -> Result<VirtualPath<Marker>> {
        let strict_root = self.root.into_strictpath()?;
        Ok(strict_root.virtualize())
    }

    /// SUMMARY:
    /// Consume this virtual root and substitute a new marker type.
    ///
    /// DETAILS:
    /// Mirrors [`crate::PathBoundary::change_marker`], [`crate::StrictPath::change_marker`], and
    /// [`crate::VirtualPath::change_marker`]. Use this when encoding proven authorization
    /// into the type system (e.g., after validating a user's permissions). The
    /// consumption makes marker changes explicit during code review.
    ///
    /// PARAMETERS:
    /// - `NewMarker` (type parameter): Marker to associate with the virtual root.
    ///
    /// RETURNS:
    /// - `VirtualRoot<NewMarker>`: Same underlying root, rebranded with `NewMarker`.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let root_dir = std::env::temp_dir().join("vroot-change-marker-example");
    /// # std::fs::create_dir_all(&root_dir)?;
    /// struct UserFiles;
    /// struct ReadOnly;
    /// struct ReadWrite;
    ///
    /// let read_root: VirtualRoot<(UserFiles, ReadOnly)> = VirtualRoot::try_new(&root_dir)?;
    ///
    /// // After authorization check...
    /// let write_root: VirtualRoot<(UserFiles, ReadWrite)> = read_root.change_marker();
    /// # std::fs::remove_dir_all(&root_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn change_marker<NewMarker>(self) -> VirtualRoot<NewMarker> {
        let VirtualRoot { root, .. } = self;

        VirtualRoot {
            root: root.change_marker(),
            _marker: PhantomData,
        }
    }

    /// SUMMARY:
    /// Create a symbolic link at `link_path` pointing to this root's underlying directory.
    ///
    /// DETAILS:
    /// `link_path` is interpreted in the virtual dimension and resolved via `virtual_join()`
    /// so that absolute virtual paths ("/links/a") are clamped within this virtual root and
    /// relative paths are resolved relative to the virtual root.
    pub fn virtual_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        // Resolve the link location in virtual space first (clamps/anchors under this root)
        let link_ref = link_path.as_ref();
        let validated_link = self
            .virtual_join(link_ref)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        // Obtain the strict target for the root directory
        let root = self
            .root
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_symlink(validated_link.as_unvirtual().path())
    }

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this root's underlying directory.
    ///
    /// DETAILS:
    /// The link location is resolved via `virtual_join()` to clamp/anchor within this root.
    /// Note: Most platforms forbid directory hard links; expect an error from the OS.
    pub fn virtual_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();
        let validated_link = self
            .virtual_join(link_ref)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let root = self
            .root
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_hard_link(validated_link.as_unvirtual().path())
    }

    /// SUMMARY:
    /// Create a Windows NTFS directory junction at `link_path` pointing to this virtual root's directory.
    ///
    /// DETAILS:
    /// - Windows-only and behind the `junctions` feature.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn virtual_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();
        let validated_link = self
            .virtual_join(link_ref)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let root = self
            .root
            .clone()
            .into_strictpath()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        root.strict_junction(validated_link.as_unvirtual().path())
    }

    /// SUMMARY:
    /// Read directory entries at the virtual root (discovery). Re‑join names through virtual/strict APIs before I/O.
    #[inline]
    pub fn read_dir(&self) -> std::io::Result<std::fs::ReadDir> {
        self.root.read_dir()
    }

    /// SUMMARY:
    /// Remove the underlying root directory (non‑recursive); fails if not empty.
    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        self.root.remove_dir()
    }

    /// SUMMARY:
    /// Recursively remove the underlying root directory and all its contents.
    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        self.root.remove_dir_all()
    }

    /// SUMMARY:
    /// Ensure the directory exists (create if missing), then return a `VirtualRoot`.
    ///
    /// EXAMPLE:
    /// Uses `AsRef<Path>` for maximum ergonomics, including direct `TempDir` support for clean shadowing patterns:
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use strict_path::VirtualRoot;
    /// let vroot = VirtualRoot::<()>::try_new_create("./data")?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let root = PathBoundary::try_new_create(root_path)?;
        Ok(Self {
            root,
            _marker: PhantomData,
        })
    }

    /// SUMMARY:
    /// Join a candidate path to this virtual root, producing a clamped `VirtualPath`.
    ///
    /// DETAILS:
    /// This is the security gateway for virtual paths. Absolute paths (starting with `"/"`) are
    /// automatically clamped to the virtual root, ensuring paths cannot escape the sandbox.
    /// For example, `"/etc/config"` becomes `vroot/etc/config`, and traversal attempts like
    /// `"../../../../etc/passwd"` are clamped to `vroot/etc/passwd`. This clamping behavior is
    /// what makes the `virtual_` dimension safe for user-facing operations.
    ///
    /// PARAMETERS:
    /// - `candidate_path` (`AsRef<Path>`): Virtual path to resolve and clamp. Absolute paths
    ///   are interpreted relative to the virtual root, not the system root.
    ///
    /// RETURNS:
    /// - `Result<VirtualPath<Marker>>`: Clamped, validated path within the virtual root.
    ///
    /// ERRORS:
    /// - `StrictPathError::PathResolutionError`, `StrictPathError::PathEscapesBoundary`.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let td = tempfile::tempdir().unwrap();
    /// let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path())?;
    ///
    /// // Absolute paths are clamped to virtual root, not system root
    /// let path1 = vroot.virtual_join("/etc/config")?;
    /// assert_eq!(path1.virtualpath_display().to_string(), "/etc/config");
    ///
    /// // Traversal attempts are also clamped
    /// let path2 = vroot.virtual_join("../../../etc/passwd")?;
    /// assert_eq!(path2.virtualpath_display().to_string(), "/etc/passwd");
    ///
    /// // Both paths are safely within the virtual root on the actual filesystem
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn virtual_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>> {
        // 1) Anchor in virtual space (clamps virtual root and resolves relative parts)
        let user_candidate = candidate_path.as_ref().to_path_buf();
        let anchored = PathHistory::new(user_candidate).canonicalize_anchored(&self.root)?;

        // 2) Boundary-check once against the PathBoundary's canonicalized root (no re-canonicalization)
        let validated = anchored.boundary_check(self.root.stated_path())?;

        // 3) Construct a StrictPath directly and then virtualize
        let jp = crate::path::strict_path::StrictPath::new(
            std::sync::Arc::new(self.root.clone()),
            validated,
        );
        Ok(jp.virtualize())
    }

    /// Returns the underlying path boundary root as a system path.
    #[inline]
    pub(crate) fn path(&self) -> &Path {
        self.root.path()
    }

    /// SUMMARY:
    /// Return the virtual root path as `&OsStr` for unavoidable third-party `AsRef<Path>` interop.
    #[inline]
    pub fn interop_path(&self) -> &std::ffi::OsStr {
        self.root.interop_path()
    }

    /// Returns true if the underlying path boundary root exists.
    #[inline]
    pub fn exists(&self) -> bool {
        self.root.exists()
    }

    /// SUMMARY:
    /// Borrow the underlying `PathBoundary`.
    #[inline]
    pub fn as_unvirtual(&self) -> &PathBoundary<Marker> {
        &self.root
    }

    /// SUMMARY:
    /// Consume this `VirtualRoot` and return the underlying `PathBoundary` (symmetry with `virtualize`).
    #[inline]
    pub fn unvirtual(self) -> PathBoundary<Marker> {
        self.root
    }

    // OS Standard Directory Constructors
    //
    // Creates virtual roots in OS standard directories following platform conventions.
    // Applications see clean virtual paths ("/config.toml") while the system manages
    // the actual location (e.g., "~/.config/myapp/config.toml").
}

impl<Marker> std::fmt::Display for VirtualRoot<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path().display())
    }
}

impl<Marker> AsRef<Path> for VirtualRoot<Marker> {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl<Marker> std::fmt::Debug for VirtualRoot<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualRoot")
            .field("root", &self.path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

impl<Marker> Eq for VirtualRoot<Marker> {}

impl<M1, M2> PartialEq<VirtualRoot<M2>> for VirtualRoot<M1> {
    #[inline]
    fn eq(&self, other: &VirtualRoot<M2>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> std::hash::Hash for VirtualRoot<Marker> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<Marker> PartialOrd for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for VirtualRoot<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path().cmp(other.path())
    }
}

impl<M1, M2> PartialEq<crate::PathBoundary<M2>> for VirtualRoot<M1> {
    #[inline]
    fn eq(&self, other: &crate::PathBoundary<M2>) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> PartialEq<std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::Path) -> bool {
        // Compare as virtual root path (always "/")
        // VirtualRoot represents the virtual "/" regardless of underlying system path
        let other_str = other.to_string_lossy();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        "/" == normalized_other
    }
}

impl<Marker> PartialEq<std::path::PathBuf> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &std::path::PathBuf) -> bool {
        self.eq(other.as_path())
    }
}

impl<Marker> PartialEq<&std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn eq(&self, other: &&std::path::Path) -> bool {
        self.eq(*other)
    }
}

impl<Marker> PartialOrd<std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &std::path::Path) -> Option<std::cmp::Ordering> {
        // Compare as virtual root path (always "/")
        let other_str = other.to_string_lossy();

        // Handle empty path specially - "/" is greater than ""
        if other_str.is_empty() {
            return Some(std::cmp::Ordering::Greater);
        }

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{}", other_normalized)
        };

        Some("/".cmp(&normalized_other))
    }
}

impl<Marker> PartialOrd<&std::path::Path> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &&std::path::Path) -> Option<std::cmp::Ordering> {
        self.partial_cmp(*other)
    }
}

impl<Marker> PartialOrd<std::path::PathBuf> for VirtualRoot<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &std::path::PathBuf) -> Option<std::cmp::Ordering> {
        self.partial_cmp(other.as_path())
    }
}

impl<Marker: Default> std::str::FromStr for VirtualRoot<Marker> {
    type Err = crate::StrictPathError;

    /// Parse a VirtualRoot from a string path for universal ergonomics.
    ///
    /// Creates the directory if it doesn't exist, enabling seamless integration
    /// with any string-parsing context (clap, config files, environment variables, etc.):
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let temp_dir = tempfile::tempdir()?;
    /// let virtual_path = temp_dir.path().join("virtual_dir");
    /// let vroot: VirtualRoot<()> = virtual_path.to_string_lossy().parse()?;
    /// assert!(virtual_path.exists());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    fn from_str(path: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_new_create(path)
    }
}
