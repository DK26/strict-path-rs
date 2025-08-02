use crate::error::JailedPathError;
use crate::validator::validated_path::{
    BoundaryChecked, Canonicalized, Clamped, JoinedJail, Raw, ValidatedPath,
};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::Arc;

// --- Struct Definition ---

/// A validated path that is guaranteed to be within a defined jail boundary.
///
/// ## Virtual Root Display
///
/// When you print a `JailedPath` (using the `Display` trait), it shows the path as if it starts from the root of your jail.
/// This keeps user-facing output clean and intuitive, never leaking internal or absolute paths.
#[derive(Clone)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail_root: Arc<ValidatedPath<(Raw, Canonicalized)>>,
    _marker: PhantomData<Marker>,
}

// --- Inherent Methods ---
#[allow(clippy::type_complexity)]
impl<Marker> JailedPath<Marker> {
    /// Creates a new JailedPath from a fully validated ValidatedPath with the exact required type-state.
    pub(crate) fn new(
        jail_root: Arc<ValidatedPath<(Raw, Canonicalized)>>,
        validated_path: ValidatedPath<(
            (((Raw, Clamped), JoinedJail), Canonicalized),
            BoundaryChecked,
        )>,
    ) -> Self {
        // The validated_path is always fully validated and jail-relative (relative to jail root)
        Self {
            path: validated_path.into_inner(),
            jail_root,
            _marker: PhantomData,
        }
    }

    /// Returns true if the path starts with the given base.
    #[inline]
    pub fn starts_with<P: AsRef<Path>>(&self, base: P) -> bool {
        self.path.starts_with(base)
    }

    /// Returns true if the virtual path (as shown to the user) starts with the given base.
    /// This is useful for user-facing search/filter features.
    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, base: P) -> bool {
        // Use platform-specific Path comparison for virtual path
        let jail_relative = if let Ok(relative) = self.path.strip_prefix(&*self.jail_root) {
            relative
        } else {
            Path::new("")
        };
        jail_relative.starts_with(base)
    }

    /// Returns a displayable representation of the path (virtual root) as an owned String (always with forward slashes).
    #[inline]
    pub fn virtual_display(&self) -> String {
        let pb = self.virtual_path();
        // Always produce forward slashes, even on Windows
        let mut s = String::from("");
        for comp in pb.components() {
            s.push('/');
            s.push_str(&comp.as_os_str().to_string_lossy());
        }
        if s.is_empty() {
            s.push('/');
        }
        s
    }

    /// Returns the file name of the path, if any.
    #[inline]
    pub fn file_name(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    /// Returns the extension of the path, if any.
    #[inline]
    pub fn extension(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    /// Returns the path as an OsStr.
    #[inline]
    pub fn as_os_str(&self) -> &OsStr {
        self.path.as_os_str()
    }

    /// Returns the real path as a string slice, if valid UTF-8.
    ///
    /// This method returns a `&str` representation of the **real, absolute path** on the filesystem.
    /// It should be used with caution, as it exposes the underlying filesystem structure.
    /// For a user-facing, jail-relative path, use [`JailedPath::virtual_path_to_string()`]
    /// or the `Display` trait (`format!("{}", jailed_path)`).
    #[inline]
    pub fn real_path_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    /// Returns the real path as a `Cow<str>`, replacing any invalid UTF-8 sequences with U+FFFD.
    ///
    /// This method returns a string representation of the **real, absolute path** on the filesystem.
    /// It should be used with caution, as it exposes the underlying filesystem structure.
    /// For a user-facing, jail-relative path, use [`JailedPath::virtual_path_to_string_lossy()`]
    /// or the `Display` trait (`format!("{}", jailed_path)`).
    #[inline]
    pub fn real_path_to_string_lossy(&self) -> Cow<'_, str> {
        self.path.to_string_lossy()
    }

    /// Returns the virtual path as an owned `String`, if valid UTF-8.
    ///
    /// This method returns a `String` representation of the **virtual, jail-relative path**
    /// using the platform's standard path separators.
    /// For a consistent forward-slash representation suitable for display, use the `Display`
    /// trait (`format!("{jailed_path}")`) which uses [`JailedPath::virtual_display()`].
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` if the path is valid UTF-8, otherwise `None`.
    #[inline]
    pub fn virtual_path_to_string(&self) -> Option<String> {
        self.virtual_path().into_os_string().into_string().ok()
    }

    /// Returns the virtual path as an owned `String`, replacing any invalid UTF-8 sequences with U+FFFD.
    ///
    /// This method returns a `String` representation of the **virtual, jail-relative path**
    /// using the platform's standard path separators.
    /// For a consistent forward-slash representation suitable for display, use the `Display`
    /// trait (`format!("{}", jailed_path)`) which uses [`JailedPath::virtual_display()`].
    #[inline]
    pub fn virtual_path_to_string_lossy(&self) -> String {
        self.virtual_path().to_string_lossy().into_owned()
    }

    /// Returns a reference to the real, absolute path on the filesystem.
    #[inline]
    pub fn real_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns a `PathBuf` representing the virtual path (the path relative to the jail root).
    /// This path uses the platform's standard path separators. For a consistent forward-slash
    /// representation, use `virtual_display()`.
    pub fn virtual_path(&self) -> PathBuf {
        if let Ok(relative) = self.path.strip_prefix(&*self.jail_root) {
            let mut pb = PathBuf::new();
            for comp in relative.components() {
                match comp {
                    Component::Normal(os) => pb.push(os),
                    Component::CurDir => {}
                    Component::ParentDir => pb.push(".."),
                    _ => {}
                }
            }
            pb
        } else {
            PathBuf::from("")
        }
    }

    /// Consumes the JailedPath and returns the jail-relative path as a PathBuf.
    #[inline]
    pub fn unjail(self) -> PathBuf {
        self.path
    }

    /// Returns a new JailedPath by safely joining a user-supplied path to the virtual path.
    ///
    /// # Usage
    /// - This method joins paths in the virtual filesystem (user's perspective).
    /// - The current JailedPath represents a virtual path like "/foo/bar.txt"
    /// - Joining "baz.txt" results in "/foo/bar.txt/baz.txt" virtually
    /// - The argument must be a jail-relative or user-style path (e.g., "foo/bar", "../baz", or "/baz").
    /// - Any absolute or rooted path is treated as jail-relative (the user sees their root as the jail root).
    ///
    /// # Invariant
    /// - The resulting path will always be clamped to the jail root and never escape it.
    /// - This operates on virtual paths, then validates the result against the real filesystem.
    pub fn virtual_join<P: AsRef<Path>>(&self, path: P) -> Option<Self> {
        self.try_virtual_join(path).ok()
    }

    /// Returns a new JailedPath by safely joining a user-supplied path (jail-relative), or an error if result escapes jail or canonicalization fails.
    ///
    /// # Usage
    /// - This method is for joining user/external input, where the user is unaware of the jail's real system path.
    /// - The argument must be a jail-relative or user-style path (e.g., "foo/bar", "../baz", or "/baz").
    /// - Any absolute or rooted path is treated as jail-relative (the user sees their root as the jail root).
    /// - Never pass an already jailed or system-absolute path (e.g., jail_root.join("foo")) to this method.
    /// - Do not use PathBuf::join or Path::join on the inner path, as it may escape the jail boundary.
    ///
    /// # Invariant
    /// - The resulting path will always be clamped to the jail root and never escape it.
    /// - This method is not for joining already jailed or canonicalized paths.
    pub fn try_virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self, JailedPathError> {
        let arg = path.as_ref();

        // Get the current virtual path as PathBuf
        let current_virtual_pb = self.virtual_path();
        // If the virtual path is empty (root), use empty PathBuf, else use as-is
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        // Normalize the user's argument to a virtual path
        // The user operates purely in virtual space - they don't know about real jail paths
        let arg_virtual = if arg.is_absolute() {
            // User provided an absolute path like "/some/path"
            // Treat as jail-relative: strip all root components
            let mut virtual_path = PathBuf::new();
            for comp in arg.components() {
                match comp {
                    Component::RootDir | Component::Prefix(_) => continue,
                    _ => virtual_path.push(comp.as_os_str()),
                }
            }
            virtual_path
        } else {
            // User provided a relative path - use as-is
            arg.to_path_buf()
        };

        // Join in virtual space: current virtual path + user's virtual path
        let virtual_joined = current_virtual.join(arg_virtual);

        // Now validate this virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(virtual_joined)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns the parent as a new JailedPath, or None if parent escapes jail (with canonicalization and boundary check).
    pub fn virtual_parent(&self) -> Option<Self> {
        self.try_virtual_parent().ok()
    }

    /// Returns the parent as a new JailedPath, or an error if parent escapes jail or does not exist (with canonicalization and boundary check).
    pub fn try_virtual_parent(&self) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and find its parent
        let current_virtual_pb = self.virtual_path();
        if current_virtual_pb.as_os_str().is_empty() {
            // Already at root, no parent
            return Err(JailedPathError::path_resolution_error(
                self.path.clone(),
                IoError::new(ErrorKind::NotFound, "No parent - already at jail root"),
            ));
        }
        let current_virtual = current_virtual_pb;

        let parent_virtual = current_virtual.parent().ok_or_else(|| {
            JailedPathError::path_resolution_error(
                self.path.clone(),
                IoError::new(ErrorKind::NotFound, "No parent"),
            )
        })?;

        // Validate this parent virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(parent_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns a new JailedPath with a different file name, or None if result escapes jail (with canonicalization and boundary check).
    pub fn virtual_with_file_name<S: AsRef<OsStr>>(&self, name: S) -> Option<Self> {
        self.try_virtual_with_file_name(name).ok()
    }

    /// Returns a new JailedPath with a different file name, or an error if result escapes jail (with canonicalization and boundary check).
    pub fn try_virtual_with_file_name<S: AsRef<OsStr>>(
        &self,
        name: S,
    ) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and change file name
        let current_virtual_pb = self.virtual_path();
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        let new_virtual = current_virtual.with_file_name(name);

        // Validate this new virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(new_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns a new JailedPath with a different extension, or None if result escapes jail (with canonicalization and boundary check).
    pub fn virtual_with_extension<S: AsRef<OsStr>>(&self, ext: S) -> Option<Self> {
        self.try_virtual_with_extension(ext).ok()
    }

    /// Returns a new JailedPath with a different extension, or an error if result escapes jail (with canonicalization and boundary check).
    pub fn try_virtual_with_extension<S: AsRef<OsStr>>(
        &self,
        ext: S,
    ) -> Result<Self, JailedPathError> {
        // Work in virtual space - get current virtual path and change extension
        let current_virtual_pb = self.virtual_path();
        let current_virtual = if current_virtual_pb.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            current_virtual_pb
        };

        let new_virtual = current_virtual.with_extension(ext);

        // Validate this new virtual path through the normal pipeline
        let validated_path = ValidatedPath::<Raw>::new(new_virtual)
            .clamp()
            .join_jail(&self.jail_root)
            .canonicalize()?
            .boundary_check(&self.jail_root)?;
        Ok(Self::new(self.jail_root.clone(), validated_path))
    }

    /// Returns the path as bytes (platform-specific).
    pub fn to_bytes(&self) -> Vec<u8> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.path.as_os_str().as_bytes().to_vec()
        }
        #[cfg(windows)]
        {
            self.path.to_string_lossy().as_bytes().to_vec()
        }
    }

    /// Consumes and returns the path as bytes (platform-specific).
    pub fn into_bytes(self) -> Vec<u8> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.path.into_os_string().as_bytes().to_vec()
        }
        #[cfg(windows)]
        {
            self.path.to_string_lossy().into_owned().into_bytes()
        }
    }

    /// Returns a reference to the jail root path.
    pub fn jail_root(&self) -> &Path {
        &self.jail_root
    }
}

// --- Trait Implementations ---
impl<Marker> fmt::Display for JailedPath<Marker> {
    /// Shows the path as if from the jail root, for clean user-facing output (always with forward slashes).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.virtual_display())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format path and jail_root using platform separator for consistency
        let format_path = |p: &Path| {
            let mut s = String::new();
            for (i, c) in p.components().enumerate() {
                if i > 0 {
                    s.push(MAIN_SEPARATOR);
                }
                s.push_str(&c.as_os_str().to_string_lossy());
            }
            s
        };
        f.debug_struct("JailedPath")
            .field("path", &format_path(&self.path))
            .field("jail_root", &format_path(&self.jail_root))
            .finish()
    }
}

impl<Marker> PartialEq for JailedPath<Marker> {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<Marker> Eq for JailedPath<Marker> {}

impl<Marker> Hash for JailedPath<Marker> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<Marker> PartialOrd for JailedPath<Marker> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for JailedPath<Marker> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl<Marker> PartialEq<PathBuf> for JailedPath<Marker> {
    fn eq(&self, other: &PathBuf) -> bool {
        &self.path == other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for PathBuf {
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        self == &other.path
    }
}

impl<Marker> PartialEq<Path> for JailedPath<Marker> {
    fn eq(&self, other: &Path) -> bool {
        self.path.as_path() == other
    }
}

impl<Marker> PartialEq<JailedPath<Marker>> for Path {
    fn eq(&self, other: &JailedPath<Marker>) -> bool {
        self == other.path.as_path()
    }
}
