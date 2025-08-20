use crate::path::virtual_path::VirtualPath;
use crate::validator::{self, jail::Jail};
use crate::Result;
use std::marker::PhantomData;
use std::path::Path;

/// A user-facing representation of a jail boundary, acting as a virtual filesystem root.
///
/// ## Core Purpose
///
/// `VirtualRoot` is the primary entry point for user-facing path operations. It provides a safe
/// and intuitive API for creating `VirtualPath` instances, which are designed for display,
/// manipulation, and general UX, treating the jail boundary as the filesystem root (`/`).
///
/// This type separates user-facing concerns from system-facing validation, which is handled
/// internally by the `Jail` type.
///
/// ## How It Works
///
/// 1.  **Establish Virtual Root**: Create a `VirtualRoot` with `VirtualRoot::try_new("/app/storage")`.
/// 2.  **Create Virtual Paths**: Use `vroot.try_path_virtual("user/file.txt")` to obtain a `VirtualPath`.
///     to get a `VirtualPath`.
/// 3.  **Use Safely**: The resulting `VirtualPath` will display as `/user/file.txt` and is guaranteed
///     to be safely contained within the `/app/storage` boundary.
///
/// ## Example
///
/// ```rust
/// # use jailed_path::VirtualRoot;
/// # use std::fs;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// fs::create_dir_all("temp_vroot")?;
/// let vroot = VirtualRoot::<()>::try_new("temp_vroot")?;
/// let virtual_path = vroot.try_path_virtual("some/file.txt")?;
///
/// // The virtual path is displayed relative to the virtual root.
/// assert_eq!(virtual_path.to_string(), "/some/file.txt");
///
/// // For file system operations, convert it to a JailedPath.
/// let jailed_path = virtual_path.unvirtual();
/// assert!(jailed_path.starts_with_real(vroot.path()));
///
/// fs::remove_dir_all("temp_vroot")?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VirtualRoot<Marker = ()> {
    jail: Jail<Marker>,
    _marker: PhantomData<Marker>,
}

impl<Marker> VirtualRoot<Marker> {
    /// Creates a new `VirtualRoot` with the specified directory as the boundary.
    ///
    /// The provided path must exist and be a directory.
    ///
    /// # Arguments
    /// * `root_path` - The directory that will serve as the virtual root.
    ///
    /// # Returns
    /// * `Ok(VirtualRoot)` - If the path is a valid, existing directory.
    /// * `Err(JailedPathError)` - If the path does not exist, is not a directory, or is inaccessible.
    #[inline]
    pub fn try_new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new(root_path)?;
        Ok(Self {
            jail,
            _marker: PhantomData,
        })
    }

    /// Creates a new `VirtualRoot`, creating the directory if it doesn't exist.
    ///
    /// This is a convenience method for cases where the virtual root directory needs to be
    /// created before use. It calls `std::fs::create_dir_all` internally.
    ///
    /// # Arguments
    /// * `root_path` - The directory to use or create as the virtual root.
    ///
    /// # Errors
    /// Returns `JailedPathError` if directory creation fails due to permissions, an invalid path,
    /// or if the path exists but is not a directory.
    #[inline]
    pub fn try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new_create(root_path)?;
        Ok(Self {
            jail,
            _marker: PhantomData,
        })
    }

    /// Validates a path against the virtual root and returns a `VirtualPath`.
    ///
    /// This method clamps the path to the virtual root, preventing directory traversal attacks
    /// (`../`) and stripping absolute path components. It is the primary way to convert a
    /// user-provided path into a safe, virtualized representation.
    ///
    /// # Arguments
    /// * `candidate_path` - The user-provided path to validate.
    ///
    /// # Returns
    /// * `Ok(VirtualPath)` - A validated, user-facing path.
    /// * `Err(JailedPathError)` - If validation fails (e.g., due to a symlink escape).
    #[inline]
    pub fn try_path_virtual<P: AsRef<Path>>(
        &self,
        candidate_path: P,
    ) -> Result<VirtualPath<Marker>> {
        let virtualized = validator::virtualize_to_jail(candidate_path, &self.jail);
        let jailed_path = self.jail.try_path(virtualized)?;
        Ok(jailed_path.virtualize())
    }

    /// Returns a reference to the real path of the virtual root.
    ///
    /// This provides read-only access to the underlying filesystem path for logging, debugging,
    /// or integration with other APIs.
    #[inline]
    pub fn path(&self) -> &Path {
        self.jail.path()
    }
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
