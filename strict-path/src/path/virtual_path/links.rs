use super::VirtualPath;
use std::path::Path;

impl<Marker> VirtualPath<Marker> {
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
    /// Read the target of a symbolic link and return it as a validated `VirtualPath`.
    ///
    /// DESIGN NOTE:
    /// This method has limited practical use because `virtual_join` resolves symlinks
    /// during canonicalization. A `VirtualPath` obtained via `virtual_join("/link")` already
    /// points to the symlink's target, not the symlink itself.
    ///
    /// To read a symlink target before validation, use `std::fs::read_link` on the raw
    /// path, then validate the target with `virtual_join`:
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::VirtualRoot;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let vroot: VirtualRoot = VirtualRoot::try_new(temp.path())?;
    ///
    /// // Create a target file
    /// let target = vroot.virtual_join("/data/target.txt")?;
    /// target.create_parent_dir_all()?;
    /// target.write("secret")?;
    ///
    /// // Create symlink (may fail on Windows without Developer Mode)
    /// if target.virtual_symlink("/data/link.txt").is_ok() {
    ///     // virtual_join resolves symlinks: link.txt -> target.txt
    ///     let resolved = vroot.virtual_join("/data/link.txt")?;
    ///     assert_eq!(resolved.virtualpath_display().to_string(), "/data/target.txt");
    ///     // The resolved path reads the target file's content
    ///     assert_eq!(resolved.read_to_string()?, "secret");
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn virtual_read_link(&self) -> std::io::Result<Self> {
        // Read the raw symlink target
        let raw_target = std::fs::read_link(self.inner.path())?;

        // If the target is relative, resolve it relative to the symlink's parent
        let resolved_target = if raw_target.is_relative() {
            match self.inner.path().parent() {
                Some(parent) => parent.join(&raw_target),
                None => raw_target,
            }
        } else {
            raw_target
        };

        // Validate through virtual_join which clamps escapes
        // We need to compute the relative path from the virtual root
        let vroot = self.inner.boundary().clone().virtualize();
        vroot
            .virtual_join(resolved_target)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
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
