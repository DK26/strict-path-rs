use super::VirtualPath;

impl<Marker> VirtualPath<Marker> {
    /// SUMMARY:
    /// Write bytes to the underlying system path. Accepts `&str`, `String`, `&[u8]`, `Vec<u8]`, etc.
    #[inline]
    pub fn write<C: AsRef<[u8]>>(&self, contents: C) -> std::io::Result<()> {
        self.inner.write(contents)
    }

    /// SUMMARY:
    /// Append bytes to the underlying system path (create if missing). Accepts `&str`, `&[u8]`, etc.
    ///
    /// PARAMETERS:
    /// - `data` (`AsRef<[u8]>`): Bytes to append to the file.
    ///
    /// RETURNS:
    /// - `()`: Returns nothing on success.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the file cannot be opened or written.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # let root = std::env::temp_dir().join("strict-path-vpath-append");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let log_file = "logs/activity.log";
    /// let vpath = vroot.virtual_join(log_file)?;
    /// vpath.create_parent_dir_all()?;
    /// vpath.append("[2025-01-01] Operation A\n")?;
    /// vpath.append("[2025-01-01] Operation B\n")?;
    /// let contents = vpath.read_to_string()?;
    /// assert!(contents.contains("Operation A"));
    /// assert!(contents.contains("Operation B"));
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn append<C: AsRef<[u8]>>(&self, data: C) -> std::io::Result<()> {
        self.inner.append(data)
    }

    /// SUMMARY:
    /// Create or truncate the file at this virtual path and return a writable handle.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Writable handle scoped to the same virtual root restriction.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates operating-system errors when the parent directory is missing or file creation fails.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # use std::io::Write;
    /// # let root = std::env::temp_dir().join("strict-path-virtual-create-file");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// let report = vroot.virtual_join("reports/summary.txt")?;
    /// report.create_parent_dir_all()?;
    /// let mut file = report.create_file()?;
    /// file.write_all(b"summary")?;
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create_file(&self) -> std::io::Result<std::fs::File> {
        self.inner.create_file()
    }

    /// SUMMARY:
    /// Open the file at this virtual path in read-only mode.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Read-only handle scoped to the same virtual root restriction.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates operating-system errors when the file is missing or inaccessible.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # use std::io::{Read, Write};
    /// # let root = std::env::temp_dir().join("strict-path-virtual-open-file");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// let report = vroot.virtual_join("reports/summary.txt")?;
    /// report.create_parent_dir_all()?;
    /// report.write("summary")?;
    /// let mut file = report.open_file()?;
    /// let mut contents = String::new();
    /// file.read_to_string(&mut contents)?;
    /// assert_eq!(contents, "summary");
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open_file(&self) -> std::io::Result<std::fs::File> {
        self.inner.open_file()
    }

    /// SUMMARY:
    /// Return an options builder for advanced file opening (read+write, append, exclusive create, etc.).
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `StrictOpenOptions<Marker>`: Builder to configure file opening options.
    ///
    /// EXAMPLE:
    /// ```rust
    /// # use strict_path::VirtualRoot;
    /// # use std::io::{Read, Write, Seek, SeekFrom};
    /// # let root = std::env::temp_dir().join("vpath-open-with-example");
    /// # std::fs::create_dir_all(&root)?;
    /// # let vroot: VirtualRoot = VirtualRoot::try_new(&root)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let data_file = "cache/state.bin";
    /// let cache_path = vroot.virtual_join(data_file)?;
    /// cache_path.create_parent_dir_all()?;
    ///
    /// // Open with read+write access, create if missing
    /// let mut file = cache_path.open_with()
    ///     .read(true)
    ///     .write(true)
    ///     .create(true)
    ///     .open()?;
    /// file.write_all(b"state")?;
    /// file.seek(SeekFrom::Start(0))?;
    /// let mut buf = [0u8; 5];
    /// file.read_exact(&mut buf)?;
    /// assert_eq!(&buf, b"state");
    /// # std::fs::remove_dir_all(&root)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "open_with() returns a builder — chain .read(), .write(), .create(), .open() to use it"]
    #[inline]
    pub fn open_with(&self) -> crate::path::strict_path::StrictOpenOptions<'_, Marker> {
        self.inner.open_with()
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
}
