//! Filesystem I/O methods for `StrictPath`.
//!
//! Every method here delegates to the OS through the validated, canonicalized inner path.
//! Keeping I/O separate from path composition makes it easy to audit: all boundary enforcement
//! happens in `mod.rs`; this file only performs reads, writes, and directory operations.
use super::{iter::StrictOpenOptions, StrictPath};
use crate::StrictPathError;

impl<Marker> StrictPath<Marker> {
    /// Create or truncate the file at this strict path and return a writable handle.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: Propagates OS errors when the parent directory is missing or file creation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::Write;
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-create-file-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let requested_file = "logs/app.log";
    /// let log_path: StrictPath = data_dir.strict_join(requested_file)?;
    /// log_path.create_parent_dir_all()?;
    /// let mut file = log_path.create_file()?;
    /// file.write_all(b"session started")?;
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::create(self.path())
    }

    /// Open the file at this strict path in read-only mode.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: Propagates OS errors when the file is missing or inaccessible.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::{Read, Write};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-open-file-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let requested_file = "logs/session.log";
    /// let transcript: StrictPath = data_dir.strict_join(requested_file)?;
    /// transcript.create_parent_dir_all()?;
    /// transcript.write("session start")?;
    /// let mut file = transcript.open_file()?;
    /// let mut contents = String::new();
    /// file.read_to_string(&mut contents)?;
    /// assert_eq!(contents, "session start");
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.path())
    }

    /// Return an options builder for advanced file opening (read+write, append, exclusive create, etc.).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::{PathBoundary, StrictPath};
    /// # use std::io::{Read, Write, Seek, SeekFrom};
    /// # let boundary_dir = std::env::temp_dir().join("strict-path-open-with-example");
    /// # std::fs::create_dir_all(&boundary_dir)?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(&boundary_dir)?;
    /// // Untrusted input from request/CLI/config/etc.
    /// let data_file = "data/records.bin";
    /// let file_path: StrictPath = data_dir.strict_join(data_file)?;
    /// file_path.create_parent_dir_all()?;
    ///
    /// // Open with read+write access, create if missing
    /// let mut file = file_path.open_with()
    ///     .read(true)
    ///     .write(true)
    ///     .create(true)
    ///     .open()?;
    /// file.write_all(b"header")?;
    /// file.seek(SeekFrom::Start(0))?;
    /// let mut buf = [0u8; 6];
    /// file.read_exact(&mut buf)?;
    /// assert_eq!(&buf, b"header");
    /// # std::fs::remove_dir_all(&boundary_dir)?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use = "open_with() returns a builder — chain .read(), .write(), .create(), .open() to use it"]
    #[inline]
    pub fn open_with(&self) -> StrictOpenOptions<'_, Marker> {
        StrictOpenOptions::new(self)
    }

    /// Creates all directories in the system path if missing (like `std::fs::create_dir_all`).
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: Propagates OS errors if any directory cannot be created.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let nested = data_dir.strict_join("a/b/c")?;
    /// nested.create_dir_all()?;
    /// assert!(nested.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.path())
    }

    /// Creates the directory at the system path (non-recursive, like `std::fs::create_dir`).
    ///
    /// Fails if the parent directory does not exist. Use `create_dir_all` to
    /// create missing parent directories recursively.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the parent directory is missing or the directory already exists.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("logs")?;
    /// subdir.create_dir()?;
    /// assert!(subdir.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn create_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir(self.path())
    }

    /// Create only the immediate parent directory (non‑recursive). `Ok(())` at the boundary root.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the grandparent directory is missing or creation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("logs/app.log")?;
    /// file_path.create_parent_dir()?;
    /// assert!(data_dir.strict_join("logs")?.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn create_parent_dir(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir(),
            Ok(None) => Ok(()),
            // Ok(()): At the boundary root, the "parent" would escape the
            // boundary, but there is nothing to create — the boundary dir already
            // exists.  Returning an error here would force every caller to handle
            // a case that never requires action.
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    /// Recursively create all missing directories up to the immediate parent. `Ok(())` at boundary.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If any directory in the chain cannot be created.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("a/b/c/file.txt")?;
    /// file_path.create_parent_dir_all()?;
    /// assert!(data_dir.strict_join("a/b/c")?.is_dir());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn create_parent_dir_all(&self) -> std::io::Result<()> {
        match self.strictpath_parent() {
            Ok(Some(parent)) => parent.create_dir_all(),
            Ok(None) => Ok(()),
            // Ok(()): Same rationale as create_parent_dir — boundary root's
            // parent escapes, but the boundary itself already exists; no action needed.
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    /// Remove the file at this path.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the file does not exist or cannot be removed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("temp.txt")?;
    /// file_path.write("data")?;
    /// file_path.remove_file()?;
    /// assert!(!file_path.exists());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(self.path())
    }

    /// Remove the directory at this path.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the directory does not exist, is not empty, or cannot be removed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("empty_dir")?;
    /// subdir.create_dir()?;
    /// subdir.remove_dir()?;
    /// assert!(!subdir.exists());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(self.path())
    }

    /// Recursively remove the directory and its contents.
    ///
    /// # Errors
    ///
    /// - `std::io::Error`: If the directory does not exist or removal fails partway through.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let subdir = data_dir.strict_join("cache")?;
    /// subdir.create_dir_all()?;
    /// data_dir.strict_join("cache/item.txt")?.write("x")?;
    /// subdir.remove_dir_all()?;
    /// assert!(!subdir.exists());
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.path())
    }
}
