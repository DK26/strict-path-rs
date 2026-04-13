use super::{iter::StrictOpenOptions, StrictPath};
use crate::StrictPathError;

impl<Marker> StrictPath<Marker> {
    /// SUMMARY:
    /// Create or truncate the file at this strict path and return a writable handle.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Writable handle scoped to this boundary.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the parent directory is missing or file creation fails.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Open the file at this strict path in read-only mode.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `std::fs::File`: Read-only handle scoped to this boundary.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors when the file is missing or inaccessible.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Return an options builder for advanced file opening (read+write, append, exclusive create, etc.).
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `StrictOpenOptions<Marker>`: Builder to configure file opening options.
    ///
    /// ERRORS:
    /// - None (infallible — errors are deferred to `.open()`).
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Creates all directories in the system path if missing (like `std::fs::create_dir_all`).
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: Directories created (or already existed) successfully.
    ///
    /// ERRORS:
    /// - `std::io::Error`: Propagates OS errors if any directory cannot be created.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Creates the directory at the system path (non-recursive, like `std::fs::create_dir`).
    ///
    /// Fails if the parent directory does not exist. Use `create_dir_all` to
    /// create missing parent directories recursively.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: Directory created successfully.
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the parent directory is missing or the directory already exists.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Create only the immediate parent directory (non‑recursive). `Ok(())` at the boundary root.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: Parent directory created (or is at boundary root where no creation is needed).
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the grandparent directory is missing or creation fails.
    ///
    /// EXAMPLE:
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
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    /// SUMMARY:
    /// Recursively create all missing directories up to the immediate parent. `Ok(())` at boundary.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: All parent directories created (or already existed).
    ///
    /// ERRORS:
    /// - `std::io::Error`: If any directory in the chain cannot be created.
    ///
    /// EXAMPLE:
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
            Err(StrictPathError::PathEscapesBoundary { .. }) => Ok(()),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    /// SUMMARY:
    /// Remove the file at this path.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: File removed successfully.
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the file does not exist or cannot be removed.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Remove the directory at this path.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: Directory removed successfully.
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the directory does not exist, is not empty, or cannot be removed.
    ///
    /// EXAMPLE:
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

    /// SUMMARY:
    /// Recursively remove the directory and its contents.
    ///
    /// PARAMETERS:
    /// - _none_
    ///
    /// RETURNS:
    /// - `()`: Directory and all contents removed successfully.
    ///
    /// ERRORS:
    /// - `std::io::Error`: If the directory does not exist or removal fails partway through.
    ///
    /// EXAMPLE:
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
