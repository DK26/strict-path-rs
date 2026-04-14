//! `StrictOpenOptions` builder and `StrictReadDir` iterator for `StrictPath`.
//!
//! `StrictOpenOptions` mirrors `std::fs::OpenOptions` but operates on a validated path,
//! so the file opened is guaranteed to be within the boundary. `StrictReadDir` wraps
//! `std::fs::ReadDir` and re-validates each entry through `strict_join`, preventing a
//! directory listing from producing raw paths that bypass the boundary check.
use super::StrictPath;

// ============================================================
// StrictOpenOptions — Builder for advanced file opening
// ============================================================

/// Builder for opening files with custom options (read, write, append, create, truncate, create_new).
///
/// Use `StrictPath::open_with()` to get an instance. Chain builder methods to configure
/// options, then call `.open()` to obtain the file handle. This mirrors `std::fs::OpenOptions`
/// but operates on a validated `StrictPath`, so the path is guaranteed to be within its boundary.
///
/// # Examples
///
/// ```rust
/// # use strict_path::{PathBoundary, StrictPath};
/// # use std::io::Write;
/// # let temp = tempfile::tempdir()?;
/// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
/// let log_path: StrictPath = data_dir.strict_join("app.log")?;
/// let mut file = log_path.open_with()
///     .create(true)
///     .append(true)
///     .open()?;
/// file.write_all(b"log entry\n")?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[must_use = "open_with() returns a builder — chain .read(), .write(), .create(), .open() to use it"]
pub struct StrictOpenOptions<'path, Marker> {
    path: &'path StrictPath<Marker>,
    options: std::fs::OpenOptions,
}

impl<'path, Marker> StrictOpenOptions<'path, Marker> {
    /// Create a new builder with default options (all flags false).
    #[inline]
    pub(crate) fn new(path: &'path StrictPath<Marker>) -> Self {
        Self {
            path,
            options: std::fs::OpenOptions::new(),
        }
    }

    /// Set the option for read access.
    ///
    /// When `true`, the file will be readable after opening.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("data.bin")?;
    /// file_path.write(b"hello")?;
    /// let _file = file_path.open_with().read(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn read(mut self, read: bool) -> Self {
        self.options.read(read);
        self
    }

    /// Set the option for write access.
    ///
    /// When `true`, the file will be writable after opening.
    /// If the file exists, writes will overwrite existing content starting at the beginning
    /// unless `.append(true)` is also set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("out.txt")?;
    /// let _file = file_path.open_with().write(true).create(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn write(mut self, write: bool) -> Self {
        self.options.write(write);
        self
    }

    /// Set the option for append mode.
    ///
    /// When `true`, all writes will append to the end of the file instead of overwriting.
    /// Implies `.write(true)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let log_path = data_dir.strict_join("app.log")?;
    /// let _file = log_path.open_with().append(true).create(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn append(mut self, append: bool) -> Self {
        self.options.append(append);
        self
    }

    /// Set the option for truncating the file.
    ///
    /// When `true`, the file will be truncated to zero length upon opening.
    /// Requires `.write(true)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("reset.txt")?;
    /// file_path.write(b"old content")?;
    /// let _file = file_path.open_with().write(true).truncate(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.options.truncate(truncate);
        self
    }

    /// Set the option to create the file if it doesn't exist.
    ///
    /// When `true`, the file will be created if missing. Requires `.write(true)` or `.append(true)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("new.txt")?;
    /// let _file = file_path.open_with().write(true).create(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create(mut self, create: bool) -> Self {
        self.options.create(create);
        self
    }

    /// Set the option for exclusive creation (fail if file exists).
    ///
    /// When `true`, the file must not exist; opening will fail with `AlreadyExists` if it does.
    /// Requires `.write(true)` and implies `.create(true)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("unique.txt")?;
    /// let _file = file_path.open_with().write(true).create_new(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.options.create_new(create_new);
        self
    }

    /// Open the file with the configured options.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use strict_path::PathBoundary;
    /// # let temp = tempfile::tempdir()?;
    /// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    /// let file_path = data_dir.strict_join("output.txt")?;
    /// let _file = file_path.open_with().write(true).create(true).open()?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn open(self) -> std::io::Result<std::fs::File> {
        self.options.open(self.path.path())
    }
}

// ============================================================
// StrictReadDir — Iterator for validated directory entries
// ============================================================

/// Iterator over directory entries that yields validated `StrictPath` values.
///
/// Created by `StrictPath::strict_read_dir()`. Each iteration automatically validates
/// the directory entry through `strict_join()`, so you get `StrictPath` values directly
/// instead of raw `std::fs::DirEntry` that would require manual re-validation.
///
/// # Examples
///
/// ```rust
/// # use strict_path::{PathBoundary, StrictPath};
/// # let temp = tempfile::tempdir()?;
/// # let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
/// # let dir = data_dir.strict_join("docs")?;
/// # dir.create_dir_all()?;
/// # data_dir.strict_join("docs/readme.md")?.write("# Docs")?;
/// for entry in dir.strict_read_dir()? {
///     let child: StrictPath = entry?;
///     if child.is_file() {
///         println!("File: {}", child.strictpath_display());
///     }
/// }
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct StrictReadDir<'path, Marker> {
    pub(super) inner: std::fs::ReadDir,
    pub(super) parent: &'path StrictPath<Marker>,
}

impl<Marker> std::fmt::Debug for StrictReadDir<'_, Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictReadDir")
            .field("parent", &self.parent.strictpath_display())
            .finish_non_exhaustive()
    }
}

impl<Marker: Clone> Iterator for StrictReadDir<'_, Marker> {
    type Item = std::io::Result<StrictPath<Marker>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(entry) => {
                let file_name = entry.file_name();
                match self.parent.strict_join(file_name) {
                    Ok(strict_path) => Some(Ok(strict_path)),
                    Err(e) => Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))),
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
