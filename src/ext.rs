//! Ergonomic, opt-in extensions for `JailedPath`.
//!
//! This module provides traits that extend the functionality of [`JailedPath`].
//! These traits are not included in the prelude and must be imported explicitly.
//!
//! The primary trait is [`JailedFileOps`], which provides convenient, jail-safe
//! file I/O operations directly on a `JailedPath` instance.
//!
//! # Usage
//!
//! To use the extension traits, simply import them into your scope:
//!
//! ```rust
//! use jailed_path::ext::JailedFileOps; // Import the trait
//! use jailed_path::PathValidator;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # std::fs::create_dir_all("test_jail/safe")?;
//! # std::fs::write("test_jail/safe/file.txt", "existing content")?;
//! // Create a validator and a jailed path
//! let validator = PathValidator::<()>::with_jail("test_jail")?;
//! let jailed = validator.try_path("safe/file.txt")?;
//!
//! // Now you can use the trait methods directly
//! if jailed.exists() {
//!     let content = jailed.read_to_string()?;
//!     println!("File content: {}", content);
//! }
//!
//! jailed.write_bytes(b"Hello, world!")?;
//! # std::fs::remove_dir_all("test_jail").ok();
//! # Ok(())
//! # }
//! ```

use crate::jailed_path::JailedPath;
use std::io;

/// An extension trait for [`JailedPath`] that provides ergonomic, jail-safe file I/O operations.
///
/// This trait allows you to perform common file operations directly on a `JailedPath`
/// without needing to use the `std::fs` module manually.
/// All operations are guaranteed to be safe and occur within the jail boundary.
///
/// ## Design Philosophy
///
/// File I/O operations are kept in this optional trait rather than as inherent methods on
/// `JailedPath` to keep the core type focused on path validation and manipulation. This
/// separation allows users to opt-in to file operations when needed.
///
/// To use this trait, you must import it explicitly:
/// ```rust
/// use jailed_path::ext::JailedFileOps;
/// ```
pub trait JailedFileOps {
    // ---- File System Inspection ----

    /// Returns true if the path exists on disk.
    fn exists(&self) -> bool;

    /// Returns true if the path is a file.
    fn is_file(&self) -> bool;

    /// Returns true if the path is a directory.
    fn is_dir(&self) -> bool;

    /// Returns the metadata for the path.
    fn metadata(&self) -> io::Result<std::fs::Metadata>;

    // ---- Reading Operations ----

    /// Reads the entire contents of a file into a string.
    ///
    /// This is a convenience method that wraps `std::fs::read_to_string`.
    ///
    /// # Errors
    ///
    /// This function will return an error if `path` does not exist, is not a file,
    /// or if the contents are not valid UTF-8.
    fn read_to_string(&self) -> io::Result<String>;

    /// Reads the entire contents of a file into a bytes vector.
    ///
    /// This is a convenience method that wraps `std::fs::read`.
    ///
    /// # Errors
    ///
    /// This function will return an error if `path` does not exist or is not a file.
    fn read_bytes(&self) -> io::Result<Vec<u8>>;

    // ---- Writing Operations ----

    /// Write a slice of bytes as the entire content of a file.
    ///
    /// This function will create a file if it does not exist, and will entirely
    /// replace its contents if it does.
    ///
    /// This is a convenience method that wraps `std::fs::write`.
    fn write_bytes(&self, data: &[u8]) -> io::Result<()>;

    /// Write a string as the entire content of a file.
    ///
    /// This function will create a file if it does not exist, and will entirely
    /// replace its contents if it does.
    fn write_string(&self, data: &str) -> io::Result<()>;

    // ---- Directory Operations ----

    /// Creates a directory at this path, including any parent directories.
    ///
    /// This is a convenience method that wraps `std::fs::create_dir_all`.
    fn create_dir_all(&self) -> io::Result<()>;

    /// Removes a file from the filesystem.
    ///
    /// This is a convenience method that wraps `std::fs::remove_file`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the file does not exist or if the user lacks permissions to remove it.
    fn remove_file(&self) -> io::Result<()>;

    /// Removes an empty directory.
    ///
    /// This is a convenience method that wraps `std::fs::remove_dir`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the directory does not exist, is not empty, or if the user lacks permissions.
    fn remove_dir(&self) -> io::Result<()>;

    /// Removes a directory and all its contents recursively.
    ///
    /// This is a convenience method that wraps `std::fs::remove_dir_all`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the directory does not exist or if the user lacks permissions.
    fn remove_dir_all(&self) -> io::Result<()>;
}

impl<Marker> JailedFileOps for JailedPath<Marker> {
    // ---- File System Inspection ----

    #[inline]
    fn exists(&self) -> bool {
        self.internal_path().exists()
    }

    #[inline]
    fn is_file(&self) -> bool {
        self.internal_path().is_file()
    }

    #[inline]
    fn is_dir(&self) -> bool {
        self.internal_path().is_dir()
    }

    #[inline]
    fn metadata(&self) -> io::Result<std::fs::Metadata> {
        std::fs::metadata(self.internal_path())
    }

    // ---- Reading Operations ----

    #[inline]
    fn read_to_string(&self) -> io::Result<String> {
        std::fs::read_to_string(self.internal_path())
    }

    #[inline]
    fn read_bytes(&self) -> io::Result<Vec<u8>> {
        std::fs::read(self.internal_path())
    }

    // ---- Writing Operations ----

    #[inline]
    fn write_bytes(&self, data: &[u8]) -> io::Result<()> {
        std::fs::write(self.internal_path(), data)
    }

    #[inline]
    fn write_string(&self, data: &str) -> io::Result<()> {
        std::fs::write(self.internal_path(), data)
    }

    // ---- Directory Operations ----

    #[inline]
    fn create_dir_all(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.internal_path())
    }

    #[inline]
    fn remove_file(&self) -> io::Result<()> {
        std::fs::remove_file(self.internal_path())
    }

    #[inline]
    fn remove_dir(&self) -> io::Result<()> {
        std::fs::remove_dir(self.internal_path())
    }

    #[inline]
    fn remove_dir_all(&self) -> io::Result<()> {
        std::fs::remove_dir_all(self.internal_path())
    }
}
