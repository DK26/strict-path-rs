use super::StrictPath;
use std::path::Path;

// ============================================================
// Windows symlink helper
// ============================================================

#[cfg(windows)]
pub(super) fn create_windows_symlink(src: &Path, link: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    match std::fs::metadata(src) {
        Ok(metadata) => {
            if metadata.is_dir() {
                symlink_dir(src, link)
            } else {
                symlink_file(src, link)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match symlink_file(src, link) {
                Ok(()) => Ok(()),
                Err(file_err) => {
                    if let Some(code) = file_err.raw_os_error() {
                        const ERROR_DIRECTORY: i32 = 267; // target resolved as directory
                        if code == ERROR_DIRECTORY {
                            return symlink_dir(src, link);
                        }
                    }
                    Err(file_err)
                }
            }
        }
        Err(err) => Err(err),
    }
}

// Note: No separate helper for junction creation by design — keep surface minimal

impl<Marker> StrictPath<Marker> {
    /// SUMMARY:
    /// Create a symbolic link at `link_path` pointing to this path (same boundary required).
    /// On Windows, file vs directory symlink is selected by target metadata (or best‑effort when missing).
    /// Relative paths are resolved as siblings; absolute paths are validated against the boundary.
    pub fn strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary().strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary().clone().into_strictpath() {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(self.path(), validated_link.path())?;
        }

        #[cfg(windows)]
        {
            create_windows_symlink(self.path(), validated_link.path())?;
        }

        Ok(())
    }

    /// SUMMARY:
    /// Read the target of a symbolic link and validate it is within the boundary.
    ///
    /// DESIGN NOTE:
    /// This method has limited practical use because `strict_join` resolves symlinks
    /// during canonicalization. A `StrictPath` obtained via `strict_join("link")` already
    /// points to the symlink's target, not the symlink itself.
    ///
    /// To read a symlink target before validation, use `std::fs::read_link` on the raw
    /// path, then validate the target with `strict_join`:
    ///
    /// EXAMPLE:
    /// ```rust
    /// use strict_path::PathBoundary;
    ///
    /// let temp = tempfile::tempdir()?;
    /// let data_dir: PathBoundary = PathBoundary::try_new(temp.path())?;
    ///
    /// // Create a target file
    /// let target = data_dir.strict_join("target.txt")?;
    /// target.write("secret")?;
    ///
    /// // Create symlink (may fail on Windows without Developer Mode)
    /// if target.strict_symlink("link.txt").is_ok() {
    ///     // WRONG: strict_join("link.txt") resolves to target.txt
    ///     let resolved = data_dir.strict_join("link.txt")?;
    ///     assert_eq!(resolved.strictpath_file_name(), Some("target.txt".as_ref()));
    ///
    ///     // RIGHT: read symlink target from raw path, then validate
    ///     let link_raw_path = temp.path().join("link.txt");
    ///     let symlink_target = std::fs::read_link(&link_raw_path)?;
    ///     let validated = data_dir.strict_join(&symlink_target)?;
    ///     assert_eq!(validated.strictpath_file_name(), Some("target.txt".as_ref()));
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn strict_read_link(&self) -> std::io::Result<Self> {
        // Read the raw symlink target
        let raw_target = std::fs::read_link(self.path())?;

        // If the target is relative, resolve it relative to the symlink's parent
        let resolved_target = if raw_target.is_relative() {
            match self.path().parent() {
                Some(parent) => parent.join(&raw_target),
                None => raw_target,
            }
        } else {
            raw_target
        };

        // Validate the resolved target against the boundary
        self.boundary()
            .strict_join(resolved_target)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    /// SUMMARY:
    /// Create a hard link at `link_path` pointing to this path (same boundary; caller creates parents).
    /// Relative paths are resolved as siblings; absolute paths are validated against the boundary.
    pub fn strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary().strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary().clone().into_strictpath() {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::hard_link(self.path(), validated_link.path())
    }

    /// SUMMARY:
    /// Create a Windows NTFS directory junction at `link_path` pointing to this path.
    ///
    /// DETAILS:
    /// - Windows-only and behind the `junctions` crate feature.
    /// - Junctions are directory-only. This call will fail if the target is not a directory.
    /// - Both `self` (target) and `link_path` must be within the same `PathBoundary`.
    /// - Parents for `link_path` are not created automatically; call `create_parent_dir_all()` first.
    ///
    /// RETURNS:
    /// - `io::Result<()>`: Mirrors OS semantics (and `junction` crate behavior).
    ///
    /// ERRORS:
    /// - Returns an error if the target is not a directory, or the OS call fails.
    #[cfg(all(windows, feature = "junctions"))]
    pub fn strict_junction<P: AsRef<Path>>(&self, link_path: P) -> std::io::Result<()> {
        let link_ref = link_path.as_ref();

        // Compute link path under the parent directory for relative paths; allow absolute too
        let validated_link = if link_ref.is_absolute() {
            match self.boundary().strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary().clone().into_strictpath() {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(link_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        // Validate target is a directory (junctions are directory-only)
        let meta = std::fs::metadata(self.path())?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "junction targets must be directories",
            ));
        }

        // The junction crate does not handle verbatim `\\?\` prefix paths correctly.
        // It creates broken junctions that return ERROR_INVALID_NAME (123) when accessed.
        // Strip the prefix before passing to the junction crate.
        // See: https://github.com/tesuji/junction/issues/30
        let target_path = super::strip_verbatim_prefix(self.path());
        let link_path = super::strip_verbatim_prefix(validated_link.path());

        junction::create(target_path.as_ref(), link_path.as_ref())
    }

    /// SUMMARY:
    /// Rename/move within the same boundary. Relative destinations are siblings; absolute are validated.
    /// Parents are not created automatically.
    pub fn strict_rename<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<()> {
        let dest_ref = dest.as_ref();

        // Compute destination under the parent directory for relative paths; allow absolute too
        let dest_path = if dest_ref.is_absolute() {
            match self.boundary().strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary().clone().into_strictpath() {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::rename(self.path(), dest_path.path())
    }

    /// SUMMARY:
    /// Copy within the same boundary. Relative destinations are siblings; absolute are validated.
    /// Parents are not created automatically. Returns bytes copied.
    pub fn strict_copy<P: AsRef<Path>>(&self, dest: P) -> std::io::Result<u64> {
        let dest_ref = dest.as_ref();

        // Compute destination under the parent directory for relative paths; allow absolute too
        let dest_path = if dest_ref.is_absolute() {
            match self.boundary().strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        } else {
            let parent = match self.strictpath_parent() {
                Ok(Some(p)) => p,
                Ok(None) => match self.boundary().clone().into_strictpath() {
                    Ok(root) => root,
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            };
            match parent.strict_join(dest_ref) {
                Ok(p) => p,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        };

        std::fs::copy(self.path(), dest_path.path())
    }
}
