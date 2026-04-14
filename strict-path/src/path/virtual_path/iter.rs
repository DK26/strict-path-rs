//! `VirtualReadDir` iterator for `VirtualPath`.
//!
//! Wraps `std::fs::ReadDir` and re-validates each directory entry through `virtual_join`,
//! so callers get `VirtualPath` values directly. This prevents a listing from exposing
//! raw `DirEntry` paths that would require the caller to re-validate manually.
use super::VirtualPath;

// ============================================================
// VirtualReadDir — Iterator for validated virtual directory entries
// ============================================================

/// Iterator over directory entries that yields validated `VirtualPath` values.
///
/// Created by `VirtualPath::virtual_read_dir()`. Each iteration automatically validates
/// the directory entry through `virtual_join()`, so you get `VirtualPath` values directly
/// instead of raw `std::fs::DirEntry` that would require manual re-validation.
///
/// # Examples
/// ```rust
/// # use strict_path::{VirtualRoot, VirtualPath};
/// # let temp = tempfile::tempdir()?;
/// # let vroot: VirtualRoot = VirtualRoot::try_new(temp.path())?;
/// # let dir = vroot.virtual_join("assets")?;
/// # dir.create_dir_all()?;
/// # vroot.virtual_join("assets/logo.png")?.write(b"PNG")?;
/// for entry in dir.virtual_read_dir()? {
///     let child: VirtualPath = entry?;
///     if child.is_file() {
///         println!("File: {}", child.virtualpath_display());
///     }
/// }
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub struct VirtualReadDir<'vpath, Marker> {
    pub(super) inner: std::fs::ReadDir,
    pub(super) parent: &'vpath VirtualPath<Marker>,
}

impl<Marker> std::fmt::Debug for VirtualReadDir<'_, Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualReadDir")
            .field("parent", &self.parent.virtualpath_display().to_string())
            .finish_non_exhaustive()
    }
}

impl<Marker: Clone> Iterator for VirtualReadDir<'_, Marker> {
    type Item = std::io::Result<VirtualPath<Marker>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(entry) => {
                let file_name = entry.file_name();
                match self.parent.virtual_join(file_name) {
                    Ok(virtual_path) => Some(Ok(virtual_path)),
                    Err(e) => Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))),
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}
