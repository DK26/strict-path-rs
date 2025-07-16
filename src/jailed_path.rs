use std::path::{Path, PathBuf};

/// A validated path that is guaranteed to be within a defined jail boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JailedPath {
    path: PathBuf,
}

impl JailedPath {
    /// Creates a new JailedPath (internal use only).
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the path as &Path.
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// Consumes and returns the inner PathBuf.
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}

impl AsRef<Path> for JailedPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for JailedPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}
