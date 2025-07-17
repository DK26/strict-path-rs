use std::path::{Path, PathBuf};
use std::marker::PhantomData;

/// A validated path that is guaranteed to be within a defined jail boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    _marker: PhantomData<Marker>,
}

impl<Marker> JailedPath<Marker> {
    /// Creates a new JailedPath (internal use only).
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { 
            path,
            _marker: PhantomData,
        }
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

impl<Marker> AsRef<Path> for JailedPath<Marker> {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl<Marker> std::ops::Deref for JailedPath<Marker> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}
