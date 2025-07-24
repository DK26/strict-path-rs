use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A validated path that is guaranteed to be within a defined jail boundary.
///
/// ## Virtual Root Display
///
/// When you print a `JailedPath` (using the `Display` trait), it shows the path as if it starts from the root of your jail.
/// This keeps user-facing output clean and intuitive, never leaking internal or absolute paths.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail_root: Arc<PathBuf>,
    _marker: PhantomData<Marker>,
}

impl<Marker> JailedPath<Marker> {
    /// Creates a new JailedPath (internal use only).
    pub(crate) fn new(path: PathBuf, jail_root: Arc<PathBuf>) -> Self {
        Self {
            path,
            jail_root,
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

    /// Returns a reference to the jail root path.
    pub fn jail_root(&self) -> &Path {
        &self.jail_root
    }
}

impl<Marker> AsRef<Path> for JailedPath<Marker> {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl<Marker> Deref for JailedPath<Marker> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl<Marker> fmt::Display for JailedPath<Marker> {
    /// Shows the path as if from the jail root, for clean user-facing output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::path::MAIN_SEPARATOR;
        if let Ok(relative) = self.path.strip_prefix(&*self.jail_root) {
            // Join components with platform separator
            let components = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy());
            let mut display_path = String::from(MAIN_SEPARATOR);
            display_path.push_str(
                &components
                    .collect::<Vec<_>>()
                    .join(std::path::MAIN_SEPARATOR_STR),
            );
            write!(f, "{display_path}")
        } else {
            write!(f, "{}", self.path.display())
        }
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::path::MAIN_SEPARATOR;
        // Format path and jail_root using platform separator for consistency
        let format_path = |p: &PathBuf| {
            let mut s = String::new();
            for (i, c) in p.components().enumerate() {
                if i > 0 {
                    s.push(MAIN_SEPARATOR);
                }
                s.push_str(&c.as_os_str().to_string_lossy());
            }
            s
        };
        f.debug_struct("JailedPath")
            .field("path", &format_path(&self.path))
            .field("jail_root", &format_path(&self.jail_root))
            .finish()
    }
}
