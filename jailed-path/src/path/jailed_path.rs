// Content copied from original src/path/jailed_path.rs
use crate::validator::stated_path::{BoundaryChecked, Canonicalized, Raw, StatedPath};
use crate::{JailedPathError, Result};
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,
    jail: Arc<crate::validator::jail::Jail<Marker>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> JailedPath<Marker> {
    pub(crate) fn new(
        jail: Arc<crate::validator::jail::Jail<Marker>>,
        validated_path: StatedPath<((Raw, Canonicalized), BoundaryChecked)>,
    ) -> Self {
        Self {
            path: validated_path.into_inner(),
            jail,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub(crate) fn jail(&self) -> &crate::validator::jail::Jail<Marker> {
        self.jail.as_ref()
    }

    #[inline]
    pub fn realpath_to_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    #[inline]
    pub fn realpath_to_str(&self) -> Option<&str> {
        self.path.to_str()
    }

    #[inline]
    pub fn realpath_as_os_str(&self) -> &OsStr {
        self.path.as_os_str()
    }

    #[inline]
    pub fn display(&self) -> std::path::Display<'_> {
        self.path.display()
    }

    #[inline]
    pub fn unjail(self) -> PathBuf {
        self.path
    }

    #[inline]
    pub fn virtualize(self) -> crate::path::virtual_path::VirtualPath<Marker> {
        crate::path::virtual_path::VirtualPath::new(self)
    }

    #[inline]
    pub fn join_real<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_real = self.path.join(path);
        crate::validator::validate(new_real, self.jail())
    }

    pub fn parent_real(&self) -> Result<Option<Self>> {
        match self.path.parent() {
            Some(p) => match crate::validator::validate(p, self.jail()) {
                Ok(p) => Ok(Some(p)),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    #[inline]
    pub fn with_file_name_real<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_real = self.path.with_file_name(file_name);
        crate::validator::validate(new_real, self.jail())
    }

    pub fn with_extension_real<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        let rpath = self.path.as_path();
        if rpath.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.path.clone(),
                self.jail().path().to_path_buf(),
            ));
        }
        let new_real = rpath.with_extension(extension);
        crate::validator::validate(new_real, self.jail())
    }

    #[inline]
    pub fn file_name_real(&self) -> Option<&OsStr> {
        self.path.file_name()
    }

    #[inline]
    pub fn file_stem_real(&self) -> Option<&OsStr> {
        self.path.file_stem()
    }

    #[inline]
    pub fn extension_real(&self) -> Option<&OsStr> {
        self.path.extension()
    }

    #[inline]
    pub fn starts_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.starts_with(p.as_ref())
    }

    #[inline]
    pub fn ends_with_real<P: AsRef<Path>>(&self, p: P) -> bool {
        self.path.ends_with(p.as_ref())
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
    }

    pub fn read_to_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }

    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    pub fn create_dir_all(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.path)
    }

    pub fn remove_file(&self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)
    }

    pub fn remove_dir(&self) -> std::io::Result<()> {
        std::fs::remove_dir(&self.path)
    }

    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        std::fs::remove_dir_all(&self.path)
    }
}

impl<Marker> fmt::Display for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JailedPath")
            .field("path", &self.path)
            .field("jail", &self.jail().path())
            .finish()
    }
}

impl<Marker> PartialEq for JailedPath<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl<Marker> Eq for JailedPath<Marker> {}

impl<Marker> Hash for JailedPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl<Marker> PartialOrd for JailedPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for JailedPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.path.cmp(&other.path)
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for JailedPath<Marker> {
    fn eq(&self, other: &T) -> bool {
        self.path == other.as_ref()
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for JailedPath<Marker> {
    fn partial_cmp(&self, other: &T) -> Option<Ordering> {
        Some(self.path.as_path().cmp(other.as_ref()))
    }
}
