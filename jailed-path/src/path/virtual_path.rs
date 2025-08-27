// Content copied from original src/path/virtual_path.rs
use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
use crate::validator;
use crate::Result;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct VirtualPath<Marker = ()> {
    inner: JailedPath<Marker>,
    virtual_path: PathBuf,
}

impl<Marker> VirtualPath<Marker> {
    #[inline]
    pub(crate) fn new(jailed_path: JailedPath<Marker>) -> Self {
        fn compute_virtual<Marker>(
            real: &std::path::Path,
            jail: &validator::jail::Jail<Marker>,
        ) -> std::path::PathBuf {
            use std::ffi::OsString;
            use std::path::Component;

            #[cfg(windows)]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                let s = p.as_os_str().to_string_lossy();
                if let Some(trimmed) = s.strip_prefix("\\\\?\\") {
                    return std::path::PathBuf::from(trimmed);
                }
                if let Some(trimmed) = s.strip_prefix("\\\\.\\") {
                    return std::path::PathBuf::from(trimmed);
                }
                std::path::PathBuf::from(s.to_string())
            }

            #[cfg(not(windows))]
            fn strip_verbatim(p: &std::path::Path) -> std::path::PathBuf {
                p.to_path_buf()
            }

            let real_norm = strip_verbatim(real);
            let jail_norm = strip_verbatim(jail.path());

            if let Ok(stripped) = real_norm.strip_prefix(&jail_norm) {
                let mut cleaned = std::path::PathBuf::new();
                for comp in stripped.components() {
                    if let Component::Normal(name) = comp {
                        let s = name.to_string_lossy();
                        let cleaned_s = s.replace(['\n', ';'], "_");
                        if cleaned_s == s {
                            cleaned.push(name);
                        } else {
                            cleaned.push(OsString::from(cleaned_s));
                        }
                    }
                }
                return cleaned;
            }

            let mut real_comps: Vec<_> = real_norm
                .components()
                .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect();
            let mut jail_comps: Vec<_> = jail_norm
                .components()
                .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect();

            #[cfg(windows)]
            fn comp_eq(a: &Component, b: &Component) -> bool {
                match (a, b) {
                    (Component::Normal(x), Component::Normal(y)) => {
                        x.to_string_lossy().to_ascii_lowercase()
                            == y.to_string_lossy().to_ascii_lowercase()
                    }
                    _ => false,
                }
            }

            #[cfg(not(windows))]
            fn comp_eq(a: &Component, b: &Component) -> bool {
                a == b
            }

            while !real_comps.is_empty()
                && !jail_comps.is_empty()
                && comp_eq(&real_comps[0], &jail_comps[0])
            {
                real_comps.remove(0);
                jail_comps.remove(0);
            }

            let mut vb = std::path::PathBuf::new();
            for c in real_comps {
                if let Component::Normal(name) = c {
                    let s = name.to_string_lossy();
                    let cleaned = s.replace(['\n', ';'], "_");
                    if cleaned == s {
                        vb.push(name);
                    } else {
                        vb.push(OsString::from(cleaned));
                    }
                }
            }
            vb
        }

        let virtual_path = compute_virtual(jailed_path.path(), jailed_path.jail());

        Self {
            inner: jailed_path,
            virtual_path,
        }
    }

    #[inline]
    pub fn unvirtual(self) -> JailedPath<Marker> {
        self.inner
    }

    pub fn jail(&self) -> &crate::validator::jail::Jail<Marker> {
        self.inner.jail()
    }

    pub fn virtualpath_to_string(&self) -> String {
        format!("{}", self.display())
    }

    #[inline]
    pub fn virtualpath_to_str(&self) -> Option<&str> {
        self.virtual_path.to_str()
    }

    #[inline]
    pub fn virtualpath_as_os_str(&self) -> &OsStr {
        self.virtual_path.as_os_str()
    }

    #[inline]
    pub fn realpath_to_string(&self) -> String {
        self.inner.realpath_to_string()
    }

    #[inline]
    pub fn realpath_to_str(&self) -> Option<&str> {
        self.inner.realpath_to_str()
    }

    #[inline]
    pub fn realpath_as_os_str(&self) -> &OsStr {
        self.inner.realpath_as_os_str()
    }

    #[inline]
    pub fn join_virtual<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let new_virtual = self.virtual_path.join(path);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    pub fn parent_virtual(&self) -> Result<Option<Self>> {
        match self.virtual_path.parent() {
            Some(p) => {
                let virtualized = validator::virtualize_to_jail(p, self.inner.jail());
                match validator::validate(virtualized, self.inner.jail()) {
                    Ok(p) => Ok(Some(p.virtualize())),
                    Err(e) => Err(e),
                }
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub fn with_file_name_virtual<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self> {
        let new_virtual = self.virtual_path.with_file_name(file_name);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    pub fn with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self> {
        if self.virtual_path.file_name().is_none() {
            return Err(JailedPathError::path_escapes_boundary(
                self.virtual_path.clone(),
                self.inner.jail().path().to_path_buf(),
            ));
        }
        let new_virtual = self.virtual_path.with_extension(extension);
        let virtualized = validator::virtualize_to_jail(new_virtual, self.inner.jail());
        validator::validate(virtualized, self.inner.jail()).map(|p| p.virtualize())
    }

    #[inline]
    pub fn file_name_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.file_name()
    }

    #[inline]
    pub fn file_stem_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.file_stem()
    }

    #[inline]
    pub fn extension_virtual(&self) -> Option<&OsStr> {
        self.virtual_path.extension()
    }

    #[inline]
    pub fn starts_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.starts_with(p)
    }

    #[inline]
    pub fn ends_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool {
        self.virtual_path.ends_with(p)
    }

    #[inline]
    pub fn display(&self) -> VirtualPathDisplay<'_, Marker> {
        VirtualPathDisplay(self)
    }

    #[inline]
    pub fn exists(&self) -> bool {
        self.inner.exists()
    }

    #[inline]
    pub fn is_file(&self) -> bool {
        self.inner.is_file()
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        self.inner.is_dir()
    }

    #[inline]
    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata()
    }

    #[inline]
    pub fn read_to_string(&self) -> std::io::Result<String> {
        self.inner.read_to_string()
    }

    #[inline]
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        self.inner.read_bytes()
    }

    #[inline]
    pub fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(data)
    }

    #[inline]
    pub fn write_string(&self, data: &str) -> std::io::Result<()> {
        self.inner.write_string(data)
    }

    #[inline]
    pub fn create_dir_all(&self) -> std::io::Result<()> {
        self.inner.create_dir_all()
    }

    #[inline]
    pub fn remove_file(&self) -> std::io::Result<()> {
        self.inner.remove_file()
    }

    #[inline]
    pub fn remove_dir(&self) -> std::io::Result<()> {
        self.inner.remove_dir()
    }

    #[inline]
    pub fn remove_dir_all(&self) -> std::io::Result<()> {
        self.inner.remove_dir_all()
    }
}

pub struct VirtualPathDisplay<'a, Marker>(&'a VirtualPath<Marker>);

impl<'a, Marker> fmt::Display for VirtualPathDisplay<'a, Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ensure leading slash and normalize to forward slashes for display
        let s_lossy = self.0.virtual_path.to_string_lossy();
        let s_norm: std::borrow::Cow<'_, str> = {
            #[cfg(windows)]
            {
                std::borrow::Cow::Owned(s_lossy.replace('\\', "/"))
            }
            #[cfg(not(windows))]
            {
                std::borrow::Cow::Borrowed(&s_lossy)
            }
        };
        if s_norm.starts_with('/') {
            write!(f, "{s_norm}")
        } else {
            write!(f, "/{s_norm}")
        }
    }
}

// Implement Display for VirtualPath by delegating to its Display helper.
impl<Marker> fmt::Display for VirtualPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display().fmt(f)
    }
}

impl<Marker> PartialEq for VirtualPath<Marker> {
    fn eq(&self, other: &Self) -> bool {
        self.virtual_path == other.virtual_path
    }
}

impl<Marker> Eq for VirtualPath<Marker> {}

impl<Marker> Hash for VirtualPath<Marker> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.virtual_path.hash(state);
    }
}
