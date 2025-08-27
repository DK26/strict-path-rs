// Content copied from original src/validator/jail.rs
use crate::error::JailedPathError;
use crate::path::jailed_path::JailedPath;
use crate::validator::stated_path::*;
use crate::Result;

#[cfg(windows)]
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(windows)]
fn is_potential_83_short_name(os: &OsStr) -> bool {
    let s = os.to_string_lossy();
    if let Some(pos) = s.find('~') {
        s[pos + 1..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
    } else {
        false
    }
}

pub(crate) fn validate<Marker>(
    path: impl AsRef<Path>,
    jail: &Jail<Marker>,
) -> Result<JailedPath<Marker>> {
    #[cfg(windows)]
    {
        let original_user_path = path.as_ref().to_path_buf();
        if !path.as_ref().is_absolute() {
            let mut probe = jail.path().to_path_buf();
            for comp in path.as_ref().components() {
                match comp {
                    Component::CurDir | Component::ParentDir => continue,
                    Component::RootDir | Component::Prefix(_) => continue,
                    Component::Normal(name) => {
                        if is_potential_83_short_name(name) {
                            return Err(JailedPathError::windows_short_name(
                                name.to_os_string(),
                                original_user_path,
                                probe.clone(),
                            ));
                        }
                        probe.push(name);
                    }
                }
            }
        }
    }

    let target_path = if path.as_ref().is_absolute() {
        path.as_ref().to_path_buf()
    } else {
        jail.path().join(path.as_ref())
    };

    let validated_path = StatedPath::<Raw>::new(target_path)
        .canonicalize()?
        .boundary_check(jail.path())?;

    Ok(JailedPath::new(
        Arc::new(Jail {
            path: jail.path.clone(),
            _marker: PhantomData,
        }),
        validated_path,
    ))
}

pub(crate) fn virtualize_to_jail<Marker>(path: impl AsRef<Path>, jail: &Jail<Marker>) -> PathBuf {
    use std::ffi::OsString;
    if path.as_ref().is_absolute() && path.as_ref().starts_with(jail.path()) {
        let mut has_parent_or_cur = false;
        for comp in path.as_ref().components() {
            if matches!(comp, Component::ParentDir | Component::CurDir) {
                has_parent_or_cur = true;
                break;
            }
        }
        if !has_parent_or_cur {
            return path.as_ref().to_path_buf();
        }
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0i32;
    let components = path.as_ref().components();
    let _is_abs_input = path.as_ref().is_absolute();
    #[cfg(unix)]
    let is_abs_input = _is_abs_input;
    for comp in components {
        match comp {
            Component::RootDir | Component::Prefix(_) => continue,
            Component::CurDir => continue,
            Component::ParentDir => {
                if depth > 0 {
                    normalized.pop();
                    depth -= 1;
                }
            }
            Component::Normal(name) => {
                let s = name.to_string_lossy();
                #[cfg(unix)]
                {
                    if is_abs_input && (s == "dev" || s == "proc" || s == "sys") {
                        let mut safe = OsString::from("__external__");
                        safe.push(s.as_ref());
                        normalized.push(safe);
                        depth += 1;
                        continue;
                    }
                }
                let cleaned = s.replace(['\n', ';'], "_");
                if cleaned != s {
                    normalized.push(OsString::from(cleaned));
                    depth += 1;
                    continue;
                }
                normalized.push(name);
                depth += 1;
            }
        }
    }
    jail.path().join(normalized)
}

/// A system-facing validator that holds the jail root and produces `JailedPath`.
#[derive(Debug, Clone)]
pub struct Jail<Marker = ()> {
    path: Arc<StatedPath<((Raw, Canonicalized), Exists)>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Jail<Marker> {
    /// Creates a new `Jail` rooted at `jail_path` (which must already exist and be a directory).
    #[inline]
    pub fn try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self> {
        let jail_path = jail_path.as_ref();
        let raw = StatedPath::<Raw>::new(jail_path);

        let canonicalized = raw.canonicalize()?;

        let verified_exists = match canonicalized.verify_exists() {
            Some(path) => path,
            None => {
                let io = IoError::new(
                    ErrorKind::NotFound,
                    "The specified jail path does not exist.",
                );
                return Err(JailedPathError::invalid_jail(jail_path.to_path_buf(), io));
            }
        };

        if !verified_exists.is_dir() {
            let error = IoError::new(
                ErrorKind::InvalidInput,
                "The specified jail path exists but is not a directory.",
            );
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            path: Arc::new(verified_exists),
            _marker: PhantomData,
        })
    }

    /// Creates the directory if missing, then constructs a new `Jail`.
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();
        if !root_path.exists() {
            std::fs::create_dir_all(root_path)
                .map_err(|e| JailedPathError::invalid_jail(root_path.to_path_buf(), e))?;
        }
        Self::try_new(root_path)
    }

    /// Validates a path against the jail boundary and returns a `JailedPath` on success.
    ///
    /// Accepts absolute or relative inputs; ensures the resulting path remains within the jail.
    #[inline]
    pub fn try_path(&self, candidate_path: impl AsRef<Path>) -> Result<JailedPath<Marker>> {
        validate(candidate_path, self)
    }

    /// Returns the canonicalized jail root path. Exposing this is safe — validation happens in `try_path`.
    #[inline]
    pub fn path(&self) -> &StatedPath<((Raw, Canonicalized), Exists)> {
        &self.path
    }
}

impl<Marker> AsRef<Path> for Jail<Marker> {
    #[inline]
    fn as_ref(&self) -> &Path {
        // StatedPath implements AsRef<Path>, so forward to it
        self.path.as_ref()
    }
}
