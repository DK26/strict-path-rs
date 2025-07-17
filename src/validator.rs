use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PathValidator<Marker = ()> {
    jail: PathBuf,
    _marker: PhantomData<Marker>,
}

impl<Marker> PathValidator<Marker> {
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail_path = jail.as_ref();
        let canonical_jail = jail_path
            .canonicalize()
            .map_err(|e| JailedPathError::path_resolution_error(jail_path.to_path_buf(), e))?;

        if !canonical_jail.is_dir() {
            let error =
                std::io::Error::new(std::io::ErrorKind::NotFound, "path is not a directory");
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: canonical_jail,
            _marker: PhantomData,
        })
    }

    /// Validate a path and return detailed error information on failure
    /// Use this when you need to know WHY a path was rejected (logging, debugging, security monitoring)
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        let candidate = candidate_path.as_ref();

        let resolved_path = if candidate.is_absolute() {
            candidate
                .canonicalize()
                .map_err(|e| JailedPathError::path_resolution_error(candidate.to_path_buf(), e))?
        } else {
            let full_path = self.jail.join(candidate);
            full_path
                .canonicalize()
                .map_err(|e| JailedPathError::path_resolution_error(candidate.to_path_buf(), e))?
        };

        if !resolved_path.starts_with(&self.jail) {
            return Err(JailedPathError::path_escapes_boundary(
                resolved_path,
                self.jail.clone(),
            ));
        }

        Ok(JailedPath::new(resolved_path))
    }

    pub fn jail(&self) -> &Path {
        &self.jail
    }
}
