use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PathValidator {
    jail: PathBuf,
}

impl PathValidator {
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail = jail.as_ref();
        let canonical_jail = jail
            .canonicalize()
            .map_err(|e| JailedPathError::from_io_error(jail.to_string_lossy().as_ref(), e))?;

        if !canonical_jail.is_dir() {
            return Err(JailedPathError::invalid_jail(
                jail.to_string_lossy().as_ref(),
                "path is not a directory",
            ));
        }

        Ok(Self {
            jail: canonical_jail,
        })
    }

    pub fn path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath> {
        let candidate = candidate_path.as_ref();

        let resolved_path = if candidate.is_absolute() {
            candidate.canonicalize().map_err(|e| {
                JailedPathError::from_io_error(candidate.to_string_lossy().as_ref(), e)
            })?
        } else {
            let full_path = self.jail.join(candidate);
            full_path.canonicalize().map_err(|e| {
                JailedPathError::from_io_error(candidate.to_string_lossy().as_ref(), e)
            })?
        };

        if !resolved_path.starts_with(&self.jail) {
            return Err(JailedPathError::path_escapes_boundary(
                candidate.to_string_lossy().as_ref(),
                self.jail.to_string_lossy().as_ref(),
            ));
        }

        Ok(JailedPath::new(resolved_path))
    }

    pub fn jail(&self) -> &Path {
        &self.jail
    }
}
