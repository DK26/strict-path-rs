// Content copied from original src/validator/stated_path.rs
use crate::{Result, StrictPathError};
use soft_canonicalize::{anchored_canonicalize, soft_canonicalize};
use std::ops::Deref;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Raw;
#[derive(Debug, Clone)]
pub struct Canonicalized;
#[derive(Debug, Clone)]
pub struct BoundaryChecked;
#[derive(Debug, Clone)]
pub struct Exists;
#[derive(Debug, Clone)]
pub struct Virtualized;

#[derive(Debug, Clone)]
pub struct PathHistory<History> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<History>,
}

impl<H> AsRef<Path> for PathHistory<H> {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

impl<H> Deref for PathHistory<H> {
    type Target = Path;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl PathHistory<Raw> {
    #[inline]
    pub fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        PathHistory {
            inner: path.into(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<H> PathHistory<H> {
    #[inline]
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }

    /// Virtualizes this path by preparing a path boundary-anchored system path for validation.
    ///
    /// Semantics:
    /// - Clamps traversal (.., .) in virtual space so results never walk above the virtual root.
    /// - Absolute inputs are treated as requests relative to the virtual root (drop only the root/prefix).
    /// - Does not resolve symlinks; that is handled by canonicalization in `PathBoundary::restricted_join`.
    /// - Returns a path under the path boundary as root to be canonicalized and boundary-checked.
    pub fn virtualize_to_restriction<Marker>(
        self,
        restriction: &crate::PathBoundary<Marker>,
    ) -> PathHistory<(H, Virtualized)> {
        // Build a clamped relative path by processing components and preventing
        // traversal above the virtual root.
        use std::path::Component;
        let mut parts: Vec<std::ffi::OsString> = Vec::new();
        for comp in self.inner.components() {
            match comp {
                Component::Normal(name) => parts.push(name.to_os_string()),
                Component::CurDir => {}
                Component::ParentDir => {
                    if parts.pop().is_none() {
                        // At virtual root; ignore extra ".."
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    // Treat as virtual root reset; clear accumulated parts
                    parts.clear();
                }
            }
        }
        let mut rel = PathBuf::new();
        for p in parts {
            rel.push(p);
        }

        PathHistory {
            inner: restriction.path().join(rel),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn canonicalize(self) -> Result<PathHistory<(H, Canonicalized)>> {
        let canon = soft_canonicalize(&self.inner)
            .map_err(|e| StrictPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(PathHistory {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }

    /// Canonicalize relative to a path boundary root using anchored semantics (virtual clamp + resolution).
    /// Returns a Canonicalized state; boundary checking is still required.
    pub fn canonicalize_anchored<Marker>(
        self,
        anchor: &crate::PathBoundary<Marker>,
    ) -> Result<PathHistory<(H, Canonicalized)>> {
        let canon = anchored_canonicalize(anchor.path(), &self.inner)
            .map_err(|e| StrictPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(PathHistory {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn verify_exists(self) -> Option<PathHistory<(H, Exists)>> {
        self.inner.exists().then_some(PathHistory {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<H> PathHistory<(H, Canonicalized)> {
    #[inline]
    pub fn boundary_check(
        self,
        restriction: &PathHistory<((Raw, Canonicalized), Exists)>,
    ) -> Result<PathHistory<((H, Canonicalized), BoundaryChecked)>> {
        if !self.starts_with(restriction) {
            return Err(StrictPathError::path_escapes_boundary(
                self.into_inner(),
                restriction.to_path_buf(),
            ));
        }
        Ok(PathHistory {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}

// No separate anchored type-state after canonicalization; use Canonicalized
