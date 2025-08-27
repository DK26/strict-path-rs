// Content copied from original src/validator/stated_path.rs
use crate::{JailedPathError, Result};
use soft_canonicalize::soft_canonicalize;
use std::ops::Deref;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Raw;
#[derive(Debug, Clone)]
pub struct Canonicalized;
#[derive(Debug, Clone)]
pub struct BoundaryChecked;
#[derive(Debug, Clone)]
pub struct Exists;

#[derive(Debug, Clone)]
pub struct StatedPath<State> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<State>,
}

impl<S> AsRef<Path> for StatedPath<S> {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

impl<S> Deref for StatedPath<S> {
    type Target = Path;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl StatedPath<Raw> {
    #[inline]
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Self {
        StatedPath {
            inner: path.as_ref().to_path_buf(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> StatedPath<S> {
    #[inline]
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }

    pub fn canonicalize(self) -> Result<StatedPath<(S, Canonicalized)>> {
        let canon = soft_canonicalize(&self.inner)
            .map_err(|e| JailedPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(StatedPath {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn verify_exists(self) -> Option<StatedPath<(S, Exists)>> {
        self.inner.exists().then_some(StatedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<S> StatedPath<(S, Canonicalized)> {
    #[inline]
    pub fn boundary_check(
        self,
        jail: &StatedPath<((Raw, Canonicalized), Exists)>,
    ) -> Result<StatedPath<((S, Canonicalized), BoundaryChecked)>> {
        if !self.starts_with(jail) {
            return Err(JailedPathError::path_escapes_boundary(
                self.into_inner(),
                jail.to_path_buf(),
            ));
        }
        Ok(StatedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}
