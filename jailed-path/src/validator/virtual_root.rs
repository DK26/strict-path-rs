// Content copied from original src/validator/virtual_root.rs
use crate::path::virtual_path::VirtualPath;
use crate::validator::{self, jail::Jail};
use crate::Result;
use std::marker::PhantomData;
use std::path::Path;

/// A user-facing virtual root that produces `VirtualPath` values.
#[derive(Debug, Clone)]
pub struct VirtualRoot<Marker = ()> {
    jail: Jail<Marker>,
    _marker: PhantomData<Marker>,
}

impl<Marker> VirtualRoot<Marker> {
    /// Creates a `VirtualRoot` from an existing directory.
    #[inline]
    pub fn try_new<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new(root_path)?;
        Ok(Self {
            jail,
            _marker: PhantomData,
        })
    }

    /// Creates the directory if missing, then returns a `VirtualRoot`.
    #[inline]
    pub fn try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self> {
        let jail = Jail::try_new_create(root_path)?;
        Ok(Self {
            jail,
            _marker: PhantomData,
        })
    }

    /// Produces a clamped `VirtualPath` from user input; always preserves the virtual root.
    #[inline]
    pub fn try_path_virtual<P: AsRef<Path>>(
        &self,
        candidate_path: P,
    ) -> Result<VirtualPath<Marker>> {
        let virtualized = validator::virtualize_to_jail(candidate_path, &self.jail);
        let jailed_path = self.jail.try_path(virtualized)?;
        Ok(jailed_path.virtualize())
    }

    /// Returns the underlying jail root as a system path.
    #[inline]
    pub fn path(&self) -> &Path {
        self.jail.path()
    }
}

impl<Marker> std::fmt::Display for VirtualRoot<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path().display())
    }
}

impl<Marker> AsRef<Path> for VirtualRoot<Marker> {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}
