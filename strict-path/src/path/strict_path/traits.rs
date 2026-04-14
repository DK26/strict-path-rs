//! Standard trait impls for `StrictPath`: `Display`, `Debug`, `PartialEq`, `Eq`, `PartialOrd`,
//! `Ord`, `Hash`.
//!
//! Equality and ordering are based solely on the underlying system path, not the marker type.
//! This lets paths with different markers be compared when the application needs to deduplicate
//! or sort — while the type system still prevents mixing them in security-sensitive operations.
use super::StrictPath;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::Path;

impl<Marker> fmt::Debug for StrictPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictPath")
            .field("path", &self.path())
            .field("boundary", &self.boundary_path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

impl<Marker> PartialEq for StrictPath<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.path() == other.path()
    }
}

impl<Marker> Eq for StrictPath<Marker> {}

impl<Marker> Hash for StrictPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path().hash(state);
    }
}

impl<Marker> PartialOrd for StrictPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for StrictPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.path().cmp(other.path())
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for StrictPath<Marker> {
    fn eq(&self, other: &T) -> bool {
        self.path() == other.as_ref()
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for StrictPath<Marker> {
    fn partial_cmp(&self, other: &T) -> Option<Ordering> {
        Some(self.path().cmp(other.as_ref()))
    }
}

#[cfg(feature = "virtual-path")]
impl<Marker> PartialEq<crate::path::virtual_path::VirtualPath<Marker>> for StrictPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::virtual_path::VirtualPath<Marker>) -> bool {
        self.path() == other.as_unvirtual().path()
    }
}
