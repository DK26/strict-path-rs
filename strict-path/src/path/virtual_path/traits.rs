use super::VirtualPath;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::Path;

impl<Marker> fmt::Debug for VirtualPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualPath")
            .field("system_path", &self.inner.path())
            .field("virtual", &self.virtualpath_display().to_string())
            .field("boundary", &self.inner.boundary().path())
            .field("marker", &std::any::type_name::<Marker>())
            .finish()
    }
}

impl<Marker> PartialEq for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.path() == other.inner.path()
    }
}

impl<Marker> Eq for VirtualPath<Marker> {}

impl<Marker> Hash for VirtualPath<Marker> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.path().hash(state);
    }
}

impl<Marker> PartialEq<crate::path::strict_path::StrictPath<Marker>> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &crate::path::strict_path::StrictPath<Marker>) -> bool {
        self.inner.path() == other.path()
    }
}

impl<T: AsRef<Path>, Marker> PartialEq<T> for VirtualPath<Marker> {
    #[inline]
    fn eq(&self, other: &T) -> bool {
        // Compare virtual paths - the user-facing representation
        // If you want system path comparison, use as_unvirtual()
        let virtual_str = self.virtualpath_display().to_string();
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_str();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{other_normalized}")
        };

        normalized_virtual == normalized_other
    }
}

impl<T: AsRef<Path>, Marker> PartialOrd<T> for VirtualPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &T) -> Option<std::cmp::Ordering> {
        // Compare virtual paths - the user-facing representation
        let virtual_str = self.virtualpath_display().to_string();
        let other_str = other.as_ref().to_string_lossy();

        // Normalize both to forward slashes and ensure leading slash
        let normalized_virtual = virtual_str.as_str();

        #[cfg(windows)]
        let other_normalized = other_str.replace('\\', "/");
        #[cfg(not(windows))]
        let other_normalized = other_str.to_string();

        let normalized_other = if other_normalized.starts_with('/') {
            other_normalized
        } else {
            format!("/{other_normalized}")
        };

        Some(normalized_virtual.cmp(&normalized_other))
    }
}

impl<Marker> PartialOrd for VirtualPath<Marker> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Marker> Ord for VirtualPath<Marker> {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.path().cmp(other.inner.path())
    }
}
