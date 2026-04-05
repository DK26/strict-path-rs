use super::VirtualPath;
use std::fmt;

pub struct VirtualPathDisplay<'a, Marker>(pub(super) &'a VirtualPath<Marker>);

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
