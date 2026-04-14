//! `VirtualPathDisplay` — formats a `VirtualPath` as a rooted, forward-slash string.
//!
//! Returns the virtual (user-facing) view, not the real system path. The real path is
//! intentionally hidden to prevent leaking host filesystem structure in API responses,
//! error messages, or multi-tenant UIs. Use `strictpath_display()` when the real path
//! is needed (e.g., for system administrators or internal logging).
use super::VirtualPath;
use std::fmt;

pub struct VirtualPathDisplay<'vpath, Marker>(pub(super) &'vpath VirtualPath<Marker>);

impl<'vpath, Marker> fmt::Display for VirtualPathDisplay<'vpath, Marker> {
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
