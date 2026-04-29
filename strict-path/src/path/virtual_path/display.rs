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
        // Sanitize each Normal component at display time so that virtual_path
        // stores raw OS names (preserving correct navigation via virtual_join).
        use std::path::Component;
        let mut parts: Vec<String> = Vec::new();
        for comp in self.0.virtual_path.components() {
            if let Component::Normal(name) = comp {
                let s = name.to_string_lossy();
                parts.push(crate::sanitize::sanitize_untrusted_display_text(&s));
            }
        }
        if parts.is_empty() {
            write!(f, "/")
        } else {
            write!(f, "/{}", parts.join("/"))
        }
    }
}
