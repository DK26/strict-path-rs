// Content copied from original src/error/mod.rs
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const MAX_ERROR_PATH_LEN: usize = 256;

pub(crate) fn truncate_path_display(path: &Path, max_len: usize) -> String {
    let path_str = path.to_string_lossy();
    let char_count = path_str.chars().count();
    if char_count <= max_len {
        return path_str.into_owned();
    }
    let keep = max_len.saturating_sub(5) / 2;
    let start: String = path_str.chars().take(keep).collect();
    let mut tail_chars: Vec<char> = path_str.chars().rev().take(keep).collect();
    tail_chars.reverse();
    let end: String = tail_chars.into_iter().collect();
    format!("{start}...{end}")
}

/// Errors produced by jail creation and path validation.
#[derive(Debug)]
pub enum JailedPathError {
    /// The jail root is invalid (missing, not a directory, or IO error).
    InvalidJail {
        jail: PathBuf,
        source: std::io::Error,
    },
    /// The attempted path would resolve outside the jail boundary.
    PathEscapesBoundary {
        attempted_path: PathBuf,
        jail_boundary: PathBuf,
    },
    /// Canonicalization/resolution failed for the given path.
    PathResolutionError {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(windows)]
    /// A component resembles a Windows 8.3 short name (potential ambiguity).
    WindowsShortName {
        component: std::ffi::OsString,
        original: PathBuf,
        checked_at: PathBuf,
    },
}

impl JailedPathError {
    #[inline]
    pub(crate) fn invalid_jail(jail: PathBuf, source: std::io::Error) -> Self {
        Self::InvalidJail { jail, source }
    }
    #[inline]
    pub(crate) fn path_escapes_boundary(attempted_path: PathBuf, jail_boundary: PathBuf) -> Self {
        Self::PathEscapesBoundary {
            attempted_path,
            jail_boundary,
        }
    }
    #[inline]
    pub(crate) fn path_resolution_error(path: PathBuf, source: std::io::Error) -> Self {
        Self::PathResolutionError { path, source }
    }
    #[cfg(windows)]
    #[inline]
    pub(crate) fn windows_short_name(
        component: std::ffi::OsString,
        original: PathBuf,
        checked_at: PathBuf,
    ) -> Self {
        Self::WindowsShortName {
            component,
            original,
            checked_at,
        }
    }
}

impl fmt::Display for JailedPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JailedPathError::InvalidJail { jail, .. } => {
                write!(f, "Invalid jail directory: {}", jail.display())
            }
            JailedPathError::PathEscapesBoundary {
                attempted_path,
                jail_boundary,
            } => {
                let truncated_attempted = truncate_path_display(attempted_path, MAX_ERROR_PATH_LEN);
                let truncated_boundary = truncate_path_display(jail_boundary, MAX_ERROR_PATH_LEN);
                write!(
                    f,
                    "Path '{truncated_attempted}' escapes jail boundary '{truncated_boundary}'"
                )
            }
            JailedPathError::PathResolutionError { path, .. } => {
                write!(f, "Cannot resolve path: {}", path.display())
            }
            #[cfg(windows)]
            JailedPathError::WindowsShortName {
                component,
                original,
                checked_at,
            } => {
                let original_trunc = truncate_path_display(original, MAX_ERROR_PATH_LEN);
                let checked_trunc = truncate_path_display(checked_at, MAX_ERROR_PATH_LEN);
                write!(
                    f,
                    "Windows 8.3 short filename component '{}' rejected at '{}' for original '{}'",
                    component.to_string_lossy(),
                    checked_trunc,
                    original_trunc
                )
            }
        }
    }
}

impl Error for JailedPathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            JailedPathError::InvalidJail { source, .. }
            | JailedPathError::PathResolutionError { source, .. } => Some(source),
            JailedPathError::PathEscapesBoundary { .. } => None,
            #[cfg(windows)]
            JailedPathError::WindowsShortName { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
