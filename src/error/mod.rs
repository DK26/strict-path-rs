use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

/// Maximum length for paths stored in error messages to prevent memory attacks
const MAX_ERROR_PATH_LEN: usize = 256;

/// Truncates a path display to prevent memory exhaustion attacks
/// while preserving readability by showing both start and end of the path
pub(crate) fn truncate_path_display(path: &Path, max_len: usize) -> String {
    let path_str = path.to_string_lossy();

    // Use character-aware truncation to avoid slicing at invalid UTF-8 boundaries.
    let char_count = path_str.chars().count();
    if char_count <= max_len {
        return path_str.into_owned();
    }

    // Keep beginning and end, indicate truncation. Reserve 5 chars for "..."
    let keep = max_len.saturating_sub(5) / 2;

    // Collect the first `keep` chars
    let start: String = path_str.chars().take(keep).collect();

    // Collect the last `keep` chars by iterating in reverse and then reversing back
    let mut tail_chars: Vec<char> = path_str.chars().rev().take(keep).collect();
    tail_chars.reverse();
    let end: String = tail_chars.into_iter().collect();

    format!("{start}...{end}")
}

/// Errors that can occur during jailed path operations.
#[derive(Debug)]
pub enum JailedPathError {
    /// The jail directory is invalid or inaccessible.
    InvalidJail {
        /// The jail path that caused the error.
        jail: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The path escapes the jail boundary.
    PathEscapesBoundary {
        /// The resolved path that attempted to escape.
        attempted_path: PathBuf,
        /// The jail boundary it tried to escape from.
        jail_boundary: PathBuf,
    },

    /// An I/O error occurred during path resolution.
    PathResolutionError {
        /// The path being resolved when the error occurred.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Windows-only: A DOS 8.3 short filename component (e.g., "PROGRA~1") was detected
    /// in a non-existent path segment inside the jail. Returning this specialized error
    /// allows callers to choose a recovery strategy (e.g., reject, prompt for full name,
    /// or map to a known safe long name).
    #[cfg(windows)]
    WindowsShortName {
        /// The short-name component that triggered the rejection (e.g., "PROGRA~1").
        component: std::ffi::OsString,
        /// The original user-provided path.
        original: PathBuf,
        /// The directory inside the jail where existence was checked.
        checked_at: PathBuf,
    },
}

impl JailedPathError {
    /// Creates a new `InvalidJail` error.
    #[inline]
    pub(crate) fn invalid_jail(jail: PathBuf, source: std::io::Error) -> Self {
        Self::InvalidJail { jail, source }
    }

    /// Creates a new `PathEscapesBoundary` error.
    #[inline]
    pub(crate) fn path_escapes_boundary(attempted_path: PathBuf, jail_boundary: PathBuf) -> Self {
        Self::PathEscapesBoundary {
            attempted_path,
            jail_boundary,
        }
    }

    /// Creates a new `PathResolutionError` from an I/O error.
    #[inline]
    pub(crate) fn path_resolution_error(path: PathBuf, source: std::io::Error) -> Self {
        Self::PathResolutionError { path, source }
    }

    /// Creates a new `WindowsShortName` error (Windows only).
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
                // Truncate only when displaying to prevent memory attacks
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
                    original_trunc,
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
