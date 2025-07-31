use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

/// Maximum length for paths stored in error messages to prevent memory attacks
const MAX_ERROR_PATH_LEN: usize = 256;

/// Truncates a path display to prevent memory exhaustion attacks
/// while preserving readability by showing both start and end of the path
pub(crate) fn truncate_path_display(path: &Path, max_len: usize) -> String {
    let path_str = path.to_string_lossy();
    if path_str.len() <= max_len {
        path_str.into_owned()
    } else {
        // Keep beginning and end, indicate truncation
        let keep_len = max_len.saturating_sub(5) / 2; // Reserve 5 chars for "..."
        format!(
            "{}...{}",
            &path_str[..keep_len],
            &path_str[path_str.len().saturating_sub(keep_len)..]
        )
    }
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
}

impl JailedPathError {
    /// Creates a new `InvalidJail` error.
    pub fn invalid_jail(jail: PathBuf, source: std::io::Error) -> Self {
        Self::InvalidJail { jail, source }
    }

    /// Creates a new `PathEscapesBoundary` error.
    pub fn path_escapes_boundary(attempted_path: PathBuf, jail_boundary: PathBuf) -> Self {
        Self::PathEscapesBoundary {
            attempted_path,
            jail_boundary,
        }
    }

    /// Creates a new `PathResolutionError` from an I/O error.
    pub fn path_resolution_error(path: PathBuf, source: std::io::Error) -> Self {
        Self::PathResolutionError { path, source }
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
        }
    }
}

impl Error for JailedPathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            JailedPathError::InvalidJail { source, .. }
            | JailedPathError::PathResolutionError { source, .. } => Some(source),
            JailedPathError::PathEscapesBoundary { .. } => None,
        }
    }
}
