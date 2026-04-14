//! Define error types and helpers for boundary creation and strict/virtual path validation.
//!
//! Exposes the crate-wide error enum `StrictPathError`, which captures boundary creation
//! failures, path resolution errors, and boundary escape attempts. These errors are surfaced
//! by public constructors and join operations throughout the crate.
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

/// Maximum characters shown per path in error messages. Paths longer than this are
/// truncated with `...` in the middle to keep diagnostics readable without hiding
/// the meaningful prefix and suffix (drive letter / filename).
const MAX_ERROR_PATH_LEN: usize = 256;

// Internal helper: render error-friendly path display (truncate long values).
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

/// Errors produced by boundary creation and strict/virtual path validation.
///
/// Returned by operations that construct `PathBoundary`/`VirtualRoot` or compose
/// `StrictPath`/`VirtualPath` via joins. Each variant carries enough context for
/// actionable diagnostics while avoiding leaking unbounded path data into messages.
#[derive(Debug)]
#[must_use = "this error indicates a path validation failure — handle it to detect path traversal attacks or invalid boundaries"]
pub enum StrictPathError {
    /// The boundary directory is invalid (missing, not a directory, or I/O error).
    InvalidRestriction {
        restriction: PathBuf,
        source: std::io::Error,
    },
    /// The attempted path resolves outside the `PathBoundary` — a traversal attack was blocked.
    PathEscapesBoundary {
        attempted_path: PathBuf,
        restriction_boundary: PathBuf,
    },
    /// Canonicalization or resolution failed for the given path.
    PathResolutionError {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl StrictPathError {
    // Internal helper: construct `InvalidRestriction`.
    #[inline]
    pub(crate) fn invalid_restriction(restriction: PathBuf, source: std::io::Error) -> Self {
        Self::InvalidRestriction {
            restriction,
            source,
        }
    }
    // Internal helper: construct `PathEscapesBoundary`.
    #[inline]
    pub(crate) fn path_escapes_boundary(
        attempted_path: PathBuf,
        restriction_boundary: PathBuf,
    ) -> Self {
        Self::PathEscapesBoundary {
            attempted_path,
            restriction_boundary,
        }
    }
    // Internal helper: construct `PathResolutionError`.
    #[inline]
    pub(crate) fn path_resolution_error(path: PathBuf, source: std::io::Error) -> Self {
        Self::PathResolutionError { path, source }
    }
}

impl fmt::Display for StrictPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StrictPathError::InvalidRestriction {
                restriction,
                source,
            } => {
                write!(
                    f,
                    "Invalid PathBoundary: '{}' is not a valid boundary directory ({source}). \
                     Ensure the path points to an existing directory, or use try_new_create() to auto-create it.",
                    truncate_path_display(restriction, MAX_ERROR_PATH_LEN)
                )
            }
            StrictPathError::PathEscapesBoundary {
                attempted_path,
                restriction_boundary,
            } => {
                let truncated_attempted = truncate_path_display(attempted_path, MAX_ERROR_PATH_LEN);
                let truncated_boundary =
                    truncate_path_display(restriction_boundary, MAX_ERROR_PATH_LEN);
                write!(
                    f,
                    "Path escapes boundary: '{truncated_attempted}' resolves outside restriction boundary \
                     '{truncated_boundary}' — this path traversal attempt was blocked. \
                     Validate untrusted input through strict_join()/virtual_join() which prevents escapes."
                )
            }
            StrictPathError::PathResolutionError { path, source } => {
                write!(
                    f,
                    "Cannot resolve path: '{}' ({source}). \
                     Ensure the target exists and is accessible, or create parent directories first.",
                    truncate_path_display(path, MAX_ERROR_PATH_LEN)
                )
            }
        }
    }
}

impl Error for StrictPathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            StrictPathError::InvalidRestriction { source, .. }
            | StrictPathError::PathResolutionError { source, .. } => Some(source),
            StrictPathError::PathEscapesBoundary { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
