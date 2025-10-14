//! SUMMARY:
//! Define error types and helpers for boundary creation and strict/virtual path validation.
//!
//! OVERVIEW:
//! This module exposes the crate-wide error enum `StrictPathError`, which captures
//! boundary creation failures, path resolution errors, boundary escape attempts,
//! and (on Windows) 8.3 short-name rejections. These errors are surfaced by
//! public constructors and join operations throughout the crate.
//!
//! STYLE:
//! All items follow the standardized doc format with explicit sections to keep
//! behavior unambiguous for both humans and LLMs.
// Content copied from original src/error/mod.rs
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

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

/// SUMMARY:
/// Represent errors produced by boundary creation and strict/virtual path validation.
///
/// DETAILS:
/// This error type is returned by operations that construct `PathBoundary`
///`VirtualRoot` or that compose `StrictPath`/`VirtualPath` via joins. Each
/// variant carries enough context for actionable diagnostics while avoiding
/// leaking unbounded path data into messages (we truncate long displays).
///
/// VARIANTS:
/// - `InvalidRestriction`: The boundary directory is missing, not a directory, or failed I/O checks.
/// - `PathEscapesBoundary`: A candidate path would resolve outside the boundary.
/// - `PathResolutionError`: Canonicalization or resolution failed (I/O error).
#[derive(Debug)]
pub enum StrictPathError {
    /// SUMMARY:
    /// The boundary directory is invalid (missing, not a directory, or I/O error).
    ///
    /// FIELDS:
    /// - `restriction` (`PathBuf`): The attempted boundary path.
    /// - `source` (`std::io::Error`): Underlying OS error that explains why the
    ///   restriction is invalid.
    InvalidRestriction {
        restriction: PathBuf,
        source: std::io::Error,
    },
    /// SUMMARY:
    /// The attempted path would resolve outside the PathBoundary boundary.
    ///
    /// FIELDS:
    /// - `attempted_path` (`PathBuf`): The user-supplied or composed candidate.
    /// - `restriction_boundary` (`PathBuf`): The effective boundary root.
    PathEscapesBoundary {
        attempted_path: PathBuf,
        restriction_boundary: PathBuf,
    },
    /// SUMMARY:
    /// Canonicalization/resolution failed for the given path.
    ///
    /// FIELDS:
    /// - `path` (`PathBuf`): The path whose resolution failed.
    /// - `source` (`std::io::Error`): Underlying I/O cause.
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
            StrictPathError::InvalidRestriction { restriction, .. } => {
                write!(
                    f,
                    "Invalid PathBoundary directory: {}",
                    restriction.display()
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
                    "Path '{truncated_attempted}' escapes path restriction boundary '{truncated_boundary}'"
                )
            }
            StrictPathError::PathResolutionError { path, .. } => {
                write!(f, "Cannot resolve path: {}", path.display())
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
