use std::error::Error;
use std::fmt;

/// Errors that can occur during jailed path operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailedPathError {
    /// The provided jail directory is invalid or inaccessible.
    InvalidJail {
        /// The jail path that caused the error.
        jail: String,
        /// The underlying reason for the error.
        reason: String,
    },

    /// The path escapes the jail boundary.
    PathEscapesBoundary {
        /// The path that attempted to escape.
        attempted_path: String,
        /// The jail boundary it tried to escape from.
        jail_boundary: String,
    },

    /// The path contains invalid components or characters.
    InvalidPath {
        /// The invalid path.
        path: String,
        /// The reason the path is invalid.
        reason: String,
    },

    /// An I/O error occurred during path validation.
    IoError {
        /// The path being validated when the error occurred.
        path: String,
        /// The I/O error message.
        message: String,
    },
}

impl JailedPathError {
    /// Creates a new `InvalidJail` error.
    pub fn invalid_jail(jail: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidJail {
            jail: jail.into(),
            reason: reason.into(),
        }
    }

    /// Creates a new `PathEscapesBoundary` error.
    pub fn path_escapes_boundary(
        attempted_path: impl Into<String>,
        jail_boundary: impl Into<String>,
    ) -> Self {
        Self::PathEscapesBoundary {
            attempted_path: attempted_path.into(),
            jail_boundary: jail_boundary.into(),
        }
    }

    /// Creates a new `InvalidPath` error.
    pub fn invalid_path(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidPath {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Creates a new `IoError` from a std::io::Error.
    pub fn from_io_error(path: impl Into<String>, io_error: std::io::Error) -> Self {
        Self::IoError {
            path: path.into(),
            message: io_error.to_string(),
        }
    }
}

impl fmt::Display for JailedPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JailedPathError::InvalidJail { jail, reason } => {
                write!(f, "Invalid jail directory '{jail}': {reason}")
            }
            JailedPathError::PathEscapesBoundary {
                attempted_path,
                jail_boundary,
            } => {
                write!(
                    f,
                    "Path '{attempted_path}' escapes jail boundary '{jail_boundary}'"
                )
            }
            JailedPathError::InvalidPath { path, reason } => {
                write!(f, "Invalid path '{path}': {reason}")
            }
            JailedPathError::IoError { path, message } => {
                write!(f, "I/O error for path '{path}': {message}")
            }
        }
    }
}

impl Error for JailedPathError {}
