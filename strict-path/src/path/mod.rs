pub mod strict_path;

#[cfg(feature = "virtual-path")]
pub mod virtual_path;

#[cfg(test)]
mod tests;

use crate::StrictPathError;
use std::ffi::OsStr;
use std::path::PathBuf;

/// Reject extensions that would panic inside `Path::with_extension`.
///
/// `Path::with_extension` has a runtime panic when the extension contains a path
/// separator (`/`, and also `\` on Windows). When the extension comes from
/// untrusted input, that turns into a DoS primitive. We translate the guard
/// into a normal `Err` before calling `with_extension`, so callers always see a
/// `Result` instead of an unwind.
pub(crate) fn validate_extension(
    extension: &OsStr,
    context_path: &std::path::Path,
) -> Result<(), StrictPathError> {
    for &byte in extension.as_encoded_bytes() {
        // `is_separator` takes a char; these two bytes cover every byte value
        // `std::path::is_separator` would accept on the respective platforms.
        if byte == b'/' {
            return Err(StrictPathError::path_resolution_error(
                context_path.to_path_buf(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "extension must not contain path separators",
                ),
            ));
        }
        #[cfg(windows)]
        if byte == b'\\' {
            return Err(StrictPathError::path_resolution_error(
                context_path.to_path_buf(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "extension must not contain path separators",
                ),
            ));
        }
        if byte == 0 {
            return Err(StrictPathError::path_resolution_error(
                context_path.to_path_buf(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "extension must not contain NUL bytes",
                ),
            ));
        }
    }
    Ok(())
}

/// Build a `PathBuf` like `Path::with_extension`, but return an error instead of
/// panicking on invalid input. The extension has already been screened via
/// `validate_extension`; this wrapper exists so the call site reads cleanly.
#[inline]
pub(crate) fn with_validated_extension(
    base: &std::path::Path,
    extension: &OsStr,
) -> Result<PathBuf, StrictPathError> {
    validate_extension(extension, base)?;
    Ok(base.with_extension(extension))
}
