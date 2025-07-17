use crate::error::{truncate_path_display, JailedPathError};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

#[test]
fn test_invalid_jail_error_creation_and_display() {
    let jail_path = PathBuf::from("/invalid/jail");
    let io_error = io::Error::new(io::ErrorKind::NotFound, "Directory not found");

    let error = JailedPathError::invalid_jail(jail_path.clone(), io_error);

    // Should display the jail path
    let display_str = format!("{error}");
    assert!(display_str.contains("Invalid jail directory"));
    assert!(display_str.contains("/invalid/jail"));

    // Should preserve the source error
    match error {
        JailedPathError::InvalidJail { jail, source } => {
            assert_eq!(jail, jail_path);
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(source.to_string().contains("Directory not found"));
        }
        _ => panic!("Expected InvalidJail error"),
    }
}

#[test]
fn test_path_escapes_boundary_error_creation_and_display() {
    let attempted_path = PathBuf::from("/etc/passwd");
    let jail_boundary = PathBuf::from("/var/www");

    let error =
        JailedPathError::path_escapes_boundary(attempted_path.clone(), jail_boundary.clone());

    // Should display both paths
    let display_str = format!("{error}");
    assert!(display_str.contains("escapes jail boundary"));
    assert!(display_str.contains("/etc/passwd"));
    assert!(display_str.contains("/var/www"));

    // Should store both paths correctly
    match error {
        JailedPathError::PathEscapesBoundary {
            attempted_path: stored_attempted,
            jail_boundary: stored_boundary,
        } => {
            assert_eq!(stored_attempted, attempted_path);
            assert_eq!(stored_boundary, jail_boundary);
        }
        _ => panic!("Expected PathEscapesBoundary error"),
    }
}

#[test]
fn test_path_resolution_error_creation_and_display() {
    let path = PathBuf::from("/nonexistent/file.txt");
    let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");

    let error = JailedPathError::path_resolution_error(path.clone(), io_error);

    // Should display the path
    let display_str = format!("{error}");
    assert!(display_str.contains("Cannot resolve path"));
    assert!(display_str.contains("/nonexistent/file.txt"));

    // Should preserve the source error
    match error {
        JailedPathError::PathResolutionError {
            path: stored_path,
            source,
        } => {
            assert_eq!(stored_path, path);
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
            assert!(source.to_string().contains("File not found"));
        }
        _ => panic!("Expected PathResolutionError error"),
    }
}

#[test]
fn test_error_source_chaining() {
    let jail_path = PathBuf::from("/invalid/jail");
    let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");

    let error = JailedPathError::invalid_jail(jail_path, io_error);

    // Should properly implement Error trait with source chaining
    let source = error.source().expect("Should have a source error");
    let io_source = source
        .downcast_ref::<io::Error>()
        .expect("Source should be io::Error");
    assert_eq!(io_source.kind(), io::ErrorKind::PermissionDenied);
    assert!(io_source.to_string().contains("Access denied"));
}

#[test]
fn test_path_escapes_boundary_has_no_source() {
    let attempted_path = PathBuf::from("/etc/passwd");
    let jail_boundary = PathBuf::from("/var/www");

    let error = JailedPathError::path_escapes_boundary(attempted_path, jail_boundary);

    // PathEscapesBoundary should not have a source error
    assert!(
        error.source().is_none(),
        "PathEscapesBoundary should not have a source error"
    );
}

#[test]
fn test_path_truncation_prevents_memory_attacks() {
    // Create a very long path to test truncation
    let long_path_component = "a".repeat(300);
    let attempted_path = PathBuf::from(format!("/very/long/path/{long_path_component}"));
    let jail_boundary = PathBuf::from("/short/jail");

    let error = JailedPathError::path_escapes_boundary(attempted_path, jail_boundary);
    let display_str = format!("{error}");

    // Display string should be truncated to prevent memory exhaustion
    assert!(
        display_str.len() < 1000,
        "Display string should be truncated for very long paths"
    );
    assert!(
        display_str.contains("..."),
        "Truncated paths should contain ellipsis"
    );
}

#[test]
fn test_normal_length_paths_not_truncated() {
    let attempted_path = PathBuf::from("/normal/length/path/file.txt");
    let jail_boundary = PathBuf::from("/jail/boundary");

    let error =
        JailedPathError::path_escapes_boundary(attempted_path.clone(), jail_boundary.clone());
    let display_str = format!("{error}");

    // Normal paths should not be truncated
    assert!(display_str.contains("/normal/length/path/file.txt"));
    assert!(display_str.contains("/jail/boundary"));
    assert!(
        !display_str.contains("..."),
        "Normal paths should not contain ellipsis"
    );
}

#[test]
fn test_error_debug_formatting() {
    let jail_path = PathBuf::from("/test/jail");
    let io_error = io::Error::new(io::ErrorKind::NotFound, "Not found");

    let error = JailedPathError::invalid_jail(jail_path, io_error);
    let debug_str = format!("{error:?}");

    // Should be debuggable (all error types implement Debug)
    assert!(debug_str.contains("InvalidJail"));
    assert!(debug_str.contains("/test/jail"));
}

#[test]
fn test_truncate_path_display_function() {
    // Test the internal truncate function behavior
    let short_path = Path::new("/short/path");
    let truncated = truncate_path_display(short_path, 100);
    assert_eq!(
        truncated, "/short/path",
        "Short paths should not be truncated"
    );

    let long_path_str = format!("/very/long/path/{}", "x".repeat(200));
    let long_path = Path::new(&long_path_str);
    let truncated = truncate_path_display(long_path, 50);
    assert!(
        truncated.len() <= 50,
        "Long paths should be truncated to max length"
    );
    assert!(
        truncated.contains("..."),
        "Truncated paths should contain ellipsis"
    );
    assert!(
        truncated.starts_with("/very"),
        "Should preserve beginning of path"
    );
    assert!(truncated.ends_with("xxx"), "Should preserve end of path");
}

#[test]
fn test_all_error_variants_are_send_and_sync() {
    // Ensure our errors can be sent across threads and shared
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<JailedPathError>();
}
