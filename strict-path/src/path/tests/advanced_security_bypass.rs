use crate::{PathBoundary, StrictPathError};
use std::path::Path;

// ============================================================
// StrictPath-Only Core Security Tests (No virtual-path feature)
// ============================================================
//
// These tests exercise the PathBoundary/StrictPath dimension WITHOUT
// requiring the virtual-path feature. This ensures the 90% use case
// (StrictPath only) has security test coverage even when virtual-path
// is not enabled.

/// Core attack patterns tested through StrictPath only (no VirtualPath required).
/// Mirrors the patterns from the virtual-path-gated test_known_cve_patterns.
#[test]
fn test_strict_path_core_attack_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let attack_patterns: &[&str] = &[
        // Classic traversal
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
        "../../../../../../proc/self/environ",
        "../../../var/log/auth.log",
        // Doubled-dot variants
        "....//....//....//etc/shadow",
        // URL-encoded (literal percent, not decoded)
        "..%2F..%2F..%2Fetc%2Fpasswd",
        // File protocol
        "file:///etc/passwd",
        // UNC
        "\\\\server\\share\\sensitive.txt",
        // Relative dot-segments sneaking upward
        "../.env",
        "../../config/database.yml",
    ];

    for attack_input in attack_patterns {
        let candidate = Path::new(attack_input);
        let has_parent = candidate
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
        let is_absolute = candidate.is_absolute() || attack_input.starts_with("file://");

        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                // If accepted (e.g., literal percent chars), must remain inside boundary
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Attack pattern '{attack_input}' escaped boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected rejection for patterns with parent dirs or absolute paths
                assert!(
                    has_parent || is_absolute,
                    "Unexpected rejection for benign pattern '{attack_input}'"
                );
            }
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// Null byte path truncation attack: attackers use embedded NUL to truncate
/// paths in C-based implementations (e.g., `../../../etc/passwd\0.jpg`).
/// Rust's OsString handles NUL differently, but we must ensure no escape.
#[test]
fn test_strict_path_null_byte_truncation_attack() {
    use std::ffi::{OsStr, OsString};

    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Truncation attack: path looks like .jpg but NUL truncates to passwd
    let truncation_payloads: Vec<OsString> = vec![
        {
            let mut s = OsString::from("../../../etc/passwd");
            s.push(OsStr::new("\0"));
            s.push(OsStr::new(".jpg"));
            s
        },
        {
            let mut s = OsString::from("safe_file.txt");
            s.push(OsStr::new("\0"));
            s.push(OsStr::new("/../../../etc/shadow"));
            s
        },
        {
            let mut s = OsString::from("uploads/avatar");
            s.push(OsStr::new("\0"));
            s.push(OsStr::new(".png"));
            s
        },
    ];

    for attack_input in &truncation_payloads {
        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                // If accepted, must remain within boundary
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Null truncation attack escaped boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Clean rejection is acceptable
            }
            Err(other) => {
                panic!("Unexpected error for null truncation payload: {other:?}");
            }
        }
    }
}

/// Empty and whitespace-only path segments should be handled safely.
#[test]
fn test_strict_path_empty_and_whitespace_segments() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let edge_case_inputs: &[&str] = &[
        // Empty string
        "",
        // Whitespace-only segments
        " ",
        "  ",
        // Path with doubled separators (empty segments)
        "path//to//file",
        // Path with only separators
        "///",
        // Path with whitespace segments
        "path/ /to/file",
        // Current-dir segments
        "path/./to/./file",
        // Mixed current-dir and empty
        "./././.",
        // Trailing separator
        "data/",
        // Leading dot
        ".",
        // Just dots
        "..",
    ];

    for attack_input in edge_case_inputs {
        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Edge case '{attack_input}' escaped boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Clean rejection is acceptable (e.g., ".." escapes)
            }
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// Windows device namespace paths (`\\.\`, `\\?\GLOBALROOT\`) must be rejected
/// or safely contained. These can access raw devices and bypass file system security.
#[test]
#[cfg(windows)]
fn test_strict_path_windows_device_paths_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let device_paths: &[&str] = &[
        r"\\.\PhysicalDrive0",
        r"\\.\CONIN$",
        r"\\.\CONOUT$",
        r"\\.\pipe\name",
        r"\\.\COM1",
        r"\\.\PHYSICALDRIVE0",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1",
        r"\\?\GLOBALROOT\Device\Null",
        r"\\.\Volume{GUID}",
    ];

    for device_path in device_paths {
        let result = restriction.strict_join(device_path);

        // All device namespace paths must be rejected or safely contained
        match result {
            Ok(validated_path) => {
                // If somehow accepted (should not happen), verify containment
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Device path '{device_path}' escaped boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected: device paths are absolute and escape the boundary
            }
            Err(other) => {
                panic!("Unexpected error for device path '{device_path}': {other:?}");
            }
        }
    }
}

/// Windows reserved filenames in subdirectories must be properly handled.
/// CON, NUL, AUX etc. are special even when in subdirectories on Windows.
#[test]
#[cfg(windows)]
fn test_strict_path_windows_reserved_names_in_subdirs() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    // Create a subdirectory for testing
    let sub = restriction.strict_join("subdir").unwrap();
    sub.create_dir_all().unwrap();

    let reserved_in_subdirs: &[&str] = &[
        "subdir/CON",
        "subdir/NUL",
        "subdir/AUX",
        "subdir/PRN",
        "subdir/COM1",
        "subdir/LPT1",
        "subdir/CON.txt",
        "subdir/NUL.txt",
        "subdir/COM1.log",
    ];

    for reserved_path in reserved_in_subdirs {
        match restriction.strict_join(reserved_path) {
            Ok(validated_path) => {
                // If accepted, must remain within boundary
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Reserved name '{reserved_path}' escaped boundary: {validated_path:?}"
                );
                // On Windows, writes to reserved names may behave unexpectedly
                // (e.g., CON maps to console). Verify no security escape occurred.
            }
            Err(_) => {
                // Rejection is acceptable; reserved names on Windows are tricky
            }
        }
    }
}

/// Mixed absolute-relative attacks: absolute path components embedded within
/// relative-looking paths. On Unix, backslashes in paths are literal filename
/// characters, not separators.
#[test]
#[cfg(unix)]
fn test_strict_path_unix_backslash_literal_filename() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // On Unix, backslash is a valid filename character, not a separator.
    // These should be treated as literal filenames (single component), not traversal.
    let backslash_paths: &[&str] = &[r"..\..\etc\passwd", r"..\secret.txt", r"data\..\config"];

    for attack_input in backslash_paths {
        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                // On Unix, the backslash is a literal filename character.
                // The path is treated as a single component, not traversal.
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Backslash path '{attack_input}' escaped boundary on Unix: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Also acceptable: even on Unix, rejecting these is safe
            }
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// Double URL encoding attacks: `%252e%252e%252f` decodes to `%2e%2e%2f` (first
/// decode) then `../` (second decode). While URL decoding is the application's
/// responsibility, the literal encoded strings must not escape if passed directly.
#[test]
fn test_strict_path_double_url_encoding_containment() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let double_encoded_attacks: &[&str] = &[
        // Double-encoded `../`
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        // Double-encoded `..\\`
        "%252e%252e%255c%252e%252e%255cWindows%255cSystem32",
        // Triple-encoded for good measure
        "%25252e%25252e%25252f",
        // Mixed single and double encoding
        "%252e%252e/%2e%2e/etc/passwd",
    ];

    for attack_input in double_encoded_attacks {
        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                // Literal percent characters are valid filename chars; path
                // must still be contained within boundary
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Double-encoded attack '{attack_input}' escaped boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Clean rejection is also acceptable
            }
            Err(other) => {
                panic!("Unexpected error for double-encoded '{attack_input}': {other:?}");
            }
        }
    }
}
