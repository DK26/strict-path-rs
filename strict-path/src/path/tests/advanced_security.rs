#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{PathBoundary, StrictPathError};
use std::path::Path;

#[test]
#[cfg(windows)]
fn test_case_sensitivity_bypass_attack() {
    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path();
    let data_dir = restriction_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(restriction_dir).unwrap();

    // Attacker uses different casing ("DATA") to try to obscure the traversal.
    let attack_path = r"DATA\..\..\windows";
    let result = restriction.strict_join(attack_path);

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Correctly rejected.
        }
        Ok(p) => {
            panic!(
                "SECURITY FAILURE: Case-sensitivity bypass was not detected. Path: {:?}",
                p
            );
        }
        Err(e) => {
            panic!("Unexpected error for case-sensitivity attack: {:?}", e);
        }
    }
}

#[test]
#[cfg(windows)]
fn test_ntfs_83_short_name_bypass_attack() {
    use std::process::Command;

    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path();
    let long_name_dir = restriction_dir.join("long-directory-name");
    std::fs::create_dir_all(&long_name_dir).unwrap();

    // Get the 8.3 short name. This can fail if 8.3 name generation is disabled.
    let output = Command::new("cmd")
        .args(["/C", "dir /X"])
        .current_dir(restriction_dir)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let short_name = stdout
        .lines()
        .find(|line| line.contains("long-directory-name"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|s| s.contains('~') && s.len() <= 12)
        });

    if let Some(short_name) = short_name {
        let restriction: PathBoundary = PathBoundary::try_new(restriction_dir).unwrap();
        let attack_path = format!(r"{}\{}", short_name, r"..\..\windows");
        let result = restriction.strict_join(&attack_path);

        match result {
            Err(StrictPathError::PathEscapesBoundary { .. }) => {
                // Correctly rejected by the traversal check.
                // The canonicalization expands the short name, and the boundary check
                // detects the ".." traversal attempts.
            }
            Ok(p) => {
                // With the new approach, the path might be allowed if it stays within the boundary.
                // Verify it's actually inside the restriction.
                let p_canon = std::fs::canonicalize(p.interop_path()).unwrap();
                assert!(
                    p_canon.starts_with(restriction_dir),
                    "Path {:?} should be inside boundary {:?}",
                    p_canon,
                    restriction_dir
                );
            }
            Err(e) => {
                panic!("Unexpected error for 8.3 short name test: {:?}", e);
            }
        }
    } else {
        eprintln!("Skipping 8.3 short name test: could not determine short name for 'long-directory-name'.");
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_advanced_toctou_read_race_condition() {
    let temp = tempfile::tempdir().unwrap();

    // Create directories - on Windows, we need to handle 8.3 short names
    // VirtualRoot will canonicalize internally (expanding short names and adding \\?\)
    // We need to create symlinks using the SAME canonical form to avoid path mismatches
    let restriction_dir = {
        let p = temp.path().join("restriction");
        std::fs::create_dir_all(&p).unwrap();

        #[cfg(not(windows))]
        {
            std::fs::canonicalize(&p).unwrap()
        }
        #[cfg(windows)]
        {
            // On Windows: canonicalize to expand 8.3 short names (RUNNER~1 → runneradmin)
            // but strip the \\?\ prefix to keep symlink creation working
            let canonical = std::fs::canonicalize(&p).unwrap();
            let canonical_str = canonical.to_string_lossy();

            if let Some(stripped) = canonical_str.strip_prefix(r"\\?\") {
                std::path::PathBuf::from(stripped)
            } else {
                canonical
            }
        }
    };

    let safe_dir = restriction_dir.join("safe");
    std::fs::create_dir_all(&safe_dir).unwrap();

    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create the files - no need to canonicalize since we're using relative symlink targets
    let _safe_file = safe_dir.join("file.txt");
    std::fs::write(&_safe_file, "safe content").unwrap();

    let _outside_file = outside_dir.join("secret.txt");
    std::fs::write(&_outside_file, "secret content").unwrap();

    let link_path = restriction_dir.join("link");

    // Initially, link points to the safe file via a RELATIVE target.
    // Using relative targets avoids absolute path quirks on Windows runners (short names/privileges).
    #[cfg(unix)]
    {
        let rel_target = std::path::Path::new("safe").join("file.txt");
        std::os::unix::fs::symlink(&rel_target, &link_path).unwrap();
    }
    #[cfg(windows)]
    {
        let rel_target = std::path::Path::new("safe").join("file.txt");
        if let Err(e) = std::os::windows::fs::symlink_file(&rel_target, &link_path) {
            eprintln!("Skipping TOCTOU test - symlink creation failed: {e:?}");
            return;
        }
    }

    let vroot: VirtualRoot = VirtualRoot::try_new(&restriction_dir).unwrap();
    let path_object = vroot.virtual_join("link").unwrap();

    // Verify it points to the safe file initially.
    // On some Windows setups, relative symlink resolution may transiently return NotFound;
    // treat that as acceptable for the initial sanity check to avoid spurious panics.

    match path_object.read_to_string() {
        Ok(content) => {
            assert_eq!(
                content, "safe content",
                "Initial TOCTOU read returned unexpected data; expected safe content"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Acceptable on some Windows setups - continuing test
        }
        Err(e) => {
            panic!("Unexpected error for initial TOCTOU read: {e:?}");
        }
    }

    // ATTACK: In another thread, swap the symlink to point outside (use RELATIVE escape).
    #[cfg(unix)]
    {
        std::fs::remove_file(&link_path).unwrap();
        let rel_escape = std::path::Path::new("..")
            .join("outside")
            .join("secret.txt");
        std::os::unix::fs::symlink(&rel_escape, &link_path).unwrap();
    }
    #[cfg(windows)]
    {
        std::fs::remove_file(&link_path).unwrap();
        let rel_escape = std::path::Path::new("..")
            .join("outside")
            .join("secret.txt");
        if let Err(e) = std::os::windows::fs::symlink_file(&rel_escape, &link_path) {
            eprintln!("Skipping TOCTOU test - symlink re-creation failed: {e:?}");
            return;
        }
    }

    // With symlink clamping (0.4.0), the swapped symlink is clamped to virtual root.
    // The outside file path gets clamped to restriction_dir/outside/secret.txt (doesn't exist).
    // Expected outcomes:
    // 1. NotFound error (clamped path doesn't exist) - acceptable, shows clamping worked
    // 2. Safe content (if symlink swap happened after validation) - acceptable
    // 3. PathEscapesBoundary (if escape detected before clamping) - acceptable

    let result = path_object.read_to_string();

    match result {
        Err(e) if e.kind() == std::io::ErrorKind::Other => {
            let inner_err = e.into_inner().unwrap();
            if let Some(strict_err) = inner_err.downcast_ref::<StrictPathError>() {
                assert!(
                    matches!(strict_err, StrictPathError::PathEscapesBoundary { .. }),
                    "Expected PathEscapesBoundary but got {strict_err:?}",
                );
            } else {
                panic!("Expected StrictPathError but got a different error type.");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Acceptable: symlink was clamped to virtual root, resulting in non-existent path
        }
        Ok(content) => {
            assert_eq!(
                content, "safe content",
                "TOCTOU read returned unexpected data; possible escape"
            );
        }
        Err(e) => {
            panic!("Unexpected error for TOCTOU read race: {e:?}");
        }
    }
}

#[test]
fn test_environment_variable_injection() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let patterns = if cfg!(windows) {
        vec![r"..\%WINDIR%\System32", r"..\%TEMP%\file"]
    } else {
        vec!["../$HOME/.ssh/id_rsa", "../$TMPDIR/file"]
    };

    for pattern in patterns {
        let result = restriction.strict_join(pattern);
        // The path should be treated literally. Since it contains '..', it should be rejected
        // as a traversal attempt, NOT expanded.
        match result {
            Err(StrictPathError::PathEscapesBoundary { .. }) => {
                // Correctly rejected as a literal traversal.
            }
            Ok(p) => {
                panic!(
                    "SECURITY FAILURE: Environment variable was likely expanded. Path: {:?}",
                    p
                );
            }
            Err(e) => {
                // On some platforms, characters like '$' or '%' might be invalid in paths,
                // leading to a different error. This is also a safe outcome.
                assert!(matches!(e, StrictPathError::PathResolutionError { .. }));
            }
        }
    }
}

/// Simulates GitHub Windows runner environment where parent directories contain 8.3 short names.
/// This test verifies that existing paths with 8.3 names in parent dirs are handled correctly.
#[test]
#[cfg(windows)]
fn test_github_runner_short_name_scenario_existing_paths() {
    use std::process::Command;

    // Create a temp directory and a subdirectory with a long name
    let temp = tempfile::tempdir().unwrap();
    let long_name_dir = temp
        .path()
        .join("very-long-directory-name-that-triggers-8dot3");
    std::fs::create_dir_all(&long_name_dir).unwrap();

    // Try to get the 8.3 short name using Windows dir command
    let output = Command::new("cmd")
        .args(["/C", "dir", "/X"])
        .current_dir(temp.path())
        .output();

    let short_name = if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find(|line| line.contains("very-long-directory-name"))
            .and_then(|line| {
                line.split_whitespace()
                    .find(|s| s.contains('~') && s.len() <= 12)
            })
            .map(|s| s.to_string())
    } else {
        None
    };

    if let Some(short_name) = short_name {
        eprintln!("Found 8.3 short name: {short_name}");

        // Test 1: PathBoundary should work with the long name (path exists)
        let boundary: PathBoundary = PathBoundary::try_new(&long_name_dir)
            .expect("Should create boundary from existing long-named directory");

        // Create a file inside
        let test_file = long_name_dir.join("test.txt");
        std::fs::write(&test_file, "content").unwrap();

        // Test 2: strict_join with regular path should work
        let joined = boundary
            .strict_join("test.txt")
            .expect("Should join to existing file");
        assert!(joined.exists());

        // Test 3: Using short name in INPUT should also work if path exists
        // (because canonicalization will expand it)
        let short_path = temp.path().join(&short_name).join("test.txt");
        eprintln!("Attempting to access via short path: {short_path:?}");

        // Verify the short path actually works at OS level
        if short_path.exists() {
            eprintln!("Short path exists at OS level, testing strict_join...");
            // If we try to create a boundary using the short name path
            let short_boundary_result: Result<PathBoundary, _> =
                PathBoundary::try_new(temp.path().join(&short_name));
            match short_boundary_result {
                Ok(short_boundary) => {
                    eprintln!("Created boundary via short name (canonicalization expanded it)");
                    // Should be able to join
                    let via_short = short_boundary.strict_join("test.txt");
                    assert!(via_short.is_ok(), "Should handle short name in parent path");
                }
                Err(e) => {
                    eprintln!("Could not create boundary via short name: {e:?}");
                }
            }
        }
    } else {
        eprintln!("Skipping test: Could not determine 8.3 short name (might be disabled)");
    }
}

/// Tests that paths containing Windows 8.3 short name patterns are handled correctly
/// through canonicalization + boundary check, without explicit short name rejection.
/// The security is maintained by the mathematical property that canonicalized paths
/// can't escape their canonicalized boundary.
#[test]
#[cfg(windows)]
fn test_short_name_patterns_handled_via_canonicalization() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Create a real directory with a pattern that looks like a short name
    let dir_with_tilde = temp.path().join("TEST~1");
    std::fs::create_dir_all(&dir_with_tilde).unwrap();
    std::fs::write(dir_with_tilde.join("file.txt"), b"content").unwrap();

    // This should succeed - canonicalization handles it
    let result = boundary.strict_join("TEST~1/file.txt");
    assert!(
        result.is_ok(),
        "Should accept paths with ~N pattern when they exist: {:?}",
        result
    );

    // Try a non-existent path with short name pattern
    let result = boundary.strict_join("ABCDEF~1/file.txt");
    // Will fail during canonicalization (path doesn't exist), which is fine
    if let Err(e) = result {
        assert!(
            matches!(e, StrictPathError::PathResolutionError { .. }),
            "Non-existent paths fail during canonicalization: {:?}",
            e
        );
    }
}

/// Tests symlink clamping with 8.3 short names in the clamped path.
/// When a symlink points outside and gets clamped, the clamped path might not exist
/// and could contain unexpanded 8.3 short names. This is acceptable - the path
/// validation allows it, and the I/O operation will naturally fail.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_github_runner_clamped_symlink_with_short_names() {
    use std::os::windows::fs as winfs;

    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path().join("boundary");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create a file outside
    let outside_file = outside_dir.join("secret.txt");
    std::fs::write(&outside_file, "secret").unwrap();

    // Create symlink inside pointing outside
    let link_inside = restriction_dir.join("link");
    if let Err(e) = winfs::symlink_file(&outside_file, &link_inside) {
        eprintln!("Skipping test - symlink creation failed: {e:?}");
        return;
    }

    // Create VirtualRoot - should succeed
    let vroot: VirtualRoot = VirtualRoot::try_new(&restriction_dir)
        .expect("Should create VirtualRoot even if temp path has short names in parents");

    // Try to access the symlink through virtual join
    // This should succeed (clamping behavior), but the clamped path won't exist
    let result = vroot.virtual_join("link");

    match result {
        Ok(clamped_path) => {
            eprintln!(
                "Symlink was clamped successfully: {}",
                clamped_path.virtualpath_display()
            );

            // The clamped path should be within the boundary - just verify it's accessible
            eprintln!(
                "Clamped virtual path: {}",
                clamped_path.virtualpath_display()
            );

            // Try to read - should fail because clamped path doesn't exist
            let read_result = clamped_path.read_to_string();
            assert!(
                read_result.is_err(),
                "Reading clamped symlink should fail (doesn't exist)"
            );
            eprintln!("Read correctly failed: {:?}", read_result.unwrap_err());
        }
        Err(StrictPathError::PathResolutionError { .. }) => {
            // Acceptable: I/O error during resolution (e.g., on GitHub runners)
            eprintln!("Test passed: PathResolutionError during symlink resolution");
        }
        Err(e) => {
            panic!("Unexpected error: {e:?}");
        }
    }
}

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
