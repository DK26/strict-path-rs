use crate::{PathBoundary, StrictPathError, VirtualRoot};

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
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::WindowsShortName { .. }) => {
                // Correctly rejected by either the traversal check or the 8.3 short name check.
            }
            Ok(p) => {
                panic!(
                    "SECURITY FAILURE: 8.3 short name bypass was not detected. Path: {:?}",
                    p
                );
            }
            Err(e) => {
                panic!("Unexpected error for 8.3 short name attack: {:?}", e);
            }
        }
    } else {
        eprintln!("Skipping 8.3 short name test: could not determine short name for 'long-directory-name'.");
    }
}

#[test]
fn test_advanced_toctou_read_race_condition() {
    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path().join("restriction");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let restriction_dir = std::fs::canonicalize(restriction_dir).unwrap();

    let safe_dir = restriction_dir.join("safe");
    std::fs::create_dir_all(&safe_dir).unwrap();

    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&outside_dir).unwrap();
    let outside_dir = std::fs::canonicalize(outside_dir).unwrap();

    let safe_file = safe_dir.join("file.txt");
    let outside_file = outside_dir.join("secret.txt");
    std::fs::write(&safe_file, "safe content").unwrap();
    std::fs::write(&outside_file, "secret content").unwrap();

    let link_path = restriction_dir.join("link");

    // Initially, link points to the safe file.
    #[cfg(unix)]
    std::os::unix::fs::symlink(&safe_file, &link_path).unwrap();
    #[cfg(windows)]
    if let Err(e) = std::os::windows::fs::symlink_file(&safe_file, &link_path) {
        eprintln!("Skipping TOCTOU test - symlink creation failed: {:?}", e);
        return;
    }

    let vroot: VirtualRoot = VirtualRoot::try_new(&restriction_dir).unwrap();
    let path_object = vroot.virtual_join("link").unwrap();

    // Verify it points to the safe file initially.
    assert_eq!(path_object.read_to_string().unwrap(), "safe content");

    // ATTACK: In another thread, swap the symlink to point outside.
    #[cfg(unix)]
    {
        std::fs::remove_file(&link_path).unwrap();
        std::os::unix::fs::symlink(&outside_file, &link_path).unwrap();
    }
    #[cfg(windows)]
    {
        std::fs::remove_file(&link_path).unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(&outside_file, &link_path) {
            eprintln!("Skipping TOCTOU test - symlink re-creation failed: {:?}", e);
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
                    "Expected PathEscapesBoundary but got {:?}",
                    strict_err
                );
            } else {
                panic!("Expected StrictPathError but got a different error type.");
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Acceptable: symlink was clamped to virtual root, resulting in non-existent path
            eprintln!(
                "TOCTOU test: Clamping caused NotFound (expected with 0.4.0 clamping behavior)"
            );
        }
        Ok(content) => {
            assert_eq!(
                content, "safe content",
                "TOCTOU read returned unexpected data; possible escape"
            );
        }
        Err(e) => {
            panic!("Unexpected error for TOCTOU read race: {:?}", e);
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

/// Tests that non-existent paths with 8.3 short names are rejected.
/// This simulates trying to access a path that doesn't exist, where canonicalization
/// cannot expand the short name, creating a security risk.
#[test]
#[cfg(windows)]
fn test_github_runner_nonexistent_path_with_short_name_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Try to join a path that looks like it has an 8.3 short name but doesn't exist
    // Example: "NONEXIST~1/file.txt"
    let fake_short_name_path = "ABCDEF~1/file.txt";

    let result = boundary.strict_join(fake_short_name_path);

    // Should be rejected because:
    // 1. Path doesn't exist
    // 2. Canonicalization can't expand ABCDEF~1
    // 3. We can't verify if it's an alias
    match result {
        Err(StrictPathError::WindowsShortName { component, .. }) => {
            eprintln!("Correctly rejected non-existent path with short name: {component:?}");
            assert!(component.to_string_lossy().contains('~'));
        }
        Ok(p) => {
            panic!(
                "SECURITY FAILURE: Accepted non-existent path with short name: {:?}",
                p
            );
        }
        Err(e) => {
            // PathResolutionError is also acceptable (path doesn't exist)
            assert!(
                matches!(e, StrictPathError::PathResolutionError { .. }),
                "Expected WindowsShortName or PathResolutionError, got: {e:?}"
            );
        }
    }
}

/// Tests symlink clamping with 8.3 short names in the clamped path.
/// When a symlink points outside and gets clamped, the clamped path might not exist
/// and could contain unexpanded 8.3 short names. This is acceptable - the path
/// validation allows it, and the I/O operation will naturally fail.
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

            // Verify it's clamped within boundary
            assert!(clamped_path
                .as_unvirtual()
                .strictpath_starts_with(&restriction_dir));

            // Try to read - should fail because clamped path doesn't exist
            let read_result = clamped_path.read_to_string();
            assert!(
                read_result.is_err(),
                "Reading clamped symlink should fail (doesn't exist)"
            );
            eprintln!("Read correctly failed: {:?}", read_result.unwrap_err());
        }
        Err(e) => {
            // WindowsShortName error might occur if the clamped path has short names
            // This is also acceptable behavior
            eprintln!("virtual_join returned error (acceptable): {e:?}");
            assert!(
                matches!(
                    e,
                    StrictPathError::WindowsShortName { .. }
                        | StrictPathError::PathResolutionError { .. }
                ),
                "Expected WindowsShortName or PathResolutionError, got: {e:?}"
            );
        }
    }
}
