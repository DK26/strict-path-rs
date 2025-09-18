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

    // Now, any I/O on the existing path object should fail because it re-validates.
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
