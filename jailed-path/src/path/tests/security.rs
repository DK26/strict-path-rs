use crate::Jail;
use std::sync::Arc;
use std::thread;

#[test]
fn test_known_cve_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let attack_patterns = vec![
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
        "../../../../../../proc/self/environ",
        "../../../var/log/auth.log",
        "....//....//....//etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "file:///etc/passwd",
        "\\\\server\\share\\sensitive.txt",
        ".ssh/id_rsa",
        "../.env",
        "../../config/database.yml",
    ];

    for pattern in attack_patterns {
        if let Ok(jailed_path) = jail.systempath_join(pattern) {
            let virtual_path = jailed_path.clone().virtualize();
            let virtual_str = virtual_path.virtualpath_to_string_lossy();

            if !pattern.contains("....") && !pattern.contains("%2F") {
                let is_traversal_pattern =
                    pattern.contains("../") || (cfg!(windows) && pattern.contains("..\\\\"));

                if is_traversal_pattern {
                    assert!(
                        !virtual_str.contains(".."),
                        "Attack pattern '{pattern}' not properly sanitized: {virtual_str}"
                    );
                }
            }

            assert!(
                jailed_path.systempath_starts_with(jail.path()),
                "Attack pattern '{pattern}' escaped jail: {jailed_path:?}"
            );
        }
    }
}

#[test]
fn test_unicode_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let unicode_patterns = vec![
        "файл.txt",
        "测试文件.log",
        "🔒secure.dat",
        "file\u{202E}gnp.txt",
        "file\u{200D}hidden.txt",
        "café/naïve.json",
        "file\u{FEFF}bom.txt",
        "\u{1F4C1}folder/test.txt",
    ];

    for pattern in unicode_patterns {
        match jail.systempath_join(pattern) {
            Ok(jailed_path) => {
                assert!(jailed_path.systempath_starts_with(jail.path()));
            }
            Err(_e) => {
                // Rejections are acceptable; test ensures no panics and no escapes
            }
        }
    }
}

#[test]
fn test_concurrent_validator_usage() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Arc<Jail> = Arc::new(Jail::try_new(temp.path()).unwrap());
    let mut handles = vec![];

    for i in 0..5 {
        let jail_clone = Arc::clone(&jail);
        let handle = thread::spawn(move || {
            for j in 0..50 {
                let path = format!("thread_{i}/file_{j}.txt");
                let result = jail_clone.systempath_join(&path);
                assert!(result.is_ok(), "Thread {i} iteration {j} failed");

                let jailed_path = result.unwrap();
                let virtual_path = jailed_path.virtualize();
                assert!(format!("{virtual_path}").contains(&format!("/thread_{i}")));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_long_path_handling() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let long_component = "a".repeat(64);
    let long_path = format!("{long_component}/{long_component}/{long_component}/{long_component}",);

    if let Ok(jailed_path) = jail.systempath_join(long_path) {
        assert!(jailed_path.systempath_starts_with(jail.path()));
    }

    let traversal_attack = "../".repeat(10) + "etc/passwd";
    if let Ok(jailed_path) = jail.systempath_join(traversal_attack) {
        assert!(jailed_path.systempath_starts_with(jail.path()));
        let virtual_path = jailed_path.virtualize();
        let expected_path = "/etc/passwd".to_string();
        assert_eq!(virtual_path.virtualpath_to_string_lossy(), expected_path);
    }
}

#[test]
#[cfg(windows)]
fn test_windows_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let windows_patterns = vec![
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
        "file.txt:",
        "file.txt::$DATA",
        "\\\\?\\C:\\Windows\\System32",
        "\\\\server\\share",
    ];

    for pattern in windows_patterns {
        if let Ok(jailed_path) = jail.systempath_join(pattern) {
            assert!(jailed_path.systempath_starts_with(jail.path()));
        }
    }
}

#[test]
#[cfg(unix)]
fn test_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let jail_dir = base.join("jail");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&jail_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create symlink inside jail pointing to a directory outside the jail
    let link_in_jail = jail_dir.join("link");
    unixfs::symlink(&outside_dir, &link_in_jail).unwrap();

    let jail: Jail = Jail::try_new(&jail_dir).unwrap();

    // Attempt to validate a path that goes through the symlink to outside
    let err = jail.systempath_join("link/escape.txt").unwrap_err();
    match err {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }

    // Same check via VirtualRoot
    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(&jail_dir).unwrap();
    let err2 = vroot.virtualpath_join("link/escape.txt").unwrap_err();
    match err2 {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary via virtual, got {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn test_relative_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let jail_dir = base.join("jail");
    let sibling = base.join("sibling");
    let outside_dir = sibling.join("outside");
    fs::create_dir_all(&jail_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create a relative symlink inside jail pointing to ../sibling/outside
    let link_in_jail = jail_dir.join("rel");
    unixfs::symlink("../sibling/outside", &link_in_jail).unwrap();

    let jail: Jail = Jail::try_new(&jail_dir).unwrap();

    let err = jail.systempath_join("rel/escape.txt").unwrap_err();
    match err {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }
}

#[test]
#[cfg(windows)]
fn test_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::windows::fs as winfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let jail_dir = base.join("jail");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&jail_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create symlink inside jail pointing to a directory outside the jail.
    // On Windows this may require Developer Mode or admin; if not available, skip.
    let link_in_jail = jail_dir.join("link");
    if let Err(e) = winfs::symlink_dir(&outside_dir, &link_in_jail) {
        // Permission/privilege issues: skip the test gracefully.
        if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
            return;
        }
        panic!("failed to create symlink: {e:?}");
    }

    let jail: Jail = Jail::try_new(&jail_dir).unwrap();

    let err = jail.systempath_join("link/escape.txt").unwrap_err();
    match err {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }

    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(&jail_dir).unwrap();
    let err2 = vroot.virtualpath_join("link/escape.txt").unwrap_err();
    match err2 {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary via virtual, got {other:?}"),
    }
}

#[test]
#[cfg(windows)]
fn test_junction_escape_is_rejected() {
    use std::fs;
    use std::process::Command;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let jail_dir = base.join("jail");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&jail_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let link_in_jail = jail_dir.join("jlink");
    let status = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link_in_jail.to_string_lossy(),
            &outside_dir.to_string_lossy(),
        ])
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            // Junction creation failed (environment/permissions); skip
            return;
        }
    }

    let jail: Jail = Jail::try_new(&jail_dir).unwrap();

    let err = jail.systempath_join("jlink/escape.txt").unwrap_err();
    match err {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary via junction, got {other:?}"),
    }

    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(&jail_dir).unwrap();
    let err2 = vroot.virtualpath_join("jlink/escape.txt").unwrap_err();
    match err2 {
        crate::JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary via virtual junction, got {other:?}"),
    }
}

#[test]
fn test_toctou_symlink_parent_attack() {
    // TOCTOU = Time-of-Check-Time-of-Use attack
    // Scenario: Path is valid at creation time, but parent becomes malicious symlink later

    let temp = tempfile::tempdir().unwrap();
    let jail_dir = temp.path().join("jail");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&jail_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Step 1: Create legitimate directory structure
    let subdir = jail_dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("file.txt"), "content").unwrap();

    let jail: Jail = Jail::try_new(&jail_dir).unwrap();

    // Step 2: Validate path when structure is legitimate
    let file_path = jail.systempath_join("subdir/file.txt").unwrap();

    // Verify it works initially
    assert!(file_path.exists());
    let initial_parent = file_path.systempath_parent().unwrap();
    assert!(initial_parent.is_some());

    // Step 3: ATTACK - Replace subdir with symlink pointing outside jail
    std::fs::remove_dir_all(&subdir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs as unixfs;
        unixfs::symlink(&outside_dir, &subdir).unwrap();
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs as winfs;
        if let Err(e) = winfs::symlink_dir(&outside_dir, &subdir) {
            // Skip test if we can't create symlinks (insufficient permissions)
            eprintln!("Skipping TOCTOU test - symlink creation failed: {e:?}");
            return;
        }
    }

    // Step 4: Now systempath_parent() should detect the escape and fail
    let parent_result = file_path.systempath_parent();

    match parent_result {
        Err(crate::JailedPathError::PathEscapesBoundary { .. }) => {
            // Expected - parent operation detected symlink escape
        }
        Err(crate::JailedPathError::PathResolutionError { .. }) => {
            // Also acceptable - I/O error during symlink resolution
        }
        Ok(_) => {
            panic!("SECURITY FAILURE: systempath_parent() should have detected symlink escape!");
        }
        Err(other) => {
            panic!("Unexpected error type: {other:?}");
        }
    }
}

#[test]
fn test_toctou_virtual_parent_attack() {
    // Same TOCTOU attack but for VirtualPath

    let temp = tempfile::tempdir().unwrap();
    let jail_dir = temp.path().join("jail");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&jail_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Step 1: Create legitimate directory structure
    let subdir = jail_dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("file.txt"), "content").unwrap();

    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(&jail_dir).unwrap();

    // Step 2: Validate virtual path when structure is legitimate
    let vfile_path = vroot.virtualpath_join("subdir/file.txt").unwrap();

    // Verify it works initially
    assert!(vfile_path.exists());
    let initial_parent = vfile_path.virtualpath_parent().unwrap();
    assert!(initial_parent.is_some());

    // Step 3: ATTACK - Replace subdir with symlink pointing outside jail
    std::fs::remove_dir_all(&subdir).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs as unixfs;
        unixfs::symlink(&outside_dir, &subdir).unwrap();
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs as winfs;
        if let Err(e) = winfs::symlink_dir(&outside_dir, &subdir) {
            // Skip test if we can't create symlinks (insufficient permissions)
            eprintln!("Skipping virtual TOCTOU test - symlink creation failed: {e:?}");
            return;
        }
    }

    // Step 4: Now virtualpath_parent() should detect the escape and fail
    let parent_result = vfile_path.virtualpath_parent();

    match parent_result {
        Err(crate::JailedPathError::PathEscapesBoundary { .. }) => {
            // Expected - parent operation detected symlink escape
        }
        Err(crate::JailedPathError::PathResolutionError { .. }) => {
            // Also acceptable - I/O error during symlink resolution
        }
        Ok(_) => {
            panic!("SECURITY FAILURE: virtualpath_parent() should have detected symlink escape!");
        }
        Err(other) => {
            panic!("Unexpected error type: {other:?}");
        }
    }
}
