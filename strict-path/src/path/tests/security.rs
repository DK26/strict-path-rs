#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
#[cfg(feature = "virtual-path")]
use crate::{PathBoundary, StrictPathError};
#[cfg(feature = "virtual-path")]
use std::path::{Component, Path};
#[cfg(feature = "virtual-path")]
use std::sync::Arc;
#[cfg(feature = "virtual-path")]
use std::thread;

#[cfg(feature = "virtual-path")]
#[test]
fn test_known_cve_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();

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
        let candidate = Path::new(pattern);
        let has_parent = candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir));
        let looks_like_scheme = pattern.starts_with("file://");
        let is_absolute = candidate.is_absolute();
        let looks_absolute = is_absolute || looks_like_scheme;
        let should_succeed_strict = !has_parent && !looks_absolute;

        match restriction.strict_join(pattern) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Attack pattern '{pattern}' escaped restriction: {validated_path:?}"
                );
            }
            Err(err) => {
                if should_succeed_strict {
                    panic!("strict_join rejected '{pattern}': {err:?}");
                }
                match err {
                    StrictPathError::PathEscapesBoundary { .. }
                    | StrictPathError::PathResolutionError { .. } => {}
                    other => panic!("Unexpected error variant for pattern '{pattern}': {other:?}"),
                }
            }
        }

        match vroot.virtual_join(pattern) {
            Ok(virtual_path) => {
                assert!(
                    virtual_path
                        .as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()),
                    "Virtual join for '{pattern}' escaped restriction"
                );

                let display = virtual_path.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display must be rooted for '{pattern}': {display}"
                );

                if has_parent || looks_absolute {
                    let has_parent_segment = display.split('/').any(|segment| segment == "..");
                    assert!(
                        !has_parent_segment,
                        "Virtual display leaked parent segments for '{pattern}': {display}"
                    );
                }
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                assert!(
                    looks_absolute,
                    "Unexpected virtual_join failure for pattern '{pattern}'"
                );
            }
            Err(other) => panic!("Unexpected virtual_join error for '{pattern}': {other:?}"),
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

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
        match restriction.strict_join(pattern) {
            Ok(validated_path) => {
                assert!(validated_path.strictpath_starts_with(restriction.interop_path()));
            }
            Err(_e) => {
                // Rejections are acceptable; test ensures no panics and no escapes
            }
        }
    }
}

// Unicode normalization: both NFC and NFD forms should remain contained.
#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_normalization_forms_are_contained() {
    let td = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(td.path()).unwrap();

    // "café" in NFC and NFD
    let nfc = "café/report.txt"; // U+00E9
    let nfd = "cafe\u{0301}/report.txt"; // 'e' + COMBINING ACUTE

    for inp in [nfc, nfd] {
        let jp = restriction.strict_join(inp).unwrap();
        assert!(jp.strictpath_starts_with(restriction.interop_path()));

        let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();
        let vp = vroot.virtual_join(inp).unwrap();
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        // Virtual display is rooted and forward slashed
        let vdisp = vp.virtualpath_display().to_string();
        assert!(vdisp.starts_with('/'));
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_concurrent_validator_usage() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: Arc<PathBoundary> = Arc::new(PathBoundary::try_new(temp.path()).unwrap());
    let mut handles = vec![];

    for i in 0..5 {
        let restriction_clone = Arc::clone(&restriction);
        let handle = thread::spawn(move || {
            for j in 0..50 {
                let path = format!("thread_{i}/file_{j}.txt");
                let result = restriction_clone.strict_join(&path);
                assert!(result.is_ok(), "Thread {i} iteration {j} failed");

                let validated_path = result.unwrap();
                // Test the actual path containment (what we really care about)
                assert!(validated_path.strictpath_starts_with(restriction_clone.interop_path()));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_long_path_handling() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let long_component = "a".repeat(64);
    let long_path = format!("{long_component}/{long_component}/{long_component}/{long_component}",);

    let validated_path = restriction
        .strict_join(&long_path)
        .unwrap_or_else(|err| panic!("long path should be accepted: {err:?}"));
    assert!(validated_path.strictpath_starts_with(restriction.interop_path()));

    let traversal_attack = "../".repeat(10) + "etc/passwd";
    let err = restriction
        .strict_join(&traversal_attack)
        .expect_err("traversal should be rejected by strict_join");
    match err {
        StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Unexpected error for traversal attack '{traversal_attack}': {other:?}"),
    }

    let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();
    let virtual_path = vroot
        .virtual_join(&traversal_attack)
        .unwrap_or_else(|err| panic!("virtual join should clamp traversal: {err:?}"));
    let expected_path = "/etc/passwd".to_string();
    assert_eq!(
        virtual_path.virtualpath_display().to_string(),
        expected_path
    );
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

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
        let candidate = Path::new(pattern);
        let is_absolute = candidate.is_absolute();

        let result = restriction.strict_join(pattern);
        if is_absolute {
            let err = result.expect_err("strict_join must reject absolute Windows escape patterns");
            match err {
                StrictPathError::PathEscapesBoundary { .. } => {}
                other => {
                    panic!("Unexpected error variant for absolute pattern '{pattern}': {other:?}")
                }
            }
            continue;
        }

        match result {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Pattern '{pattern}' escaped restriction"
                );
            }
            Err(StrictPathError::PathResolutionError { .. }) => {
                // Reserved device names and ADS forms may fail resolution on some systems.
            }
            Err(other) => panic!("Unexpected error for Windows pattern '{pattern}': {other:?}"),
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&restriction_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create symlink inside PathBoundary pointing to a directory outside the PathBoundary
    let link_in_restriction = restriction_dir.join("link");
    unixfs::symlink(&outside_dir, &link_in_restriction).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to validate a path that goes through the symlink to outside
    let err = restriction.strict_join("link/escape.txt").unwrap_err();
    match err {
        crate::StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }

    // VirtualRoot should CLAMP the symlink target to virtual root (new behavior in 0.4.0)
    let vroot: VirtualRoot = VirtualRoot::try_new(&restriction_dir).unwrap();
    let clamped = vroot
        .virtual_join("link/escape.txt")
        .expect("Virtual paths should clamp symlink targets to virtual root");

    // Verify the path is clamped within the virtual root
    // Canonicalize both paths for comparison (macOS has /var -> /private/var symlink)
    let clamped_system = clamped.interop_path();
    let canonical_restriction = fs::canonicalize(&restriction_dir).unwrap();
    assert!(
        AsRef::<std::path::Path>::as_ref(clamped_system).starts_with(&canonical_restriction),
        "Virtual path should be clamped within virtual root. Got: {:?}, Expected to start with: {:?}",
        clamped_system,
        canonical_restriction
    );
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_relative_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let sibling = base.join("sibling");
    let outside_dir = sibling.join("outside");
    fs::create_dir_all(&restriction_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create a relative symlink inside PathBoundary pointing to ../sibling/outside
    let link_in_restriction = restriction_dir.join("rel");
    unixfs::symlink("../sibling/outside", &link_in_restriction).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    let err = restriction.strict_join("rel/escape.txt").unwrap_err();
    match err {
        crate::StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_symlink_escape_is_rejected() {
    use std::fs;
    use std::os::windows::fs as winfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    // Create directories and canonicalize to resolve Windows short names (8.3)
    let restriction_dir = {
        let p = base.join("PathBoundary");
        fs::create_dir_all(&p).unwrap();
        fs::canonicalize(&p).unwrap()
    };
    let outside_dir = {
        let p = base.join("outside");
        fs::create_dir_all(&p).unwrap();
        fs::canonicalize(&p).unwrap()
    };

    // Create symlink inside PathBoundary pointing to a directory outside the restriction.
    // On Windows this may require Developer Mode or admin; if not available, skip.
    let link_in_restriction = restriction_dir.join("link");
    if let Err(e) = winfs::symlink_dir(&outside_dir, &link_in_restriction) {
        // Permission/privilege issues: skip the test gracefully.
        if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(1314) {
            return;
        }
        panic!("failed to create symlink: {e:?}");
    }

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to validate a path that goes through the symlink to outside
    let err = restriction.strict_join("link/escape.txt").unwrap_err();
    match err {
        crate::StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary, got {other:?}"),
    }

    // VirtualRoot should CLAMP the symlink target to virtual root (new behavior in 0.4.0)
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();
    let clamped = vroot.virtual_join("link/escape.txt").unwrap();

    // Verify the path is clamped within the virtual root
    // Since escape.txt doesn't exist, we need to find the deepest existing ancestor
    let clamped_path = clamped.as_unvirtual().interop_path();
    let mut check_path = std::path::PathBuf::from(clamped_path);

    // Walk up until we find an existing path
    while !check_path.exists() && check_path.pop() {
        // Keep popping until we find something that exists
    }

    if check_path.exists() {
        let check_canonical = fs::canonicalize(&check_path).unwrap();
        let restriction_canonical = fs::canonicalize(&restriction_dir).unwrap();
        assert!(
            check_canonical.starts_with(&restriction_canonical),
            "Virtual path should be clamped within virtual root. Got: {:?}, Expected to start with: {:?}",
            check_canonical,
            restriction_canonical
        );
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_junction_escape_is_rejected() {
    use std::fs;
    use std::process::Command;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&restriction_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let link_in_restriction = restriction_dir.join("jlink");
    let status = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link_in_restriction.to_string_lossy(),
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

    // StrictPath: System filesystem semantics - junction should be rejected
    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();
    let err = restriction.strict_join("jlink/escape.txt").unwrap_err();
    match err {
        crate::StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Expected PathEscapesBoundary via junction, got {other:?}"),
    }

    // VirtualPath: Virtual filesystem semantics - junction target is CLAMPED (v0.4.0 behavior)
    // The junction target /outside/escape.txt is reinterpreted as vroot/outside/escape.txt
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();
    let clamped = vroot
        .virtual_join("jlink/escape.txt")
        .expect("VirtualPath should clamp junction target to virtual root");

    // Verify the junction was clamped within virtual root
    let system_path = clamped.interop_path();
    let vroot_canonical = std::fs::canonicalize(&restriction_dir).unwrap();
    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&vroot_canonical),
        "Junction target should be clamped within virtual root. Got: {:?}, Expected within: {:?}",
        system_path,
        vroot_canonical
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_toctou_symlink_parent_attack() {
    // TOCTOU = Time-of-Check-Time-of-Use attack
    // Scenario: Path is valid at creation time, but parent becomes malicious symlink later

    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path().join("PathBoundary");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Step 1: Create legitimate directory structure
    let subdir = restriction_dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("file.txt"), "content").unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Step 2: Validate path when structure is legitimate
    let file_path = restriction.strict_join("subdir/file.txt").unwrap();

    // Verify it works initially
    assert!(file_path.exists());
    let initial_parent = file_path.strictpath_parent().unwrap();
    assert!(initial_parent.is_some());

    // Step 3: ATTACK - Replace subdir with symlink pointing outside PathBoundary
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

    // Step 4: Now strictpath_parent() should detect the escape and fail
    let parent_result = file_path.strictpath_parent();

    match parent_result {
        Err(crate::StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected - parent operation detected symlink escape
        }
        Err(crate::StrictPathError::PathResolutionError { .. }) => {
            // Also acceptable - I/O error during symlink resolution
        }
        Ok(_) => {
            panic!("SECURITY FAILURE: strictpath_parent() should have detected symlink escape!");
        }
        Err(other) => {
            panic!("Unexpected error type: {other:?}");
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_toctou_virtual_parent_attack() {
    // Same TOCTOU attack but for VirtualPath

    let temp = tempfile::tempdir().unwrap();
    let restriction_dir = temp.path().join("PathBoundary");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Step 1: Create legitimate directory structure
    let subdir = restriction_dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    std::fs::write(subdir.join("file.txt"), "content").unwrap();

    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Step 2: Validate virtual path when structure is legitimate
    let vfile_path = vroot.virtual_join("subdir/file.txt").unwrap();

    // Verify it works initially
    assert!(vfile_path.exists());
    let initial_parent = vfile_path.virtualpath_parent().unwrap();
    assert!(initial_parent.is_some());

    // Step 3: ATTACK - Replace subdir with symlink pointing outside PathBoundary
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

    // Step 4: With clamping behavior (soft-canonicalize 0.4.0), virtualpath_parent()
    // should CLAMP the symlink target to virtual root instead of rejecting
    let parent_result = vfile_path.virtualpath_parent();

    match parent_result {
        Ok(Some(parent)) => {
            // New expected behavior: parent is clamped within virtual root
            // Canonicalize both paths for comparison (macOS has /var -> /private/var symlink)
            let parent_system = parent.interop_path();
            let canonical_restriction = std::fs::canonicalize(&restriction_dir).unwrap();
            assert!(
                AsRef::<std::path::Path>::as_ref(parent_system).starts_with(&canonical_restriction),
                "Parent should be clamped within virtual root. Got: {:?}, Expected to start with: {:?}",
                parent_system,
                canonical_restriction
            );
        }
        Err(crate::StrictPathError::PathResolutionError { .. }) => {
            // Also acceptable - I/O error during symlink resolution
        }
        Ok(None) => {
            panic!("SECURITY FAILURE: virtualpath_parent() returned None unexpectedly!");
        }
        Err(other) => {
            panic!("Unexpected error type: {other:?}");
        }
    }
}

// Black-box: Simulate a Zip Slip-style extraction routine using VirtualRoot
// to map archive entry names to safe jailed paths. Ensure traversal-style
// entries are rejected and nothing is written outside the restriction.
#[cfg(feature = "virtual-path")]
#[test]
fn test_zip_slip_style_extraction() {
    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();

    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Candidate archive entries (mix of valid and malicious)
    let mut entries = vec![
        ("ok/file.txt", true),
        ("nested/dir/ok2.bin", true),
        ("../escape.txt", true),
        ("../../outside/evil.txt", true),
        ("/abs/should/fail", true),
        ("..\\..\\win\\escape.txt", true),
    ];
    // On Windows, absolute and drive-relative inputs are treated as virtual-rooted
    // requests, thus should succeed while staying inside the restriction.
    if cfg!(windows) {
        entries.push(("C:..\\Windows\\win.ini", true));
        entries.push(("C:\\Windows\\win.ini", true));
    }

    for (name, should_succeed) in entries {
        let res = vroot.virtual_join(name);
        match res {
            Ok(vp) => {
                if should_succeed {
                    // Simulate extraction: ensure parents and write
                    vp.create_parent_dir_all().unwrap();
                    vp.write("data").unwrap();
                    assert!(vp.exists());
                    // Ensure the resolved system path lives under PathBoundary
                    // Compare against the canonical PathBoundary path to avoid Windows verbatim prefix issues
                    assert!(vp
                        .as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()));
                } else {
                    panic!(
                        "Expected rejection for '{name}', but joined to {}",
                        vp.as_unvirtual().strictpath_to_string_lossy()
                    );
                }
            }
            Err(e) => {
                if should_succeed {
                    panic!("Expected success for '{name}', got {e:?}");
                }
                // For should_succeed == false: any error is an acceptable rejection
            }
        }
    }

    // Sanity: no files created outside PathBoundary
    assert!(!base.join("escape.txt").exists());
    assert!(!base.join("outside/evil.txt").exists());
}

// TAR-like extraction semantics: handle ./, leading /, and deep ../ entries.
#[cfg(feature = "virtual-path")]
#[test]
fn test_tar_slip_style_extraction() {
    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();

    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    let entries = vec![
        ("./ok.txt", true),
        ("./nested/./dir/file.bin", true),
        ("/abs/should/not/escape", true),
        ("../../outside/evil.txt", true),
        ("./../sneaky", true),
    ];

    for (name, should_succeed) in entries {
        match vroot.virtual_join(name) {
            Ok(vp) => {
                if should_succeed {
                    vp.create_parent_dir_all().unwrap();
                    vp.write("data").unwrap();
                    assert!(vp
                        .as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()));
                } else {
                    panic!("unexpected success for {name}");
                }
            }
            Err(e) => {
                if should_succeed {
                    panic!("expected success for {name}, got {e:?}");
                }
            }
        }
    }

    // Sanity: nothing outside base was written
    assert!(!base.join("outside/evil.txt").exists());
}

// White-box: Windows namespace escapes should be rejected by virtual join.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_unc_and_verbatim_escape_rejected() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Treat these as virtual-rooted requests; ensure the result stays inside the restriction.
    let cases = vec![
        "\\\\server\\share\\sensitive.txt",
        "\\\\?\\C:\\Windows\\System32\\config\\SAM",
        "\\\\.\\PhysicalDrive0\\nul",
    ];

    for b in cases {
        let vp = vroot
            .virtual_join(b)
            .expect("absolute/namespace input should be clamped to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

// White-box: Windows drive-relative paths (e.g., "C:..\\foo") must not enable escape.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_drive_relative_rejected() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Drive-relative forms must not escape; we clamp and allow inside the restriction.
    let candidates = vec!["C:..\\Windows", "D:..\\..\\temp\\file.txt"];
    for c in candidates {
        let vp = vroot
            .virtual_join(c)
            .expect("drive-relative input should be clamped to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

// White-box: Hard-link behavior demonstration (expected limitation).
// If a hard link inside the PathBoundary points to a file outside, writes will
// affect the outside target. This test documents the behavior.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_hard_link_inside_to_outside_documents_limitation() {
    use std::fs::hard_link;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Prepare an outside target file
    let outside_file = outside_dir.join("target.txt");
    std::fs::write(&outside_file, b"original").unwrap();

    // Place a hard link to it inside the PathBoundary
    let inside_link = restriction_dir.join("alias.txt");
    hard_link(&outside_file, &inside_link).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();
    let vp = restriction
        .clone()
        .virtualize()
        .virtual_join("alias.txt")
        .expect("join should succeed within PathBoundary");

    // Write via jailed API
    vp.write("modified").unwrap();

    // Outside file reflects the change (documented limitation)
    let out = std::fs::read_to_string(&outside_file).unwrap();
    assert_eq!(out, "modified");

    // Still, the path is inside the PathBoundary from a path-boundary perspective
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(restriction.interop_path()));
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_mixed_separators_and_encoded_inputs() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // These are odd strings a user/attacker might pass in
    // Mixed separators and encoded inputs; display is always forward-slashed.
    // The first case differs by platform: on Windows, backslash is a separator; on Unix, it's a character.
    let mut cases = vec![
        ("a//b////c", "/a/b/c"),
        ("./././d", "/d"),
        ("b/%2e%2e/c", "/b/%2e%2e/c"), // percent-encoded is not decoded by us
        ("\u{202E}rtl.txt", "/\u{202E}rtl.txt"),
    ];
    if cfg!(windows) {
        cases.insert(0, ("a\\b/../c.txt", "/a/c.txt"));
    } else {
        cases.insert(0, ("a\\b/../c.txt", "/c.txt"));
    }

    for (inp, expected_prefix) in cases {
        let vp = vroot
            .virtual_join(inp)
            .expect("join should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        let vdisp = format!("{}", vp.virtualpath_display());
        assert!(vdisp.starts_with(expected_prefix), "{inp} => {vdisp}");
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_non_utf8_component_handling() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Make a non-UTF8 name like b"bad\xFFname"
    let raw = OsStr::from_bytes(b"bad\xFFname");
    let vp = vroot
        .virtual_join(raw)
        .expect("non-utf8 should be acceptable at Path level");
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_super_deep_traversal_clamps_to_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(td.path()).unwrap();

    // Lots of parent components should clamp to virtual root
    let deep = "../".repeat(50) + "a/b";
    let vp = vroot
        .virtual_join(&deep)
        .expect("deep traversal should clamp");
    assert_eq!(vp.virtualpath_display().to_string(), "/a/b");
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_trailing_dots_spaces() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Windows normalizes trailing dots/spaces at FS layer; we only ensure clamping
    let cases = vec!["dir.\\file.", "dir \\file ", "con.\\nul "];

    for c in cases {
        let vp = vroot.virtual_join(c).expect("should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_ads_and_reserved_names() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // We don't try to write these; just ensure containment or clean error.
    let cases = vec![
        "file.txt:stream",
        "file.txt::$DATA",
        "CON",
        "NUL",
        "AUX",
        "COM1",
        "LPT1",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => assert!(vp
                .as_unvirtual()
                .strictpath_starts_with(vroot.interop_path())),
            Err(_e) => { /* acceptable: rejected safely */ }
        }
    }
}

// White-box: Windows NT path prefix variants should be clamped to the restriction.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_nt_prefix_variants_clamped() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    let cases = vec![
        r"\\??\\C:\\Windows\\System32\\config\\SAM",
        r"\\??\\UNC\\server\\share\\sensitive.txt",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => {
                assert!(vp
                    .as_unvirtual()
                    .strictpath_starts_with(vroot.interop_path()));
                // Virtual display remains rooted and forward-slashed.
                let v = vp.virtualpath_display().to_string();
                assert!(v.starts_with('/'));
                assert!(!v.contains("\\\\??\\\\"));
            }
            Err(_e) => {
                // Clean rejection is acceptable
            }
        }
    }
}

// Black-box: Unicode dot lookalikes should not be treated as traversal; ensure clamping.
#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_dot_lookalike_does_not_traverse() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // U+2024 (One Dot Leader) and U+FF0E (Fullwidth Full Stop)
    let cases = vec![
        (
            "dir/\u{2024}\u{2024}/file.txt".to_string(),
            "/dir/\u{2024}\u{2024}/file.txt".to_string(),
        ),
        (
            "dir/\u{FF0E}\u{FF0E}/file.txt".to_string(),
            "/dir/\u{FF0E}\u{FF0E}/file.txt".to_string(),
        ),
    ];

    for (inp, expected_virtual_prefix) in cases {
        let vp = vroot
            .virtual_join(&inp)
            .expect("join should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        let vdisp = vp.virtualpath_display().to_string();
        assert!(
            vdisp.starts_with(&expected_virtual_prefix),
            "{inp} => {vdisp}"
        );
    }
}

// White-box: Embedded NUL should not enable escapes. We don't perform I/O here.
#[cfg(feature = "virtual-path")]
#[test]
fn test_embedded_nulls_are_not_exploitable() {
    use std::ffi::{OsStr, OsString};

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Construct an OsString with an embedded NUL in a platform-portable way
    // On Rust, OsString can hold a NUL; any filesystem I/O may fail, so we avoid I/O.
    let mut s = OsString::from("prefix");
    s.push(OsStr::new("\u{0000}"));
    s.push(OsStr::new("suffix.txt"));

    match vroot.virtual_join(&s) {
        Ok(vp) => {
            assert!(vp
                .as_unvirtual()
                .strictpath_starts_with(vroot.interop_path()));
            // Do not attempt to write/read; just ensure virtual view is rooted
            let vdisp = vp.virtualpath_display().to_string();
            assert!(vdisp.starts_with('/'));
        }
        Err(_e) => {
            // Acceptable: embedded NUL rejected safely
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_winrar_ads_traversal_payload_is_clamped() {
    // Simulate the CVE-2025-8088-like payload: an ADS stream name with traversal
    // e.g., "decoy.txt:..\\..\\evil.exe". Ensure it cannot escape the PathBoundary and
    // does not create files outside the restriction. If ADS is unsupported, we accept
    // a clean error, but still verify no escape occurred.

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Ensure the decoy file exists (ADS writes typically require the base file)
    let decoy = vroot.virtual_join("decoy.txt").expect("join decoy");
    decoy.write("decoy").unwrap();

    // The malicious entry name used by attackers
    let payload = "decoy.txt:..\\..\\evil.exe";
    let vp = vroot
        .virtual_join(payload)
        .expect("ADS payload should be clamped to PathBoundary");

    // Must remain within the PathBoundary from a system path perspective
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));

    // Attempt to write the payload; on NTFS this writes an ADS on decoy.txt.
    // On filesystems without ADS support this may error; both outcomes are acceptable
    // as long as no file is created outside the restriction.
    match vp.write("malware-bytes") {
        Ok(()) => {
            // Optional: attempt to read the ADS back to confirm write stayed attached to decoy
            let read_back = vp.read_to_string();
            if let Ok(contents) = read_back {
                assert_eq!(contents, "malware-bytes");
            }
        }
        Err(_e) => {
            // Acceptable on filesystems without ADS support
        }
    }

    // Critical assertion: no file named 'evil.exe' appears outside the PathBoundary
    assert!(!outside_dir.join("evil.exe").exists());
    assert!(!base.join("evil.exe").exists());

    // And nothing escaped to the filesystem root of the temp hierarchy either
    assert!(!restriction_dir.join("..\\evil.exe").exists());

    // The virtual display should remain rooted and not contain raw drive paths
    let vdisp = vp.virtualpath_display().to_string();
    assert!(
        vdisp.starts_with('/'),
        "virtual path must be rooted: {vdisp}"
    );
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_winrar_like_edge_cases() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // WinRAR-adjacent tricky names: ensure clamping or safe rejection.
    let cases: &[&str] = &[
        // Device/global roots and odd prefixes
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\hosts",
        // Forward-slash drive and single-leading-backslash (absolute on Windows)
        "C:/Windows/System32/config/SAM",
        "\\Windows\\System32\\drivers\\etc\\hosts",
        // UNC with double forward slashes
        "//server/share/boot.ini",
        // Startup-like and ProgramData-like targets (social engineering payloads)
        "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/payload.lnk",
        "ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/payload.vbs",
        // Deep traversal mixed with separators
        "..\\..//Windows/../Temp/evil.dll",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => {
                assert!(
                    vp.as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()),
                    "escaped PathBoundary for input: {c} -> {}",
                    vp.as_unvirtual().strictpath_to_string_lossy()
                );
                // Nothing should point to real system locations; it's virtual-rooted
                let v = vp.virtualpath_display().to_string();
                assert!(v.starts_with('/'), "virtual must be rooted: {v}");
            }
            Err(_e) => {
                // Clean rejection also acceptable; key is no escape.
            }
        }
    }

    // Also validate that creating parents stays inside the PathBoundary when allowed
    let ok = "ProgramData/MyApp/Updates/update.bin";
    let vp = vroot.virtual_join(ok).expect("should clamp");
    vp.create_parent_dir_all().expect("create parents");
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));
}
// ============================================================
// I/O Security Tests for append(), write(), create_file(), open_file()
// ============================================================

/// Security test: append() through a symlink pointing outside boundary should be blocked.
/// The symlink resolution during strict_join must detect the escape.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_append_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file that attacker wants to modify
    let outside_file = outside_dir.join("sensitive.log");
    std::fs::write(&outside_file, "original content\n").unwrap();

    // Create symlink inside boundary pointing to outside file
    let link_inside = restriction_dir.join("log.txt");
    unixfs::symlink(&outside_file, &link_inside).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path containing the symlink - should detect escape
    let result = boundary.strict_join("log.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected during join
        }
        Ok(strict_path) => {
            // If join succeeded (shouldn't with proper symlink resolution),
            // verify append would still be safe
            let append_result = strict_path.append("malicious log entry\n");
            if append_result.is_ok() {
                let outside_content = std::fs::read_to_string(&outside_file).unwrap();
                assert_eq!(
                    outside_content, "original content\n",
                    "SECURITY FAILURE: append() modified file outside boundary via symlink"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify outside file was not modified
    let final_content = std::fs::read_to_string(&outside_file).unwrap();
    assert_eq!(
        final_content, "original content\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: create_file() through a symlink directory pointing outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_create_file_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create symlink inside boundary pointing to outside directory
    let link_to_outside = restriction_dir.join("escape_dir");
    unixfs::symlink(&outside_dir, &link_to_outside).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path through the symlink
    let result = boundary.strict_join("escape_dir/new_file.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, create_file should still be safe
            let create_result = strict_path.create_file();
            if create_result.is_ok() {
                assert!(
                    !outside_dir.join("new_file.txt").exists(),
                    "SECURITY FAILURE: create_file() created file outside boundary"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify no file was created outside
    assert!(
        !outside_dir.join("new_file.txt").exists(),
        "No file should be created outside boundary"
    );
}

/// Security test: open_file() through a symlink pointing to sensitive file outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_open_file_through_symlink_escape_is_blocked() {
    use std::io::Read;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create sensitive file outside boundary
    let sensitive_file = outside_dir.join("secrets.txt");
    std::fs::write(&sensitive_file, "API_KEY=supersecret123").unwrap();

    // Create symlink inside boundary pointing to sensitive file
    let link_inside = restriction_dir.join("config.txt");
    unixfs::symlink(&sensitive_file, &link_inside).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path to the symlink
    let result = boundary.strict_join("config.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, open_file should be blocked or return safe content
            match strict_path.open_file() {
                Ok(mut file) => {
                    let mut contents = String::new();
                    let _ = file.read_to_string(&mut contents);
                    assert!(
                        !contents.contains("supersecret123"),
                        "SECURITY FAILURE: open_file() leaked sensitive data via symlink"
                    );
                }
                Err(_) => {
                    // I/O error is acceptable
                }
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }
}

/// Security test: write() through a preexisting malicious symlink should be blocked.
/// This simulates a poisoned filesystem scenario (e.g., after vulnerable archive extraction).
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_write_through_preexisting_malicious_symlink() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create original outside file
    let target_outside = outside_dir.join("important.cfg");
    std::fs::write(&target_outside, "original config\n").unwrap();

    // Simulate poisoned filesystem: symlink already exists inside boundary
    let poison_link = restriction_dir.join("config.cfg");
    unixfs::symlink(&target_outside, &poison_link).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Try to write through the poisoned symlink
    let join_result = boundary.strict_join("config.cfg");

    match join_result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: escape detected via symlink resolution
        }
        Ok(strict_path) => {
            // If join succeeded, write must not affect outside file
            let write_result = strict_path.write("malicious config\n");
            if write_result.is_ok() {
                let outside_content = std::fs::read_to_string(&target_outside).unwrap();
                assert_eq!(
                    outside_content, "original config\n",
                    "SECURITY FAILURE: write() modified file outside boundary via symlink"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Final verification
    let final_content = std::fs::read_to_string(&target_outside).unwrap();
    assert_eq!(
        final_content, "original config\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: VirtualPath append() through symlink escape should be clamped.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_virtual_append_through_symlink_clamps_or_blocks() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let vroot_dir = base.join("vroot");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&vroot_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file
    let outside_log = outside_dir.join("system.log");
    std::fs::write(&outside_log, "system log\n").unwrap();

    // Create symlink inside vroot pointing outside
    let link_inside = vroot_dir.join("user.log");
    unixfs::symlink(&outside_log, &link_inside).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&vroot_dir).unwrap();

    // VirtualPath should either block the symlink escape or clamp it
    match vroot.virtual_join("user.log") {
        Ok(vpath) => {
            // If join succeeded (after clamping), append should not modify outside file
            let _ = vpath.append("user content\n");
            let outside_content = std::fs::read_to_string(&outside_log).unwrap();
            assert_eq!(
                outside_content, "system log\n",
                "VirtualPath must not allow writes outside virtual root"
            );
        }
        Err(_) => {
            // Rejection is also acceptable
        }
    }
}

/// Security test for Windows: append() through junction pointing outside should be blocked.
#[cfg(feature = "virtual-path")]
#[cfg(feature = "junctions")]
#[test]
#[cfg(windows)]
fn test_append_through_junction_escape_is_blocked() {
    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file that attacker wants to modify
    let outside_file = outside_dir.join("sensitive.log");
    std::fs::write(&outside_file, "original content\n").unwrap();

    // Create junction inside boundary pointing to outside directory
    let junction_inside = restriction_dir.join("escape");
    junction_verbatim::create(&outside_dir, &junction_inside).expect("junction creation");

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path through the junction
    let result = boundary.strict_join("escape/sensitive.log");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: junction escape detected during join
        }
        Ok(strict_path) => {
            // If join succeeded, verify append would still be safe
            let append_result = strict_path.append("malicious log entry\n");
            if append_result.is_ok() {
                let outside_content = std::fs::read_to_string(&outside_file).unwrap();
                assert_eq!(
                    outside_content, "original content\n",
                    "SECURITY FAILURE: append() modified file outside boundary via junction"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify outside file was not modified
    let final_content = std::fs::read_to_string(&outside_file).unwrap();
    assert_eq!(
        final_content, "original content\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: read() through symlink pointing to sensitive file outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_read_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create sensitive file outside boundary
    let sensitive_file = outside_dir.join("passwd");
    std::fs::write(&sensitive_file, "root:x:0:0:root:/root:/bin/bash").unwrap();

    // Create symlink inside boundary pointing to sensitive file
    let link_inside = restriction_dir.join("data.txt");
    unixfs::symlink(&sensitive_file, &link_inside).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path to the symlink
    let result = boundary.strict_join("data.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, read must not leak sensitive data
            match strict_path.read_to_string() {
                Ok(contents) => {
                    assert!(
                        !contents.contains("root:x:0:0"),
                        "SECURITY FAILURE: read() leaked sensitive data via symlink"
                    );
                }
                Err(_) => {
                    // I/O error is acceptable
                }
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }
}
