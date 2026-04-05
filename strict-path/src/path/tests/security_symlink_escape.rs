// Tests for symlink and junction escape detection/clamping, TOCTOU attacks,
// and archive extraction (zip/tar slip) scenarios.

#[cfg(feature = "virtual-path")]
use crate::PathBoundary;
#[cfg(all(feature = "virtual-path", unix))]
use crate::VirtualRoot;

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
            "Virtual path should be clamped within virtual root. Got: {check_canonical:?}, Expected to start with: {restriction_canonical:?}"
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
        "Junction target should be clamped within virtual root. Got: {system_path:?}, Expected within: {vroot_canonical:?}"
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
                "Parent should be clamped within virtual root. Got: {parent_system:?}, Expected to start with: {canonical_restriction:?}"
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
