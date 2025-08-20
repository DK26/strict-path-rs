use crate::validator::jail::Jail;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Creates cross-platform attack target paths for testing
fn get_attack_target_paths() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        vec![
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "D:\\sensitive\\data.txt",
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "/etc/passwd",
            "/usr/bin/malware",
            "/root/.ssh/authorized_keys",
            "/home/user/secrets.txt",
        ]
    }
}

fn create_test_directory() -> std::io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let temp_base = std::env::temp_dir();

    // Try multiple times with different suffixes to avoid collisions
    for attempt in 0..100 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let temp_dir = temp_base.join(format!(
            "jailed_path_test_{}_{}_{}",
            std::process::id(),
            nanos,
            attempt
        ));

        // Try to create the directory - if it already exists, try again
        match fs::create_dir_all(&temp_dir) {
            Ok(_) => {
                // Successfully created, now set up the test structure
                let sub_dir = temp_dir.join("subdir");
                fs::create_dir(&sub_dir)?;

                // Create a test file in the jail
                let test_file = temp_dir.join("test.txt");
                let mut file = fs::File::create(test_file)?;
                writeln!(file, "test content")?;

                // Create a test file in subdirectory
                let sub_file = sub_dir.join("sub_test.txt");
                let mut file = fs::File::create(sub_file)?;
                writeln!(file, "sub test content")?;

                return Ok(temp_dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Directory already exists, try again with a different name
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    // If we couldn't create a unique directory after 100 attempts, give up
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "Could not create unique test directory after 100 attempts",
    ))
}

fn cleanup_test_directory(path: &std::path::Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

/// Test clamping behavior for jail escape attempts
#[test]
fn test_cleanup_on_jail_escape_attempts_with_clamping_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    // For user-style inputs that require clamping/virtualization, use VirtualRoot
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    let existing_subdir = temp_dir.join("legitimate_user_data");
    std::fs::create_dir(&existing_subdir).unwrap();
    let existing_nested = existing_subdir.join("photos");
    std::fs::create_dir(&existing_nested).unwrap();

    // NEW BEHAVIOR: These paths are clamped, not blocked
    let escape_attempts = vec![
        "legitimate_user_data/photos/../../../../../../../sensitive.txt",
        "legitimate_user_data/new_folder/../../../../../../malware.exe",
        "existing_dir/../../../../../../../secrets.txt",
        "valid/path/../../../../../../../evil.txt",
        "../../../outside_jail/malicious.txt",
        "../../../../config.ini",
    ];

    for escape_attempt in &escape_attempts {
        println!("Testing clamping behavior: {escape_attempt}");
        let result = vroot
            .try_path_virtual(escape_attempt)
            .map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(
            result.is_ok(),
            "Escape attempt should be clamped: {escape_attempt}"
        );
        let jailed_path = result.unwrap();
        // Accept clamped paths that resolve to jail root or its parent
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path.starts_with_real(jail_root),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        // Display should show virtual root (use explicit virtualization)
        let display = format!("{}", jailed_path.virtualize());
        assert!(
            display.starts_with('/'),
            "Should display as virtual root (forward slash): {display}"
        );
        println!("✅ Correctly clamped: {escape_attempt} -> {display}");
    }

    // Verify existing directories are still intact
    assert!(
        existing_subdir.exists(),
        "Existing directory should remain untouched"
    );
    assert!(
        existing_nested.exists(),
        "Existing nested directory should remain untouched"
    );

    println!(
        "✅ Successfully clamped {} escape attempts",
        escape_attempts.len()
    );
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_directory_traversal_attack_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Should block directory traversal attempts
    let traversal_attempts = vec![
        "../../../sensitive.txt",
        "../../..",
        "../outside.txt",
        "subdir/../../outside.txt",
        "subdir/../../../sensitive.txt",
    ];

    for attempt in traversal_attempts {
        let result = vroot.try_path_virtual(attempt).map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(
            result.is_ok(),
            "Traversal attempt should be clamped: {attempt}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path.starts_with_real(jail_root),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Clamped traversal attempt: {attempt} -> {jailed_path}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_absolute_path_outside_jail_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Create another temp directory outside the jail
    let outside_base = std::env::temp_dir();
    let outside_dir = outside_base.join(format!("jailed_path_outside_test_{}", std::process::id()));
    fs::create_dir_all(&outside_dir).expect("Failed to create outside temp directory");
    let outside_file = outside_dir.join("outside.txt");
    fs::File::create(&outside_file).expect("Failed to create outside file");

    // Should succeed (clamped, not blocked)
    let result = vroot
        .try_path_virtual(&outside_file)
        .map(|vp| vp.unvirtual());
    assert!(
        result.is_ok(),
        "Absolute path outside jail should be clamped"
    );
    let jailed_path = result.unwrap();
    let jail_root = temp_dir.canonicalize().unwrap();
    // Use starts_with directly on JailedPath instead of unjailing
    assert!(
        jailed_path.starts_with_real(jail_root),
        "Clamped absolute path should be within jail: {}",
        jailed_path.realpath_to_string()
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
    cleanup_test_directory(&outside_dir);
}

#[test]
fn test_try_path_blocks_traversal_in_nonexistent_paths_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Should block traversal attacks even for non-existent paths
    let traversal_attempts = vec![
        "user/../../../sensitive.txt",
        "photos/../../../../../../malware.exe",
        "docs/../../../secrets.txt",
        "../escape/file.txt",
        "valid/path/../../../config.ini",
    ];

    for attempt in traversal_attempts {
        let result = vroot.try_path_virtual(attempt).map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(
            result.is_ok(),
            "Traversal attempt should be clamped: {attempt}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Clamped traversal attempt: {attempt} -> {jailed_path}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_absolute_nonexistent_path_outside_jail_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Should block absolute paths outside jail, even if they don't exist
    let outside_paths = get_attack_target_paths();

    for path in outside_paths {
        let result = vroot.try_path_virtual(path).map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(result.is_ok(), "Absolute path should be clamped: {path}");
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Clamped absolute path: {path} -> {jailed_path}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_complex_traversal_patterns_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Complex traversal patterns that should all be blocked
    let complex_attacks = vec![
        "../../../sensitive.txt",
        "../../../../config.ini",
        "a/../../../sensitive.txt",
        "a/b/../../../../../../malware.exe",
        "user/../../../../../../secrets.txt",
    ];

    for attack in complex_attacks {
        let result = vroot.try_path_virtual(attack).map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(
            result.is_ok(),
            "Complex traversal attack should be clamped: {attack}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Clamped complex traversal: {attack} -> {jailed_path}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_cleanup_on_jail_escape_attempts_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Create an existing subdirectory structure in the jail
    let existing_subdir = temp_dir.join("legitimate_user_data");
    std::fs::create_dir(&existing_subdir).unwrap();
    let existing_nested = existing_subdir.join("photos");
    std::fs::create_dir(&existing_nested).unwrap();

    // Capture initial state - should have our existing structure
    let initial_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    // Test various jail escape attempts that create directories
    let escape_attempts = vec![
        "legitimate_user_data/photos/../../../../../../../sensitive.txt",
        "legitimate_user_data/new_folder/../../../../../../malware.exe",
        "existing_dir/../../../../../../../secrets.txt",
        "valid/path/../../../../../../../evil.txt",
        "../../../outside_jail/malicious.txt",
        "../../../../config.ini",
    ];

    for escape_attempt in &escape_attempts {
        println!("Testing clamping behavior: {escape_attempt}");
        let result = vroot
            .try_path_virtual(escape_attempt)
            .map(|vp| vp.unvirtual());
        // Should succeed (clamped, not blocked)
        assert!(
            result.is_ok(),
            "Escape attempt should be clamped: {escape_attempt}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        // Display should show virtual root
        let display = format!("{}", jailed_path.virtualize());
        assert!(
            display.starts_with('/'),
            "Should display as virtual root: {display}"
        );
        println!("✅ Correctly clamped: {escape_attempt} -> {display}");
        // Verify existing directories are still intact
        assert!(
            existing_subdir.exists(),
            "Existing directory should remain untouched: {existing_subdir:?}"
        );
        assert!(
            existing_nested.exists(),
            "Existing nested directory should remain untouched: {existing_nested:?}"
        );
    }

    // Final verification - should be back to initial state
    let final_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    assert_eq!(
        initial_entries.len(),
        final_entries.len(),
        "Should be back to initial state after all escape attempts"
    );

    println!(
        "✅ Successfully cleaned up after {} jail escape attempts",
        escape_attempts.len()
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
/// Test attacker path is clamped, not blocked, and resolves to jail root
fn test_attacker_path_clamping_in_existing_directory_virtual() {
    // Use tempfile for unique temp directory
    let temp_dir = TempDir::new().expect("Failed to create unique temp dir");
    let temp_path = temp_dir.path();
    let _jail = Jail::<()>::try_new(temp_path).unwrap();

    // VirtualRoot for user-style clamping behavior
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(temp_path).unwrap();

    // Create existing directory structure (like /home/my_user/import_dir/)
    let import_dir = temp_path.join("import_dir");
    std::fs::create_dir(&import_dir).unwrap();
    let user_data = import_dir.join("user_data");
    std::fs::create_dir(user_data).unwrap();

    // NEW BEHAVIOR: Attack path is clamped, not blocked
    let attack_path =
        "import_dir/user_data/dir_created_by_attacker/another_subdir/../../../../../sensitive.txt";
    println!("Testing attack path: {attack_path}");

    let result = vroot.try_path_virtual(attack_path).map(|vp| vp.unvirtual());
    assert!(result.is_ok(), "Path should be clamped, not blocked");
    let jailed_path = result.unwrap();
    // Accept clamped paths that resolve to jail root or its parent
    let jail_root = temp_path.canonicalize().unwrap();
    // Use starts_with directly on JailedPath instead of unjailing
    assert!(
        jailed_path.starts_with_real(jail_root),
        "Clamped path should be within jail: {}",
        jailed_path.realpath_to_string()
    );
    // Should resolve to something like jail/sensitive.txt (clamped to jail root)
    let expected_suffix = "sensitive.txt";
    assert!(
        jailed_path.ends_with_real(expected_suffix),
        "Should clamp to jail root + filename: {}",
        jailed_path.realpath_to_string()
    );
    // Display should show virtual root
    let display = format!("{}", jailed_path.virtualize());
    assert!(
        display.starts_with('/'),
        "Should display as virtual root path (forward slash): {display}"
    );

    println!("✅ Successfully clamped attack path: {attack_path} -> {display}");
    cleanup_test_directory(temp_dir.path());
}

#[test]
/// Test parent directory navigation is clamped to jail boundary
fn test_parent_directory_navigation_with_clamping_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();

    // NEW BEHAVIOR: .. components are allowed but clamped
    let parent_paths = vec![
        "..",
        "../..",
        "../../..",
        "../../../..",
        "subdir/..",
        "subdir/../..",
        "a/b/c/../../..",
    ];

    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();
    for path in parent_paths {
        let result = vroot.try_path_virtual(path).map(|vp| vp.unvirtual());
        assert!(
            result.is_ok(),
            "Parent navigation should be clamped: {path}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        // Display should show virtual root
        let display = format!("{jailed_path}");
        println!("✅ Clamped parent navigation: {path} -> {display}");
    }

    cleanup_test_directory(&temp_dir);
}

#[test]
/// Test clamping and virtual root for absolute paths and traversal
fn test_absolute_path_clamping_and_virtual_root_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // NEW BEHAVIOR: Absolute paths outside jail are treated as jail-relative
    let outside_absolute_paths = get_attack_target_paths();

    for abs_path in outside_absolute_paths {
        let result = vroot.try_path_virtual(abs_path).map(|vp| vp.unvirtual());
        assert!(
            result.is_ok(),
            "Absolute path should be treated as jail-relative: {abs_path}"
        );
        let jailed_path = result.unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(jailed_path.starts_with_real(vroot.path()));
        // Should show as virtual root path (use VirtualPath for user-facing display)
        let display = format!("{}", jailed_path.virtualize());
        assert!(
            display.starts_with('/'),
            "Should display as virtual root path: {display}"
        );
    }

    // NEW BEHAVIOR: Absolute paths with .. are clamped, not blocked
    let jail_str = temp_dir.to_string_lossy();
    let jail_with_traversal = vec![
        format!("{}/../../../sensitive.txt", jail_str),
        format!("{}/subdir/../../../secrets.txt", jail_str),
        format!("{}/user/../../config.ini", jail_str),
    ];

    for path_with_traversal in jail_with_traversal {
        let result = vroot
            .try_path_virtual(&path_with_traversal)
            .map(|vp| vp.unvirtual());
        assert!(
            result.is_ok(),
            "Path with .. should be clamped, not blocked: {path_with_traversal}"
        );
        let jailed_path = result.unwrap();
        assert!(
            jailed_path.starts_with_real(vroot.path()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Correctly clamped path: {path_with_traversal} -> {jailed_path}");
    }

    cleanup_test_directory(&temp_dir);
}

#[test]
/// Test clamping is fast and secure for malicious paths
fn test_clamping_is_fast_and_secure_virtual() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let _jail = Jail::<()>::try_new(&temp_dir).unwrap();
    let vroot = crate::virtual_root::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // NEW BEHAVIOR: Malicious paths are clamped, not rejected
    let malicious_paths = vec![
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../../root/.ssh/id_rsa",
        "../../../../../../usr/bin/sh",
        "../../../Windows/System32/config/SAM",
        "subdir/../../../sensitive.txt",
    ];

    for malicious_path in malicious_paths {
        let result = vroot
            .try_path_virtual(malicious_path)
            .map(|vp| vp.unvirtual());
        assert!(
            result.is_ok(),
            "Malicious path should be clamped: {malicious_path}"
        );
        let jailed_path = result.unwrap();
        let jail_root = temp_dir.canonicalize().unwrap();
        // Use starts_with directly on JailedPath instead of unjailing
        assert!(
            jailed_path
                .realpath_to_string()
                .starts_with(jail_root.to_string_lossy().as_ref()),
            "Clamped path should be within jail: {}",
            jailed_path.realpath_to_string()
        );
        println!("✅ Securely clamped: {malicious_path} -> {jailed_path}");
    }

    cleanup_test_directory(&temp_dir);
}
