#[cfg(unix)]
use crate::Jail;
use crate::VirtualRoot;
use std::fs;
use std::io::Write;

fn create_test_directory() -> std::io::Result<std::path::PathBuf> {
    // Use the tempfile crate to create a unique temporary directory. Call
    // `keep()` to persist the directory across the test and delete it
    // manually via `cleanup_test_directory` to keep behavior consistent.
    // Create the TempDir first, then call `keep()` and propagate any IO error
    // while ensuring the success case yields a `PathBuf` that we can return.
    let td = tempfile::tempdir()?;
    // In this version of `tempfile`, `TempDir::keep()` returns a `PathBuf`.
    // Use it directly to obtain the persisted directory path.
    let temp_dir = td.keep();

    // Create a subdirectory structure for testing
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

    Ok(temp_dir)
}

fn cleanup_test_directory(path: &std::path::Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn test_virtual_root_display_functionality() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Test various paths to ensure virtual root display works correctly
    let test_cases = vec![
        ("file.txt", "/file.txt".to_string()),
        ("subdir/file.txt", "/subdir/file.txt".to_string()),
        (
            "users/alice/documents/report.pdf",
            "/users/alice/documents/report.pdf".to_string(),
        ),
        (
            "deeply/nested/path/structure/file.log",
            "/deeply/nested/path/structure/file.log".to_string(),
        ),
    ];

    for (input_path, expected_display) in test_cases {
        let result = vroot.try_path_virtual(input_path);
        assert!(
            result.is_ok(),
            "Path validation should succeed for: {input_path}"
        );

        let virtual_path = result.unwrap();

        // Test Display trait - should show virtual root (relative to jail)
        let display_output = format!("{virtual_path}");
        assert_eq!(
            display_output, expected_display,
            "Display should show virtual root for path: {input_path} (forward slashes)"
        );
        // Should always start with forward slash
        assert!(
            display_output.starts_with('/') || display_output.starts_with('\u{5C}'),
            "Virtual root display should start with forward slash: {display_output}"
        );

        // Verify it doesn't contain the actual jail path
        let jail_str = temp_dir.to_string_lossy();
        assert!(
            !display_output.contains(&*jail_str),
            "Virtual root display should not contain actual jail path: {display_output}"
        );

        println!("✅ Virtual root display: {input_path} -> {display_output}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_debug_formatting() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    let virtual_path = vroot.try_path_virtual("user/document.pdf").unwrap();

    let jailed_path = virtual_path.unvirtual();
    let debug_output = format!("{jailed_path:?}");

    assert!(debug_output.contains("JailedPath"));
    assert!(debug_output.contains("path:"));
    assert!(debug_output.contains("jail_root:"));

    let expected_debug_prefix = "JailedPath { path: ";
    assert!(debug_output.starts_with(expected_debug_prefix));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_display_vs_debug_differences() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    let virtual_path = vroot.try_path_virtual("users/alice/file.txt").unwrap();

    // Get both outputs
    let display_output = format!("{virtual_path}");
    let debug_output = format!("{virtual_path:?}");

    // Display should be clean and user-friendly
    let expected_display = "/users/alice/file.txt";
    assert_eq!(display_output, expected_display);

    // Debug should be verbose and contain internal details
    assert!(debug_output.len() > display_output.len());
    assert!(debug_output.contains("JailedPath"));

    // They should be completely different
    assert_ne!(display_output, debug_output);

    // Display should NOT contain debug formatting
    assert!(!display_output.contains("JailedPath"));
    assert!(!display_output.contains("path:"));
    assert!(!display_output.contains("jail_root:"));

    println!("✅ Display: {display_output}");
    println!("✅ Debug: {debug_output}");

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_jail_root_accessor() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    let virtual_path = vroot.try_path_virtual("file.txt").unwrap();
    let jailed_path = virtual_path.unvirtual();

    // Test jail root access through the vroot (VirtualRoot)
    let jail_root = vroot.path();

    // Should be the canonical jail path
    assert_eq!(jail_root, temp_dir.canonicalize().unwrap().as_os_str());

    // JailedPath should not expose jail root directly for security
    // Instead, it should only provide its own path (which includes the file)
    // Use the explicit helper for containment checks
    assert!(jailed_path.ends_with_real("file.txt"));

    println!(
        "✅ Jail root accessor works: {}",
        jail_root.to_string_lossy()
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_with_different_marker_types() {
    #[derive(Clone)]
    struct UserFiles;
    #[derive(Clone)]
    struct ConfigFiles;

    let temp_dir = create_test_directory().expect("Failed to create temp directory");

    let user_vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new(&temp_dir).unwrap();
    let config_vroot: VirtualRoot<ConfigFiles> = VirtualRoot::try_new(&temp_dir).unwrap();

    let user_path: crate::VirtualPath<UserFiles> =
        user_vroot.try_path_virtual("user_data.json").unwrap();
    let config_path: crate::VirtualPath<ConfigFiles> =
        config_vroot.try_path_virtual("config.toml").unwrap();

    // Both should have same virtual root display behavior regardless of marker type
    assert_eq!(format!("{user_path}"), "/user_data.json");
    assert_eq!(format!("{config_path}"), "/config.toml");

    // Both vroots should access the same directory (but through their own instances)
    assert_eq!(user_vroot.path(), config_vroot.path());
    assert_eq!(
        user_vroot.path(),
        temp_dir.canonicalize().unwrap().as_os_str()
    );

    // JailedPaths (system-facing) created from the virtual paths should have their full paths (including filenames)
    let jailed_user = user_path.clone().unvirtual();
    let jailed_config = config_path.clone().unvirtual();
    assert!(jailed_user.ends_with_real("user_data.json"));
    assert!(jailed_config.ends_with_real("config.toml"));

    // Debug formatting should work for both underlying jailed paths
    let user_debug = format!("{jailed_user:?}");
    let config_debug = format!("{jailed_config:?}");

    assert!(user_debug.contains("JailedPath"));
    assert!(config_debug.contains("JailedPath"));

    println!("✅ Virtual root works with marker types");
    println!("   User: {user_path}");
    println!("   Config: {config_path}");

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_display_edge_cases() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Test edge cases for virtual root display
    let separator = "/";
    let edge_cases = vec![
        // Root file (no subdirectory)
        ("root_file.txt", format!("{separator}root_file.txt")),
        // Single character names
        ("a", format!("{separator}a")),
        ("a/b", format!("{separator}a{separator}b")),
        // Files with dots
        (".hidden", format!("{separator}.hidden")),
        (
            "file.with.many.dots.txt",
            format!("{separator}file.with.many.dots.txt"),
        ),
    ];

    for (input_path, expected_display) in edge_cases {
        let result = vroot.try_path_virtual(input_path);
        assert!(
            result.is_ok(),
            "Path validation should succeed for: {input_path}"
        );
        let virtual_path = result.unwrap();
        let display_output = format!("{virtual_path}");

        // Should start with platform separator (virtual root)
        assert!(
            display_output.starts_with('/'),
            "Virtual root should start with platform separator for: {input_path} -> {display_output}"
        );

        // Should match expected format
        assert_eq!(
            display_output, expected_display,
            "Virtual root display mismatch for: {input_path}"
        );

        println!("✅ Edge case: {input_path} -> {display_output}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_with_cross_platform_paths() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // Test that virtual root display handles cross-platform path separators
    let virtual_path = vroot
        .try_path_virtual("users/alice/documents/file.txt")
        .unwrap();
    let display_output = format!("{virtual_path}");

    // Virtual root should use platform-appropriate separators
    assert!(display_output.starts_with('/') || display_output.starts_with('\\'));

    println!("✅ Cross-platform virtual root: {display_output}");
    println!("   Underlying path: {}", vroot.path().display());

    // The virtual root display should be clean and consistent
    assert!(!display_output.is_empty());
    assert!(display_output.contains("file.txt"));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
#[cfg(windows)]
fn test_virtual_root_display_windows_separators() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    // On Windows, virtual root should use forward slashes (cross-platform contract)
    let test_cases = vec![
        ("file.txt", "/file.txt"),
        ("subdir/file.txt", "/subdir/file.txt"),
        (
            "users/alice/documents/report.pdf",
            "/users/alice/documents/report.pdf",
        ),
        (
            "deeply/nested/path/structure/file.log",
            "/deeply/nested/path/structure/file.log",
        ),
    ];

    for (input_path, expected_display) in test_cases {
        let result = vroot.try_path_virtual(input_path);
        assert!(
            result.is_ok(),
            "Path validation should succeed for: {input_path}"
        );

        let virtual_path = result.unwrap();
        let display_output = format!("{virtual_path}");

        // Should use forward slashes (cross-platform contract)
        assert_eq!(
            display_output, expected_display,
            "Virtual root display should use forward slashes for: {input_path}"
        );
        // Should start with forward slash
        assert!(
            display_output.starts_with('/') || display_output.starts_with('\u{5C}'),
            "Virtual root display should start with '/': {display_output}"
        );
        // Should not contain backslashes
        assert!(
            !display_output.contains('\\'),
            "Virtual root display should not contain backslashes: {display_output}"
        );

        println!("✅ Windows virtual root: {input_path} -> {display_output}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
#[cfg(unix)]
fn test_virtual_root_display_unix_separators() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let jail = Jail::<()>::try_new(&temp_dir).unwrap();

    // On Unix/Linux/macOS, virtual root should use forward slashes (Unix convention)
    let test_cases = vec![
        ("file.txt", "/file.txt"),
        ("subdir/file.txt", "/subdir/file.txt"),
        (
            "users/alice/documents/report.pdf",
            "/users/alice/documents/report.pdf",
        ),
        (
            "deeply/nested/path/structure/file.log",
            "/deeply/nested/path/structure/file.log",
        ),
    ];

    for (input_path, expected_display) in test_cases {
        let result = jail.try_path(input_path);
        assert!(
            result.is_ok(),
            "Path validation should succeed for: {input_path}"
        );

        let jailed_path = result.unwrap();
        // For Unix separator tests, inspect the virtualized user-facing
        // representation rather than the real filesystem path.
        let display_output = jailed_path.virtualize().display().to_string();

        // On Unix, should use forward slashes
        assert_eq!(
            display_output, expected_display,
            "Unix virtual root should use forward slashes for: {input_path}"
        );

        // Should start with forward slash (Unix virtual root)
        assert!(
            display_output.starts_with('/') || display_output.starts_with('\u{5C}'),
            "Unix virtual root should start with '/': {display_output}"
        );

        // Should not contain backslashes
        assert!(
            !display_output.contains('\\'),
            "Unix virtual root should not contain backslashes: {display_output}"
        );

        println!("✅ Unix virtual root: {input_path} -> {display_output}");
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_virtual_root_platform_consistency() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let vroot = crate::VirtualRoot::<()>::try_new(&temp_dir).unwrap();

    let virtual_path = vroot.try_path_virtual("users/alice/file.txt").unwrap();
    let display_output = format!("{virtual_path}");

    // Should always start with a forward slash (cross-platform contract)
    assert!(
        display_output.starts_with('/') || display_output.starts_with('\u{5C}'),
        "Virtual root should start with forward slash: {display_output}"
    );
    // Should not contain backslashes
    assert!(
        !display_output.contains('\\'),
        "Virtual root display should not contain backslashes: {display_output}"
    );
    println!("✅ Platform consistency verified: {display_output}");

    // Cleanup
    cleanup_test_directory(&temp_dir);
}
