use crate::PathValidator;
use std::fs;

#[test]
fn test_jail_directory_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let jail_path = temp.path().join("jail");
    fs::create_dir_all(&jail_path).unwrap();

    let validator: PathValidator = PathValidator::with_jail(&jail_path).unwrap();

    // Create a valid path first
    let jailed_path = validator.try_path("test.txt").unwrap();
    // Compare with canonicalized jail path to handle UNC paths on Windows
    let canonical_jail = jail_path.canonicalize().unwrap();
    assert!(jailed_path.starts_with(canonical_jail));

    // Simulate jail directory being deleted
    fs::remove_dir_all(&jail_path).ok();

    // Existing jailed paths should still reference the original location
    // Check that the virtual path contains "test.txt" (the file we created)
    assert!(jailed_path
        .virtual_path_to_string_lossy()
        .contains("test.txt"));

    // New validations might fail (depending on implementation)
    if let Ok(new_path) = validator.try_path("new_file.txt") {
        assert!(new_path
            .virtual_path_to_string_lossy()
            .contains("new_file.txt"));
    }
}

#[test]
fn test_network_paths() {
    let temp = tempfile::tempdir().unwrap();
    let validator: PathValidator = PathValidator::with_jail(temp.path()).unwrap();

    // Network path patterns that should be rejected or safely handled
    let network_paths = vec![
        "//server/share/file.txt",
        "\\\\server\\share\\file.txt",
        "ftp://example.com/file.txt",
        "http://example.com/file.txt",
        "file://server/share/file.txt",
    ];

    for net_path in network_paths {
        if let Ok(jailed_path) = validator.try_path(net_path) {
            // If accepted, must still be within local jail
            let canonical_temp = temp.path().canonicalize().unwrap();
            let unjailed_path = jailed_path.unjail();
            assert!(
                unjailed_path.starts_with(canonical_temp),
                "Network path not properly contained: {net_path} -> {unjailed_path:?}"
            );
        }
    }
}

#[test]
fn test_special_filesystem_entries() {
    let temp = tempfile::tempdir().unwrap();
    let validator: PathValidator = PathValidator::with_jail(temp.path()).unwrap();

    let special_names = vec![
        ".",
        "..",
        "...",
        ".hidden",
        "..hidden",
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        ".gitignore",
        ".htaccess",
    ];

    for name in special_names {
        if let Ok(jailed_path) = validator.try_path(name) {
            let canonical_temp = temp.path().canonicalize().unwrap();
            assert!(jailed_path.starts_with(canonical_temp));
            // Special names should be handled safely
        }
    }
}
