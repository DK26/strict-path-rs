#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::PathBoundary;

// ============================================================
// strict_read_dir() / virtual_read_dir() tests
// ============================================================

#[test]
fn test_strict_read_dir_iterates_files() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let dir = test_dir.strict_join("docs").unwrap();
    dir.create_dir_all().unwrap();

    // Create some files
    test_dir
        .strict_join("docs/readme.md")
        .unwrap()
        .write("# Readme")
        .unwrap();
    test_dir
        .strict_join("docs/guide.md")
        .unwrap()
        .write("# Guide")
        .unwrap();
    test_dir
        .strict_join("docs/api.md")
        .unwrap()
        .write("# API")
        .unwrap();

    // Iterate and collect
    let entries: Vec<_> = dir
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 3);
    // All entries should be files
    for entry in &entries {
        assert!(entry.is_file());
    }
}

#[test]
fn test_strict_read_dir_mixed_files_and_dirs() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let root = test_dir.strict_join("project").unwrap();
    root.create_dir_all().unwrap();

    // Create files
    test_dir
        .strict_join("project/file.txt")
        .unwrap()
        .write("content")
        .unwrap();
    // Create subdirectory
    test_dir
        .strict_join("project/subdir")
        .unwrap()
        .create_dir_all()
        .unwrap();

    let entries: Vec<_> = root
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 2);

    let files: Vec<_> = entries.iter().filter(|e| e.is_file()).collect();
    let dirs: Vec<_> = entries.iter().filter(|e| e.is_dir()).collect();

    assert_eq!(files.len(), 1);
    assert_eq!(dirs.len(), 1);
}

#[test]
fn test_strict_read_dir_empty_directory() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let empty = test_dir.strict_join("empty").unwrap();
    empty.create_dir_all().unwrap();

    let entries: Vec<_> = empty
        .strict_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(entries.is_empty());
}

#[test]
fn test_strict_read_dir_on_file_errors() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file = test_dir.strict_join("not_a_dir.txt").unwrap();
    file.write("content").unwrap();

    // strict_read_dir on a file should error
    // strict_read_dir on a file must fail; exact error kind is platform-dependent
    // (NotADirectory on Linux ≥ 1.83, Other on older MSRV, varies on Windows).
    file.strict_read_dir().unwrap_err();
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_read_dir_iterates_files() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let dir = vroot.virtual_join("uploads").unwrap();
    dir.create_dir_all().unwrap();

    // Create some files
    vroot
        .virtual_join("uploads/photo.jpg")
        .unwrap()
        .write(b"JPG")
        .unwrap();
    vroot
        .virtual_join("uploads/doc.pdf")
        .unwrap()
        .write(b"PDF")
        .unwrap();

    let entries: Vec<_> = dir
        .virtual_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert!(entry.is_file());
        // Verify virtual display format
        let display = entry.virtualpath_display().to_string();
        assert!(display.starts_with("/uploads/"));
    }
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_read_dir_preserves_virtual_paths() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let dir = vroot.virtual_join("nested/deep").unwrap();
    dir.create_dir_all().unwrap();
    vroot
        .virtual_join("nested/deep/file.txt")
        .unwrap()
        .write("test")
        .unwrap();

    let entries: Vec<_> = dir
        .virtual_read_dir()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    // Virtual display should show the full virtual path
    assert_eq!(
        entry.virtualpath_display().to_string(),
        "/nested/deep/file.txt"
    );
}

// ==================== strict_read_link / virtual_read_link tests ====================
// NOTE: strict_join and virtual_join resolve symlinks during canonicalization,
// so the resulting StrictPath/VirtualPath always points to the resolved target.
// This means strict_read_link/virtual_read_link are only useful in very specific
// scenarios where you already have a StrictPath to a symlink (which is rare).
// The main security tests for symlink handling are in symlink_methods.rs.

#[test]
#[cfg(unix)]
fn test_strict_join_catches_escaping_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let boundary_dir = temp.path().join("boundary");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&boundary_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let test_dir: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    // Create a file outside the boundary
    let outside_file = outside_dir.join("secret.txt");
    std::fs::write(&outside_file, "secret data").unwrap();

    // Create a malicious symlink inside the boundary pointing outside
    let link_path = boundary_dir.join("escape_link");
    std::os::unix::fs::symlink(&outside_file, &link_path).unwrap();

    // strict_join catches escaping symlinks during canonicalization
    // This is the correct security behavior - we can't even get a StrictPath
    // to a symlink that points outside the boundary
    let result = test_dir.strict_join("escape_link");
    assert!(result.is_err());

    // The error should indicate path escapes boundary
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        crate::StrictPathError::PathEscapesBoundary { .. }
    ));
}

#[test]
#[cfg(all(unix, feature = "virtual-path"))]
fn test_virtual_join_clamps_escaping_symlink_target() {
    // NOTE: VirtualPath CLAMPS escaping symlink targets, it does NOT error.
    // This is the key difference from StrictPath:
    // - StrictPath: symlink pointing outside -> PathEscapesBoundary error
    // - VirtualPath: symlink pointing outside -> target is clamped into vroot
    //
    // When a symlink at vroot/escape_link points to /outside/external.txt,
    // VirtualPath clamps the resolved target to vroot/outside/external.txt
    // (which likely doesn't exist, but that's the clamping behavior).

    let temp = tempfile::tempdir().unwrap();
    let vroot_dir = temp.path().join("vroot");
    let outside_dir = temp.path().join("outside");
    std::fs::create_dir_all(&vroot_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&vroot_dir).unwrap();

    // Create a file outside the virtual root
    let outside_file = outside_dir.join("external.txt");
    std::fs::write(&outside_file, "external").unwrap();

    // Create a symlink inside vroot pointing to the outside file
    let link_path = vroot_dir.join("escape_link");
    std::os::unix::fs::symlink(&outside_file, &link_path).unwrap();

    // VirtualPath clamps the escaping symlink target into the vroot
    // This succeeds (unlike StrictPath which would error)
    let result = vroot.virtual_join("escape_link");
    assert!(
        result.is_ok(),
        "VirtualPath should clamp escaping symlinks, not error: {:?}",
        result
    );

    // The resulting path should be inside the vroot (clamped)
    let vpath = result.unwrap();
    let canonical_vroot = std::fs::canonicalize(&vroot_dir).unwrap();
    let system_path = vpath.interop_path();
    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_vroot),
        "Clamped path must be within vroot. Got: {:?}, VRoot: {:?}",
        system_path,
        canonical_vroot
    );
}

// ==================== set_permissions / try_exists / touch tests ====================

#[test]
fn test_strict_path_set_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file = test_dir.strict_join("test.txt").unwrap();
    file.write("content").unwrap();

    // Get current permissions and make read-only
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_readonly(true);
    file.set_permissions(perms).unwrap();

    // Verify permissions changed
    assert!(file.metadata().unwrap().permissions().readonly());

    // Cleanup: temp directory will be removed anyway, no need to restore
}

#[test]
fn test_strict_path_try_exists() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Existing file
    let existing = test_dir.strict_join("exists.txt").unwrap();
    existing.write("content").unwrap();
    assert!(existing.try_exists().unwrap());

    // Non-existing file
    let missing = test_dir.strict_join("missing.txt").unwrap();
    assert!(!missing.try_exists().unwrap());

    // Existing directory
    let dir = test_dir.strict_join("subdir").unwrap();
    dir.create_dir_all().unwrap();
    assert!(dir.try_exists().unwrap());
}

#[test]
fn test_strict_path_touch_creates_file() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file = test_dir.strict_join("new_file.txt").unwrap();
    assert!(!file.exists());

    file.touch().unwrap();

    assert!(file.exists());
    assert!(file.is_file());
    assert_eq!(file.read_to_string().unwrap(), "");
}

#[test]
fn test_strict_path_touch_updates_existing() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let file = test_dir.strict_join("existing.txt").unwrap();
    file.write("original content").unwrap();

    // Small delay then touch to update mtime
    std::thread::sleep(std::time::Duration::from_millis(50));
    file.touch().unwrap();

    // Content should be preserved (touch doesn't truncate)
    assert_eq!(file.read_to_string().unwrap(), "original content")
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_set_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let file = vroot.virtual_join("/test.txt").unwrap();
    file.write("content").unwrap();

    // Get current permissions and make read-only
    let mut perms = file.metadata().unwrap().permissions();
    perms.set_readonly(true);
    file.set_permissions(perms).unwrap();

    // Verify permissions changed
    assert!(file.metadata().unwrap().permissions().readonly());

    // Cleanup: temp directory will be removed anyway, no need to restore
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_try_exists() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let existing = vroot.virtual_join("/exists.txt").unwrap();
    existing.write("content").unwrap();
    assert!(existing.try_exists().unwrap());

    let missing = vroot.virtual_join("/missing.txt").unwrap();
    assert!(!missing.try_exists().unwrap());
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_touch() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    let file = vroot.virtual_join("/touched.txt").unwrap();
    assert!(!file.exists());

    file.touch().unwrap();

    assert!(file.exists());
    assert_eq!(file.read_to_string().unwrap(), "");
}
