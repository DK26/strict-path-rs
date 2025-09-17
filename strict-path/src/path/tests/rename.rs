use crate::PathBoundary;
use std::sync::Mutex;

// Global mutex to prevent race conditions in rename tests
static RENAME_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn strict_rename_file_in_same_boundary() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Create file
    let src = boundary.strict_join("a.txt").unwrap();
    src.write("hello").unwrap();

    // Rename to new name (same directory)
    let dst = src.strict_rename("b.txt").unwrap();

    // New path has the content
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "hello");

    // Old path should not exist anymore
    let old = boundary.strict_join("a.txt").unwrap();
    assert!(!old.exists());
}

#[test]
fn virtual_rename_file_simple() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Prepare a directory and file
    let file = boundary.strict_join("docs/file.txt").unwrap();
    file.create_parent_dir_all().unwrap();
    file.write("v").unwrap();

    // Work with virtual view rooted at the same boundary
    let v = file.clone().virtualize();

    // Relative destination resolves as sibling under current virtual parent
    let v2 = v.virtual_rename("renamed.txt").unwrap();
    assert_eq!(format!("{}", v2.virtualpath_display()), "/docs/renamed.txt");
    assert!(v2.exists());
    assert_eq!(v2.read_to_string().unwrap(), "v");
}

#[test]
fn strict_rename_nested_relative_and_absolute() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // tree: ./docs/file.txt
    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("content").unwrap();

    // Create the nested parent
    boundary
        .strict_join("docs/sub")
        .unwrap()
        .create_dir_all()
        .unwrap();
    // Relative to parent: moves to ./docs/sub/renamed.txt (parent is "docs")
    let dst_nested = src.strict_rename("sub/renamed.txt").unwrap();
    assert_eq!(dst_nested.read_to_string().unwrap(), "content");
    assert!(dst_nested.strictpath_display().to_string().contains("docs"));
    assert!(
        dst_nested
            .strictpath_display()
            .to_string()
            .ends_with("sub/renamed.txt")
            || dst_nested
                .strictpath_display()
                .to_string()
                .ends_with("sub\\renamed.txt")
    );

    // Absolute inside boundary (use the temp root joined path)
    let abs_inside = td.path().join("abs_target.txt");
    let src_again = boundary.strict_join("docs/sub/renamed.txt").unwrap();
    let dst_abs = src_again.strict_rename(&abs_inside).unwrap();
    assert!(dst_abs.exists());
    assert_eq!(dst_abs.read_to_string().unwrap(), "content");
}

#[test]
fn strict_rename_rejects_escape_outside_boundary() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    // Attempt to escape with an absolute outside path should map to io::Error(Other)
    let outside = td.path().parent().unwrap().join("oops.txt");
    let err = src.strict_rename(&outside).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
fn strict_rename_directory_tree() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Create directory with nested file
    let dir = boundary.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let file = boundary.strict_join("dir/note.txt").unwrap();
    file.write("notes").unwrap();

    // Move the directory under a new name
    let moved = dir.strict_rename("dir2").unwrap();
    let moved_file = moved.strict_join("note.txt").unwrap();
    assert_eq!(moved_file.read_to_string().unwrap(), "notes");
}

#[test]
fn strict_rename_destination_exists_behavior() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("src.txt").unwrap();
    src.write("S").unwrap();
    let dst = boundary.strict_join("dst.txt").unwrap();
    dst.write("D").unwrap();

    let result = src.strict_rename("dst.txt");
    match result {
        Ok(replaced) => {
            // Destination replaced; ensure content came from source
            assert_eq!(replaced.read_to_string().unwrap(), "S");
        }
        Err(_) => {
            // Some platforms may not allow replacing existing destinations
            // Accept failure in that case
        }
    }
}

#[test]
fn strict_rename_nonexistent_source() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let missing = boundary.strict_join("missing.txt").unwrap();
    let err = missing.strict_rename("any.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn virtual_rename_relative_sibling_and_absolute() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let file = boundary.strict_join("docs/file.txt").unwrap();
    file.create_parent_dir_all().unwrap();
    file.write("v").unwrap();
    let v = file.virtualize();

    // Relative: sibling under /docs
    let v2 = v.virtual_rename("renamed.txt").unwrap();
    assert_eq!(format!("{}", v2.virtualpath_display()), "/docs/renamed.txt");

    // Absolute: under virtual root
    let v3 = v2.virtual_rename("/rooted.txt").unwrap();
    assert_eq!(format!("{}", v3.virtualpath_display()), "/rooted.txt");
}

#[test]
fn virtual_rename_with_parent_components_is_clamped() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let file = boundary.strict_join("docs/file.txt").unwrap();
    file.create_parent_dir_all().unwrap();
    file.write("v").unwrap();
    let v = file.virtualize();

    let v2 = v.virtual_rename("../outside.txt").unwrap();
    // Parent traversal from /docs/file.txt to ../outside.txt -> /outside.txt
    assert_eq!(format!("{}", v2.virtualpath_display()), "/outside.txt");
}

#[test]
fn virtual_rename_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let file = boundary.strict_join("docs/file.txt").unwrap();
    file.create_parent_dir_all().unwrap();
    file.write("v").unwrap();
    let v = file.virtualize();

    // Destination parent (/docs/sub) doesn't exist; rename should fail
    let err = v.virtual_rename("sub/renamed.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn virtual_rename_directory() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let dir = boundary.strict_join("docs").unwrap();
    dir.create_dir_all().unwrap();
    let file = boundary.strict_join("docs/a.txt").unwrap();
    file.write("x").unwrap();
    let vdir = dir.virtualize();

    // Move folder as sibling under root (absolute)
    let moved = vdir.virtual_rename("/docs2").unwrap();
    assert_eq!(format!("{}", moved.virtualpath_display()), "/docs2");
    let moved_file = moved.as_unvirtual().strict_join("a.txt").unwrap();
    assert_eq!(moved_file.read_to_string().unwrap(), "x");
}
