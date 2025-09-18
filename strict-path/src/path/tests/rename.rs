use crate::PathBoundary;
use std::sync::Mutex;

// Global mutex to prevent race conditions in rename tests
static RENAME_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn strict_rename_file_in_same_boundary() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("a.txt").unwrap();
    src.write("hello").unwrap();

    let dest = boundary.strict_join("b.txt").unwrap();
    src.strict_rename("b.txt").unwrap();

    assert!(dest.exists());
    assert_eq!(dest.read_to_string().unwrap(), "hello");
    assert!(!boundary.strict_join("a.txt").unwrap().exists());
}

#[test]
fn virtual_rename_file_simple() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let file = boundary.strict_join("docs/file.txt").unwrap();
    file.create_parent_dir_all().unwrap();
    file.write("v").unwrap();

    let v = file.clone().virtualize();
    v.virtual_rename("renamed.txt").unwrap();
    let renamed = boundary
        .strict_join("docs/renamed.txt")
        .unwrap()
        .virtualize();
    assert_eq!(
        format!("{}", renamed.virtualpath_display()),
        "/docs/renamed.txt"
    );
    assert!(renamed.exists());
    assert_eq!(renamed.read_to_string().unwrap(), "v");
}

#[test]
fn strict_rename_nested_relative_and_absolute() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("content").unwrap();

    boundary
        .strict_join("docs/sub")
        .unwrap()
        .create_dir_all()
        .unwrap();

    src.strict_rename("sub/renamed.txt").unwrap();
    let nested = boundary.strict_join("docs/sub/renamed.txt").unwrap();
    assert_eq!(nested.read_to_string().unwrap(), "content");
    assert!(
        nested
            .strictpath_display()
            .to_string()
            .ends_with("sub/renamed.txt")
            || nested
                .strictpath_display()
                .to_string()
                .ends_with("sub\\renamed.txt")
    );

    let abs_inside = td.path().join("abs_target.txt");
    let current = boundary.strict_join("docs/sub/renamed.txt").unwrap();
    current.strict_rename(&abs_inside).unwrap();
    let abs_dest = boundary.strict_join("abs_target.txt").unwrap();
    assert!(abs_dest.exists());
    assert_eq!(abs_dest.read_to_string().unwrap(), "content");
}

#[test]
fn strict_rename_rejects_escape_outside_boundary() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    let outside = td.path().parent().unwrap().join("oops.txt");
    let err = src.strict_rename(&outside).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
fn strict_rename_directory_tree() {
    let _guard = RENAME_TEST_MUTEX.lock().unwrap();

    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let dir = boundary.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let file = boundary.strict_join("dir/note.txt").unwrap();
    file.write("notes").unwrap();

    dir.strict_rename("dir2").unwrap();
    let moved_file = boundary.strict_join("dir2/note.txt").unwrap();
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

    match src.strict_rename("dst.txt") {
        Ok(()) => {
            assert_eq!(dst.read_to_string().unwrap(), "S");
        }
        Err(err) => {
            assert!(err.kind() == std::io::ErrorKind::PermissionDenied);
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

    v.virtual_rename("renamed.txt").unwrap();
    let v2 = boundary
        .strict_join("docs/renamed.txt")
        .unwrap()
        .virtualize();
    assert_eq!(format!("{}", v2.virtualpath_display()), "/docs/renamed.txt");

    v2.virtual_rename("/rooted.txt").unwrap();
    let v3 = boundary.strict_join("rooted.txt").unwrap().virtualize();
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

    v.virtual_rename("../outside.txt").unwrap();
    let v2 = boundary.strict_join("outside.txt").unwrap().virtualize();
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

    vdir.virtual_rename("/docs2").unwrap();
    let moved = boundary.strict_join("docs2").unwrap().virtualize();
    assert_eq!(format!("{}", moved.virtualpath_display()), "/docs2");
    let moved_file = moved.as_unvirtual().strict_join("a.txt").unwrap();
    assert_eq!(moved_file.read_to_string().unwrap(), "x");
}
