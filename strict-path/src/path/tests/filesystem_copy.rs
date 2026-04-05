use crate::{path::strict_path::StrictPath, PathBoundary};
use std::path::PathBuf;

#[test]
fn test_strict_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let test_path = PathBuf::from("path/file.txt");
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let entry_path: StrictPath = temp_dir
        .strict_join(stated_path.virtualize_to_restriction(&temp_dir))
        .unwrap();

    let mut map: HashMap<StrictPath, &str> = HashMap::new();
    map.insert(entry_path.clone(), "value");
    assert_eq!(map.get(&entry_path), Some(&"value"));

    let mut btree: BTreeMap<StrictPath, &str> = BTreeMap::new();
    btree.insert(entry_path.clone(), "btree");
    assert_eq!(btree.get(&entry_path), Some(&"btree"));
}

#[test]
fn strict_copy_file_in_same_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = test_dir.strict_join("a.txt").unwrap();
    src.write("hello").unwrap();

    // Copy to sibling name
    let dst = test_dir.strict_join("b.txt").unwrap();
    let bytes = src.strict_copy("b.txt").unwrap();
    assert_eq!(bytes, "hello".len() as u64);
    assert!(src.exists());
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "hello");
}

#[test]
fn strict_copy_absolute_inside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = test_dir.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("x").unwrap();

    let abs_inside = td.path().join("copy_here.txt");
    let dst = test_dir.strict_join("copy_here.txt").unwrap();
    let bytes = src.strict_copy(&abs_inside).unwrap();
    assert_eq!(bytes, 1);
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "x");
}

#[test]
fn strict_copy_rejects_escape_outside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    let outside = td.path().parent().unwrap().join("oops.txt");
    let err = src.strict_copy(&outside).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_file_simple() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = test_dir.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    // Relative sibling copy
    let vdst = test_dir.strict_join("docs/b.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("b.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(vdst.virtualpath_display().to_string(), "/docs/b.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
    // Source still exists
    assert!(v.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_absolute_under_root() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    let vdst = test_dir.strict_join("rooted.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("/rooted.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(vdst.virtualpath_display().to_string(), "/rooted.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
}

#[test]
fn strict_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    // Parent for destination missing
    let err = src.strict_copy("missing_dir/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let err = v.virtual_copy("sub/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn strict_copy_directory_is_error() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let dir = test_dir.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let dst = test_dir.strict_join("dir2").unwrap();
    let err = dir.strict_copy("dir2").unwrap_err();
    // Cross-platform and MSRV-friendly: assert a failure kind from a known stable set,
    // and on Unix also accept a direct EISDIR mapping via raw_os_error (21).
    let kind = err.kind();
    let acceptable = matches!(
        kind,
        std::io::ErrorKind::Other
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::Unsupported
    );
    #[cfg(unix)]
    {
        const EISDIR_CODE: i32 = 21; // POSIX EISDIR
        let acceptable =
            acceptable || matches!(err.raw_os_error(), Some(code) if code == EISDIR_CODE);
        assert!(
            acceptable,
            "unexpected error kind: {:?}, raw: {:?}",
            kind,
            err.raw_os_error()
        );
    }
    #[cfg(not(unix))]
    {
        assert!(
            acceptable,
            "unexpected error kind: {:?}, raw: {:?}",
            kind,
            err.raw_os_error()
        );
    }
    // No destination was created
    assert!(dir.is_dir());
    assert!(!dst.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_with_parent_components_is_clamped() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let v2 = test_dir.strict_join("outside.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("../outside.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(v2.virtualpath_display().to_string(), "/outside.txt");
}

#[test]
fn strict_copy_overwrites_existing_destination() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = test_dir.strict_join("src.txt").unwrap();
    src.write("NEW").unwrap();
    let dst = test_dir.strict_join("dst.txt").unwrap();
    dst.write("OLD").unwrap();
    let dst = test_dir.strict_join("dst.txt").unwrap();
    let bytes = src.strict_copy("dst.txt").unwrap();
    assert_eq!(bytes, "NEW".len() as u64);
    assert_eq!(dst.read_to_string().unwrap(), "NEW");
}
