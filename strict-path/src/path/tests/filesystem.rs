#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("a.txt").unwrap();
    src.write("hello").unwrap();

    // Copy to sibling name
    let dst = boundary.strict_join("b.txt").unwrap();
    let bytes = src.strict_copy("b.txt").unwrap();
    assert_eq!(bytes, "hello".len() as u64);
    assert!(src.exists());
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "hello");
}

#[test]
fn strict_copy_absolute_inside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("x").unwrap();

    let abs_inside = td.path().join("copy_here.txt");
    let dst = boundary.strict_join("copy_here.txt").unwrap();
    let bytes = src.strict_copy(&abs_inside).unwrap();
    assert_eq!(bytes, 1);
    assert!(dst.exists());
    assert_eq!(dst.read_to_string().unwrap(), "x");
}

#[test]
fn strict_copy_rejects_escape_outside_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    let outside = td.path().parent().unwrap().join("oops.txt");
    let err = src.strict_copy(&outside).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_file_simple() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    // Relative sibling copy
    let vdst = boundary.strict_join("docs/b.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("b.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", vdst.virtualpath_display()), "/docs/b.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
    // Source still exists
    assert!(v.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_absolute_under_root() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();

    let vdst = boundary.strict_join("rooted.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("/rooted.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", vdst.virtualpath_display()), "/rooted.txt");
    assert!(vdst.exists());
    assert_eq!(vdst.read_to_string().unwrap(), "v");
}

#[test]
fn strict_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("a.txt").unwrap();
    src.write("x").unwrap();
    // Parent for destination missing
    let err = src.strict_copy("missing_dir/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_fails_when_parent_missing() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/a.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let err = v.virtual_copy("sub/b.txt").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn strict_copy_directory_is_error() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let dir = boundary.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let dst = boundary.strict_join("dir2").unwrap();
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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("docs/file.txt").unwrap();
    src.create_parent_dir_all().unwrap();
    src.write("v").unwrap();
    let v = src.virtualize();
    let v2 = boundary.strict_join("outside.txt").unwrap().virtualize();
    let bytes = v.virtual_copy("../outside.txt").unwrap();
    assert_eq!(bytes, "v".len() as u64);
    assert_eq!(format!("{}", v2.virtualpath_display()), "/outside.txt");
}

#[test]
fn strict_copy_overwrites_existing_destination() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let src = boundary.strict_join("src.txt").unwrap();
    src.write("NEW").unwrap();
    let dst = boundary.strict_join("dst.txt").unwrap();
    dst.write("OLD").unwrap();
    let dst = boundary.strict_join("dst.txt").unwrap();
    let bytes = src.strict_copy("dst.txt").unwrap();
    assert_eq!(bytes, "NEW".len() as u64);
    assert_eq!(dst.read_to_string().unwrap(), "NEW");
}
#[test]
#[cfg(feature = "virtual-path")]
fn test_strict_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("path/file.txt").unwrap();

    let display_output = format!("{}", vpath.virtualpath_display());
    assert_eq!(display_output, "/path/file.txt");
}

#[test]
fn test_strict_path_equality_and_hash() {
    let path1 = PathBuf::from("path");
    let path2 = PathBuf::from("path");
    let path3 = PathBuf::from("different/path");
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let stated_path1 = crate::validator::path_history::PathHistory::new(path1);
    let jailed1: StrictPath = temp_dir
        .strict_join(stated_path1.virtualize_to_restriction(&temp_dir))
        .unwrap();
    let stated_path2 = crate::validator::path_history::PathHistory::new(path2);
    let jailed2: StrictPath = temp_dir
        .strict_join(stated_path2.virtualize_to_restriction(&temp_dir))
        .unwrap();
    let stated_path3 = crate::validator::path_history::PathHistory::new(path3);
    let jailed3: StrictPath = temp_dir
        .strict_join(stated_path3.virtualize_to_restriction(&temp_dir))
        .unwrap();

    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}
#[test]
fn test_strict_path_metadata_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let strict_file: StrictPath = boundary.strict_join("file.txt").unwrap();

    std::fs::write(strict_file.interop_path(), b"hello").unwrap();
    let metadata = strict_file.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 5);

    strict_file.remove_file().unwrap();
    assert!(strict_file.metadata().is_err());
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_metadata_behavior() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("file.txt").unwrap();

    std::fs::write(vpath.as_unvirtual().interop_path(), b"abc").unwrap();
    let metadata = vpath.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 3);

    vpath.remove_file().unwrap();
    assert!(vpath.metadata().is_err());
}

#[test]
fn test_strict_path_remove_dir_variants() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // remove_dir removes an empty directory
    let empty_dir = boundary.strict_join("dir_one").unwrap();
    empty_dir.create_dir_all().unwrap();
    assert!(empty_dir.is_dir());
    empty_dir.remove_dir().unwrap();
    assert!(!empty_dir.exists());

    // remove_dir_all removes a directory tree
    let dir_root = boundary.strict_join("dir_two").unwrap();
    let nested = dir_root.strict_join("nested").unwrap();
    nested.create_dir_all().unwrap();
    assert!(nested.is_dir());
    dir_root.remove_dir_all().unwrap();
    assert!(!dir_root.exists());
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_remove_dir_variants() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

    // remove_dir removes an empty directory
    let empty_dir = vroot.virtual_join("dir_one").unwrap();
    empty_dir.create_dir_all().unwrap();
    assert!(empty_dir.is_dir());
    empty_dir.remove_dir().unwrap();
    assert!(!empty_dir.exists());

    // remove_dir_all removes a directory tree
    let dir_root = vroot.virtual_join("dir_two").unwrap();
    let nested = dir_root.virtual_join("nested").unwrap();
    nested.create_dir_all().unwrap();
    assert!(nested.is_dir());
    dir_root.remove_dir_all().unwrap();
    assert!(!dir_root.exists());
}
