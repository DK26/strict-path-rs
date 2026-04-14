#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{path::strict_path::StrictPath, PathBoundary};
use std::path::PathBuf;

#[test]
#[cfg(feature = "virtual-path")]
fn test_strict_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("path/file.txt").unwrap();

    let display_output = vpath.virtualpath_display().to_string();
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
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let strict_file: StrictPath = test_dir.strict_join("file.txt").unwrap();

    strict_file.write(b"hello").unwrap();
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

    vpath.write(b"abc").unwrap();
    let metadata = vpath.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 3);

    vpath.remove_file().unwrap();
    assert!(vpath.metadata().is_err());
}

#[test]
fn test_strict_path_remove_dir_variants() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // remove_dir removes an empty directory
    let empty_dir = test_dir.strict_join("dir_one").unwrap();
    empty_dir.create_dir_all().unwrap();
    assert!(empty_dir.is_dir());
    empty_dir.remove_dir().unwrap();
    assert!(!empty_dir.exists());

    // remove_dir_all removes a directory tree
    let dir_root = test_dir.strict_join("dir_two").unwrap();
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
