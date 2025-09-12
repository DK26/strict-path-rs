use crate::{path::strict_path::StrictPath, PathBoundary, VirtualRoot};
use std::path::PathBuf;

#[test]
fn test_strict_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let test_path = PathBuf::from("path/file.txt");
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let strict_path: StrictPath = temp_dir
        .strict_join(stated_path.virtualize_to_restriction(&temp_dir))
        .unwrap();

    let mut map: HashMap<StrictPath, &str> = HashMap::new();
    map.insert(strict_path.clone(), "value");
    assert_eq!(map.get(&strict_path), Some(&"value"));

    let mut btree: BTreeMap<StrictPath, &str> = BTreeMap::new();
    btree.insert(strict_path.clone(), "btree");
    assert_eq!(btree.get(&strict_path), Some(&"btree"));
}

#[test]
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
