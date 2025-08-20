use crate::path::jailed_path::JailedPath;
use std::path::PathBuf;

#[test]
fn test_jailed_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let jail = crate::validator::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let test_path = PathBuf::from("/path/file.txt");
    let jailed_path: JailedPath = crate::validator::validate(
        crate::validator::virtualize_to_jail(test_path, &jail),
        &jail,
    )
    .unwrap();

    let mut map: HashMap<JailedPath, &str> = HashMap::new();
    map.insert(jailed_path.clone(), "value");
    assert_eq!(map.get(&jailed_path), Some(&"value"));

    let mut btree: BTreeMap<JailedPath, &str> = BTreeMap::new();
    btree.insert(jailed_path.clone(), "btree");
    assert_eq!(btree.get(&jailed_path), Some(&"btree"));
}

#[test]
fn test_jailed_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let vroot = crate::validator::virtual_root::VirtualRoot::<()>::try_new(temp.path()).unwrap();
    let vpath = vroot.try_path_virtual("path/file.txt").unwrap();

    let display_output = format!("{vpath}");
    let expected_root = "/path/file.txt";
    assert_eq!(
        display_output, expected_root,
        "Display output should use forward slashes"
    );
}

#[test]
fn test_jailed_path_equality_and_hash() {
    let path1 = PathBuf::from("path");
    let path2 = PathBuf::from("path");
    let path3 = PathBuf::from("different/path");
    let temp = tempfile::tempdir().unwrap();
    let jail = crate::validator::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let jailed1: JailedPath =
        crate::validator::validate(crate::validator::virtualize_to_jail(path1, &jail), &jail)
            .unwrap();
    let jailed2: JailedPath =
        crate::validator::validate(crate::validator::virtualize_to_jail(path2, &jail), &jail)
            .unwrap();
    let jailed3: JailedPath =
        crate::validator::validate(crate::validator::virtualize_to_jail(path3, &jail), &jail)
            .unwrap();

    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}
