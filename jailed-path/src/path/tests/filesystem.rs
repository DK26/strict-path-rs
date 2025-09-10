use crate::{path::jailed_path::JailedPath, Jail, VirtualRoot};
use std::path::PathBuf;

#[test]
fn test_jailed_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();
    let test_path = PathBuf::from("path/file.txt");
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let jailed_path: JailedPath = jail
        .jailed_join(stated_path.virtualize_to_jail(&jail))
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
    let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
    let vpath = vroot.virtual_join("path/file.txt").unwrap();

    let display_output = format!("{}", vpath.virtualpath_display());
    assert_eq!(display_output, "/path/file.txt");
}

#[test]
fn test_jailed_path_equality_and_hash() {
    let path1 = PathBuf::from("path");
    let path2 = PathBuf::from("path");
    let path3 = PathBuf::from("different/path");
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let stated_path1 = crate::validator::path_history::PathHistory::new(path1);
    let jailed1: JailedPath = jail
        .jailed_join(stated_path1.virtualize_to_jail(&jail))
        .unwrap();
    let stated_path2 = crate::validator::path_history::PathHistory::new(path2);
    let jailed2: JailedPath = jail
        .jailed_join(stated_path2.virtualize_to_jail(&jail))
        .unwrap();
    let stated_path3 = crate::validator::path_history::PathHistory::new(path3);
    let jailed3: JailedPath = jail
        .jailed_join(stated_path3.virtualize_to_jail(&jail))
        .unwrap();

    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}
