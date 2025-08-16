use crate::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_collections() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap()
        .verify_exists()
        .unwrap(),
    );
    let test_path = PathBuf::from("/path/file.txt");
    let validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(test_path)
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);

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
    let jail_root = Arc::new(
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap()
        .verify_exists()
        .unwrap(),
    );
    let test_path = PathBuf::from("/path/file.txt");

    let validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(test_path)
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(jail_root, validated_path);

    let display_output = format!("{jailed_path}");
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
    let jail_root = Arc::new(
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap()
        .verify_exists()
        .unwrap(),
    );
    let validated_path1 =
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(path1)
            .virtualize()
            .join_jail(&jail_root)
            .canonicalize()
            .unwrap()
            .boundary_check(&jail_root)
            .unwrap();
    let validated_path2 =
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(path2)
            .virtualize()
            .join_jail(&jail_root)
            .canonicalize()
            .unwrap()
            .boundary_check(&jail_root)
            .unwrap();
    let validated_path3 =
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(path3)
            .virtualize()
            .join_jail(&jail_root)
            .canonicalize()
            .unwrap()
            .boundary_check(&jail_root)
            .unwrap();
    let jailed1: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path1);
    let jailed2: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path2);
    let jailed3: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path3);

    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}
