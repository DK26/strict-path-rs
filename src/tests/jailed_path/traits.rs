use crate::jailed_path::JailedPath;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[test]
fn test_jailed_path_partial_eq_and_borrow() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let test_path = PathBuf::from("path");
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(test_path.clone())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);
    // Type annotation for validated_path to ensure correct type-state

    let abs_path = jail_root.join(&test_path);
    // PartialEq<Path>
    assert_eq!(jailed_path.real_path(), abs_path.as_path());
    // PartialEq<PathBuf>
    assert_eq!(jailed_path, abs_path);
    // PartialEq<&str> (string form of the path)

    // Only explicit JailedPath keys are supported for HashMap/BTreeMap
    let mut map: HashMap<JailedPath, &str> = HashMap::new();
    map.insert(jailed_path.clone(), "value");
    assert_eq!(map.get(&jailed_path), Some(&"value"));

    let mut btree: BTreeMap<JailedPath, &str> = BTreeMap::new();
    btree.insert(jailed_path.clone(), "btree");
    assert_eq!(btree.get(&jailed_path), Some(&"btree"));
}

#[test]
fn test_jailed_path_as_ref_implementation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(test_path.clone())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);

    // Should work with AsRef<Path>
    let abs_path = jail_root.join(&test_path);
    let path_ref: &Path = jailed_path.real_path();
    assert_eq!(path_ref, abs_path.as_path());
}

#[test]
fn test_jailed_path_deref_implementation() {
    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(jail_relative)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath<()> = JailedPath::new(Arc::clone(&jail_root), validated_path);

    // Should allow calling Path methods directly via Deref
    assert_eq!(
        jailed_path.real_path().file_name(),
        Some(std::ffi::OsStr::new("path"))
    );
    // Compare parent paths, not Option types
    let parent = jailed_path
        .virtual_parent()
        .map(|jp| jp.real_path().to_path_buf());
    let expected_parent = Some(jail_root.to_path_buf());
    assert_eq!(parent, expected_parent);
    assert_eq!(jailed_path.real_path().extension(), None);
}

#[test]
fn test_jailed_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let test_path = PathBuf::from("path/file.txt");

    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(test_path)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(jail_root, validated_path);

    // Should display virtual root - path relative to jail, always with forward slashes
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
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );

    let validated_path1 = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(path1)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let validated_path2 = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(path2)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let validated_path3 = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(path3)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed1: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path1);
    let jailed2: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path2);
    let jailed3: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path3);

    // Should implement equality correctly
    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}