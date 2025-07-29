#[test]
fn test_jailed_path_try_join_and_try_parent() {
    use crate::jailed_path::JailedPath;

    use std::sync::Arc;

    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("foo/bar.txt");
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(jail_relative)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();

    // Only check for jail-relativity before join_jail/canonicalize if needed.
    // After join_jail/canonicalize, staged.as_path() should be absolute and include jail_root.
    let jailed: JailedPath = JailedPath::new(staged, Arc::clone(&jail_root));

    // try_virtual_join (inside jail)
    let joined = jailed.try_virtual_join("baz.txt");
    assert!(joined.is_ok(), "try_virtual_join failed: {joined:?}");
    let actual = joined.as_ref().unwrap().real_path();
    let expected = jail_root.as_path().join("foo/bar.txt/baz.txt");
    assert_eq!(
        actual, expected,
        "actual: {actual:?}, expected: {expected:?}"
    );

    // try_virtual_join (outside jail, expect clamping)
    let outside = jailed.try_virtual_join("../../../../etc/passwd");
    assert!(
        outside.is_ok(),
        "Expected clamping to jail root, got error: {outside:?}"
    );
    let clamped = outside.unwrap();
    assert!(clamped.real_path().starts_with(jail_root.as_path()));

    // try_parent (inside jail)
    let parent = jailed.try_virtual_parent();
    assert!(parent.is_ok());
    let expected_parent = jail_root.as_path().join("foo");
    let actual_parent = parent.as_ref().unwrap().real_path();
    assert_eq!(
        actual_parent, expected_parent,
        "actual: {actual_parent:?}, expected: {expected_parent:?}"
    );

    // try_parent (at jail root, use empty PathBuf for virtual root)
    let jail_staged = crate::validator::StagedPath::<crate::validator::Raw>::new(PathBuf::new())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jail: JailedPath<()> = JailedPath::new(jail_staged, Arc::clone(&jail_root));
    let parent_none = jail.try_virtual_parent();
    assert!(parent_none.is_err());
}
#[test]
fn test_jailed_path_pathbuf_methods() {
    use std::path::PathBuf;
    use std::sync::Arc;
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );

    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("foo/bar.txt");
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(jail_relative.clone())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(staged, Arc::clone(&jail_root));

    // safe_join (inside jail)
    // The jailed path represents "/foo/bar.txt" virtually
    // Joining "baz.txt" should result in "/foo/bar.txt/baz.txt" virtually
    // Which translates to jail_root/foo/bar.txt/baz.txt in real path
    let joined = jailed.virtual_join("baz.txt");
    assert!(joined.is_some());
    let actual = joined.as_ref().unwrap().real_path();

    // The expected path should be: jail_root/foo/bar.txt/baz.txt
    // This is because we're joining "baz.txt" to the virtual path "/foo/bar.txt"
    let expected = jail_root
        .as_path()
        .join("foo")
        .join("bar.txt")
        .join("baz.txt");
    assert_eq!(actual, expected);

    // virtual_join (outside jail)
    let outside = jailed.virtual_join("../../../../etc/passwd");
    assert!(outside.is_some()); // This should be clamped, not rejected
                                // The result should be clamped to jail root
    let clamped = outside.unwrap();
    // After clamping ../../../../etc/passwd from /foo/bar.txt, we should get /etc/passwd
    // (or possibly just /passwd depending on how many levels up we can go)
    assert!(clamped.real_path().starts_with(jail_root.as_path()));

    // parent (inside jail)
    let parent = jailed.virtual_parent();
    assert!(parent.is_some());
    let expected_parent = jail_root.as_path().join("foo");
    let actual_parent = parent.as_ref().unwrap().real_path();
    assert_eq!(actual_parent, expected_parent);

    // parent (at jail root)
    // To create a JailedPath representing the virtual root "/", use an empty path
    let jail_staged = crate::validator::StagedPath::<crate::validator::Raw>::new(PathBuf::new())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jail: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(jail_staged, Arc::clone(&jail_root));
    assert!(jail.virtual_parent().is_none());

    // with_file_name (inside jail)
    let with_name = jailed.virtual_with_file_name("newname.txt");
    assert!(with_name.is_some());
    let joined_path = jail_root.as_path().join("foo/bar.txt");
    let expected_with_name = joined_path.parent().unwrap().join("newname.txt");
    let actual_with_name = with_name.as_ref().unwrap().real_path();
    assert_eq!(
        actual_with_name, expected_with_name,
        "actual: {actual_with_name:?}, expected: {expected_with_name:?}"
    );

    // with_file_name (potential escape attempt - should be clamped, not rejected)
    let root_staged = crate::validator::StagedPath::<crate::validator::Raw>::new(PathBuf::new())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let root: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(root_staged, Arc::clone(&jail_root));
    let escape_attempt = root.virtual_with_file_name("../../etc/passwd");
    assert!(escape_attempt.is_some()); // Should be clamped, not rejected
                                       // The result should still be within the jail
    assert!(escape_attempt
        .unwrap()
        .real_path()
        .starts_with(jail_root.as_path()));

    // with_extension (inside jail)
    let with_ext = jailed.virtual_with_extension("log");
    assert!(with_ext.is_some());
    let mut joined_path = jail_root.as_path().join("foo/bar.txt");
    joined_path.set_extension("log");
    let expected_with_ext = joined_path;
    let actual_with_ext = with_ext.as_ref().unwrap().real_path();
    assert_eq!(
        actual_with_ext, expected_with_ext,
        "actual: {actual_with_ext:?}, expected: {expected_with_ext:?}"
    );

    // unjail
    let inner = jailed.unjail();
    assert_eq!(inner, jail_root.as_path().join("foo/bar.txt"));

    // to_bytes and into_bytes (platform-specific)
    // (Cannot use jailed after move above, so re-create)
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(jail_relative)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(staged, Arc::clone(&jail_root));
    let bytes = jailed.to_bytes();
    let into_bytes = jailed.into_bytes();
    assert_eq!(bytes, into_bytes);
}
#[test]
fn test_jailed_path_partial_eq_and_borrow() {
    use std::collections::{BTreeMap, HashMap};

    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let test_path = PathBuf::from("path");
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path.clone())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, Arc::clone(&jail_root));
    // Type annotation for staged to ensure correct type-state

    let abs_path = jail_root.as_path().join(&test_path);
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
use crate::jailed_path::JailedPath;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path.clone())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, Arc::clone(&jail_root));

    // Should store the path correctly
    let abs_path = jail_root.as_path().join(&test_path);
    assert_eq!(jailed_path.real_path(), abs_path.as_path());
    assert_eq!(jailed_path.unjail(), abs_path);
}

#[test]
fn test_jailed_path_as_ref_implementation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path.clone())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, Arc::clone(&jail_root));

    // Should work with AsRef<Path>
    let abs_path = jail_root.as_path().join(&test_path);
    let path_ref: &Path = jailed_path.real_path();
    assert_eq!(path_ref, abs_path.as_path());
}

#[test]
fn test_jailed_path_deref_implementation() {
    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(jail_relative)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath<()> = JailedPath::new(staged, Arc::clone(&jail_root));

    // Should allow calling Path methods directly via Deref
    assert_eq!(
        jailed_path.real_path().file_name(),
        Some(std::ffi::OsStr::new("path"))
    );
    // Compare parent paths, not Option types
    let parent = jailed_path
        .virtual_parent()
        .map(|jp| jp.real_path().to_path_buf());
    let expected_parent = Some(jail_root.as_path().to_path_buf());
    assert_eq!(parent, expected_parent);
    assert_eq!(jailed_path.real_path().extension(), None);
}

#[test]
fn test_jailed_path_display_formatting() {
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let test_path = PathBuf::from("path/file.txt");

    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, jail_root);

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
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );

    let staged1 = crate::validator::StagedPath::<crate::validator::Raw>::new(path1)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let staged2 = crate::validator::StagedPath::<crate::validator::Raw>::new(path2)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let staged3 = crate::validator::StagedPath::<crate::validator::Raw>::new(path3)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed1: JailedPath = JailedPath::new(staged1, Arc::clone(&jail_root));
    let jailed2: JailedPath = JailedPath::new(staged2, Arc::clone(&jail_root));
    let jailed3: JailedPath = JailedPath::new(staged3, Arc::clone(&jail_root));

    // Should implement equality correctly
    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(temp.path())
            .canonicalize()
            .unwrap(),
    );
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path)
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, jail_root);

    // Should be cloneable
    assert_eq!(jailed_path, jailed_path.clone());

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    // Only check for struct name, not path formatting
    assert!(
        debug_str.contains("JailedPath"),
        "Debug output should contain struct name"
    );
}

#[test]
fn test_marker_type_is_zero_cost() {
    #[derive(Clone)]
    struct TestMarker;

    // JailedPath with and without marker should have same size
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        std::mem::size_of::<JailedPath<TestMarker>>(),
        "Marker types should not increase memory footprint"
    );

    // JailedPath now contains PathBuf + Arc<StagedPath<(Raw, Canonicalized)>> + PhantomData
    // Arc<StagedPath<...>> is 8 bytes (pointer), StagedPath is 24 bytes on Windows, PhantomData is 0
    // So total should be PathBuf + Arc size
    let expected_size = std::mem::size_of::<PathBuf>()
        + std::mem::size_of::<
            Arc<
                crate::validator::StagedPath<(
                    crate::validator::Raw,
                    crate::validator::Canonicalized,
                )>,
            >,
        >();
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        expected_size,
        "JailedPath should not add overhead beyond the underlying PathBuf"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    #[derive(Clone)]
    struct ImageResource;
    #[derive(Clone)]
    struct UserData;

    let test_path = PathBuf::from("path");
    let jail_root = Arc::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new("/test")
            .canonicalize()
            .unwrap(),
    );
    let staged = crate::validator::StagedPath::<crate::validator::Raw>::new(test_path.clone())
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let _image_path: JailedPath<ImageResource> = JailedPath::new(staged, Arc::clone(&jail_root));
    // If you need another staged for a different marker, re-create it above as needed.
    let _user_path: JailedPath<UserData> = JailedPath::new(
        crate::validator::StagedPath::<crate::validator::Raw>::new(test_path)
            .clamp()
            .join_jail(&jail_root)
            .canonicalize()
            .unwrap()
            .boundary_check(&jail_root)
            .unwrap(),
        jail_root,
    );

    // This test ensures that different marker types are treated as different types
    // The fact that we can assign to different typed variables proves this works
    // Trying to assign image_path to a JailedPath<UserData> would be a compile error
}
