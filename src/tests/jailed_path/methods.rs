use crate::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_join_and_parent() {
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
    let jail_relative = PathBuf::from("foo/bar.txt");
    let validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(jail_relative)
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();

    let jailed: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);

    // join (inside jail)
    let joined = jailed.join("baz.txt");
    assert!(joined.is_some(), "join failed: {joined:?}");
    let actual = joined.unwrap();
    assert_eq!(actual.to_string_virtual(), "/foo/bar.txt/baz.txt");

    // join (outside jail, expect clamping)
    let outside = jailed.join("../../../../etc/passwd");
    assert!(
        outside.is_some(),
        "Expected clamping to jail root, got None"
    );
    let clamped = outside.unwrap();
    assert_eq!(clamped.to_string_virtual(), "/etc/passwd");

    // parent (inside jail)
    let parent = jailed.parent();
    assert!(parent.is_some());
    let actual_parent = parent.unwrap();
    assert_eq!(actual_parent.to_string_virtual(), "/foo");

    // parent (at jail root)
    let jail_validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(PathBuf::new())
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jail: JailedPath<()> = JailedPath::new(Arc::clone(&jail_root), jail_validated_path);
    let parent_none = jail.parent();
    assert!(parent_none.is_none());
}

#[test]
fn test_jailed_path_pathbuf_methods() {
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

    let jail_relative = PathBuf::from("foo/bar.txt");
    let validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(jail_relative)
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), validated_path);

    // join (inside jail)
    let joined = jailed.join("baz.txt");
    assert!(joined.is_some());
    assert_eq!(joined.unwrap().to_string_virtual(), "/foo/bar.txt/baz.txt");

    // join (outside jail)
    let outside = jailed.join("../../../../etc/passwd");
    assert!(outside.is_some());
    assert_eq!(outside.unwrap().to_string_virtual(), "/etc/passwd");

    // parent (inside jail)
    let parent = jailed.parent();
    assert!(parent.is_some());
    assert_eq!(parent.unwrap().to_string_virtual(), "/foo");

    // parent (at jail root)
    let jail_validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(PathBuf::new())
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jail: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), jail_validated_path);
    assert!(jail.parent().is_none());

    // with_file_name (inside jail)
    let with_name = jailed.with_file_name("newname.txt");
    assert!(with_name.is_some());
    assert_eq!(with_name.unwrap().to_string_virtual(), "/foo/newname.txt");

    // with_file_name (potential escape attempt)
    let root_validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(PathBuf::new())
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let root: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), root_validated_path);
    let escape_attempt = root.with_file_name("../../etc/passwd");
    assert!(escape_attempt.is_some());
    assert_eq!(escape_attempt.unwrap().to_string_virtual(), "/etc/passwd");

    // with_extension (inside jail)
    let with_ext = jailed.with_extension("log");
    assert!(with_ext.is_some());
    assert_eq!(with_ext.unwrap().to_string_virtual(), "/foo/bar.log");

    // unjail
    let inner = jailed.unjail();
    let expected_path = jail_root.join("foo/bar.txt");
    assert_eq!(inner.to_string_lossy(), expected_path.to_string_lossy());
}
