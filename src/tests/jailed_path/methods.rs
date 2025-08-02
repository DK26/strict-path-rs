use crate::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_try_join_and_try_parent() {
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("foo/bar.txt");
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(jail_relative)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();

    // Only check for jail-relativity before join_jail/canonicalize if needed.
    // After join_jail/canonicalize, validated_path.as_path() should be absolute and include jail_root.
    let jailed: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);

    // try_virtual_join (inside jail)
    let joined = jailed.try_virtual_join("baz.txt");
    assert!(joined.is_ok(), "try_virtual_join failed: {joined:?}");
    let actual = joined.as_ref().unwrap().real_path();
    let expected = jail_root.join("foo/bar.txt/baz.txt");
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
    assert!(clamped.real_path().starts_with(&*jail_root));

    // try_parent (inside jail)
    let parent = jailed.try_virtual_parent();
    assert!(parent.is_ok());
    let expected_parent = jail_root.join("foo");
    let actual_parent = parent.as_ref().unwrap().real_path();
    assert_eq!(
        actual_parent, expected_parent,
        "actual: {actual_parent:?}, expected: {expected_parent:?}"
    );

    // try_parent (at jail root, use empty PathBuf for virtual root)
    let jail_validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(PathBuf::new())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jail: JailedPath<()> = JailedPath::new(Arc::clone(&jail_root), jail_validated_path);
    let parent_none = jail.try_virtual_parent();
    assert!(parent_none.is_err());
}

#[test]
fn test_jailed_path_pathbuf_methods() {
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );

    // Use jail_relative as a relative path, not rooted at jail_root
    let jail_relative = PathBuf::from("foo/bar.txt");
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(jail_relative.clone())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), validated_path);

    // safe_join (inside jail)
    // The jailed path represents "/foo/bar.txt" virtually
    // Joining "baz.txt" should result in "/foo/bar.txt/baz.txt" virtually
    // Which translates to jail_root/foo/bar.txt/baz.txt in real path
    let joined = jailed.virtual_join("baz.txt");
    assert!(joined.is_some());
    let actual = joined.as_ref().unwrap().real_path();

    // The expected path should be: jail_root/foo/bar.txt/baz.txt
    // This is because we're joining "baz.txt" to the virtual path "/foo/bar.txt"
    let expected = jail_root.join("foo").join("bar.txt").join("baz.txt");
    assert_eq!(actual, expected);

    // virtual_join (outside jail)
    let outside = jailed.virtual_join("../../../../etc/passwd");
    assert!(outside.is_some()); // This should be clamped, not rejected
                                // The result should be clamped to jail root
    let clamped = outside.unwrap();
    // After clamping ../../../../etc/passwd from /foo/bar.txt, we should get /etc/passwd
    // (or possibly just /passwd depending on how many levels up we can go)
    assert!(clamped.real_path().starts_with(&*jail_root));

    // parent (inside jail)
    let parent = jailed.virtual_parent();
    assert!(parent.is_some());
    let expected_parent = &*jail_root.join("foo");
    let actual_parent = parent.as_ref().unwrap().real_path();
    assert_eq!(actual_parent, expected_parent);

    // parent (at jail root)
    // To create a JailedPath representing the virtual root "/", use an empty path
    let jail_validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(PathBuf::new())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jail: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), jail_validated_path);
    assert!(jail.virtual_parent().is_none());

    // with_file_name (inside jail)
    let with_name = jailed.virtual_with_file_name("newname.txt");
    assert!(with_name.is_some());
    let joined_path = jail_root.join("foo/bar.txt");
    let expected_with_name = joined_path.parent().unwrap().join("newname.txt");
    let actual_with_name = with_name.as_ref().unwrap().real_path();
    assert_eq!(
        actual_with_name, expected_with_name,
        "actual: {actual_with_name:?}, expected: {expected_with_name:?}"
    );

    // with_file_name (potential escape attempt - should be clamped, not rejected)
    let root_validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(PathBuf::new())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let root: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), root_validated_path);
    let escape_attempt = root.virtual_with_file_name("../../etc/passwd");
    assert!(escape_attempt.is_some()); // Should be clamped, not rejected
                                       // The result should still be within the jail
    assert!(escape_attempt.unwrap().real_path().starts_with(&*jail_root));

    // with_extension (inside jail)
    let with_ext = jailed.virtual_with_extension("log");
    assert!(with_ext.is_some());
    let mut joined_path = jail_root.join("foo/bar.txt");
    joined_path.set_extension("log");
    let expected_with_ext = joined_path;
    let actual_with_ext = with_ext.as_ref().unwrap().real_path();
    assert_eq!(
        actual_with_ext, expected_with_ext,
        "actual: {actual_with_ext:?}, expected: {expected_with_ext:?}"
    );

    // unjail
    let inner = jailed.unjail();
    assert_eq!(inner, &*jail_root.join("foo/bar.txt"));

    // to_bytes and into_bytes (platform-specific)
    // (Cannot use jailed after move above, so re-create)
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(jail_relative)
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed: crate::jailed_path::JailedPath<()> =
        crate::jailed_path::JailedPath::new(Arc::clone(&jail_root), validated_path);
    let bytes = jailed.to_bytes();
    let into_bytes = jailed.into_bytes();
    assert_eq!(bytes, into_bytes);
}
