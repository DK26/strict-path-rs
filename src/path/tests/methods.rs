use crate::validator::jail::Jail;

#[test]
fn test_virtual_path_join_and_parent() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed = jail.try_path("foo/bar.txt").unwrap();
    let virtual_path = jailed.virtualize();

    // join (inside jail)
    let joined = virtual_path.join_virtual("baz.txt").unwrap();
    assert_eq!(format!("{joined}"), "/foo/bar.txt/baz.txt");

    // join (outside jail, expect clamping)
    let outside = virtual_path.join_virtual("../../../../etc/passwd").unwrap();
    assert_eq!(format!("{outside}"), "/etc/passwd");

    // parent (inside jail)
    let parent = virtual_path.parent_virtual().unwrap();
    assert!(parent.is_some());
    let actual_parent = parent.unwrap();
    assert_eq!(format!("{actual_parent}"), "/foo");

    // parent (at jail root)
    let root_jailed = jail.try_path("").unwrap();
    let root_virtual = root_jailed.virtualize();
    let parent_none = root_virtual.parent_virtual().unwrap();
    assert!(parent_none.is_none());
}

#[test]
fn test_virtual_path_pathbuf_methods() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed = jail.try_path("foo/bar.txt").unwrap();
    let virtual_path = jailed.virtualize();

    // with_file_name (inside jail)
    let with_name = virtual_path.with_file_name_virtual("newname.txt").unwrap();
    assert_eq!(format!("{with_name}"), "/foo/newname.txt");

    // with_file_name (potential escape attempt)
    let root_jailed = jail.try_path("").unwrap();
    let root_virtual = root_jailed.virtualize();
    let escape_attempt = root_virtual
        .with_file_name_virtual("../../etc/passwd")
        .unwrap();
    assert_eq!(format!("{escape_attempt}"), "/etc/passwd");

    // with_extension (inside jail)
    let with_ext = virtual_path.with_extension_virtual("log").unwrap();
    assert_eq!(format!("{with_ext}"), "/foo/bar.log");

    // unjail
    let jailed_again = virtual_path.unvirtual();
    let inner = jailed_again.unjail();
    let expected_path = jail.path().join("foo/bar.txt");
    assert_eq!(inner.to_string_lossy(), expected_path.to_string_lossy());
}
