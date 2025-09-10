use crate::validator::jail::Jail;

#[test]
fn test_virtual_path_accessors_and_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed = jail.jailed_join("foo/bar.txt").unwrap();
    let virtual_path = jailed.virtualize();

    // file name
    let fname = virtual_path.virtualpath_file_name().expect("file name");
    assert_eq!(fname.to_string_lossy(), "bar.txt");

    // file stem
    let stem = virtual_path.virtualpath_file_stem().expect("file stem");
    assert_eq!(stem.to_string_lossy(), "bar");

    // extension
    let ext = virtual_path.virtualpath_extension().expect("ext");
    assert_eq!(ext.to_string_lossy(), "txt");

    // starts_with / ends_with (virtual)
    assert!(virtual_path.virtualpath_starts_with("foo"));
    assert!(virtual_path.virtualpath_ends_with("bar.txt"));

    // virtualpath_parent
    let parent = virtual_path.virtualpath_parent().unwrap().unwrap();
    assert_eq!(parent.virtualpath_to_string_lossy(), "/foo");
}
