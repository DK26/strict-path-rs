use crate::Jail;

#[test]
fn test_virtual_path_accessors_and_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed = jail.try_path("foo/bar.txt").unwrap();
    let virtual_path = jailed.virtualize();

    // file name
    let fname = virtual_path.file_name_virtual().expect("file name");
    assert_eq!(fname.to_string_lossy(), "bar.txt");

    // file stem
    let stem = virtual_path.file_stem_virtual().expect("file stem");
    assert_eq!(stem.to_string_lossy(), "bar");

    // extension
    let ext = virtual_path.extension_virtual().expect("ext");
    assert_eq!(ext.to_string_lossy(), "txt");

    // starts_with / ends_with (virtual)
    assert!(virtual_path.starts_with_virtual("foo"));
    assert!(virtual_path.ends_with_virtual("bar.txt"));

    // parent_virtual
    let parent = virtual_path.parent_virtual().unwrap().unwrap();
    assert_eq!(parent.virtualpath_to_string(), "/foo");
}
