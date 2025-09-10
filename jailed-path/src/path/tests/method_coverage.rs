use crate::{Jail, JailedPathError};

#[test]
fn test_jailed_path_accessors_and_manipulation() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    // Create a file and directories inside the jail to exercise I/O/metadata too.
    let dir = jail.jailed_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let file = jail.jailed_join("dir/file.txt").unwrap();
    file.write_string("hello").unwrap();

    // Basic accessors
    assert!(file.jailedpath_to_str().is_some());
    assert_eq!(
        file.jailedpath_to_string_lossy(),
        file.interop_path().to_string_lossy()
    );

    // Components
    assert_eq!(
        file.jailedpath_file_name().unwrap().to_string_lossy(),
        "file.txt"
    );
    assert_eq!(
        file.jailedpath_file_stem().unwrap().to_string_lossy(),
        "file"
    );
    assert_eq!(
        file.jailedpath_extension().unwrap().to_string_lossy(),
        "txt"
    );

    // Starts/ends checks
    assert!(file.jailedpath_starts_with(jail.path()));
    assert!(file.jailedpath_ends_with("file.txt"));

    // Parent
    let parent = file.jailedpath_parent().unwrap().unwrap();
    assert!(parent.jailedpath_ends_with("dir"));

    // jailed_join (appends relative component)
    let joined = file.jailed_join("sibling.log").unwrap();
    assert!(joined.jailedpath_ends_with("file.txt/sibling.log"));

    // with file name/extension
    let renamed = file.jailedpath_with_file_name("renamed.bin").unwrap();
    assert!(renamed.jailedpath_ends_with("dir/renamed.bin"));
    let changed_ext = file.jailedpath_with_extension("bak").unwrap();
    assert!(changed_ext.jailedpath_ends_with("dir/file.bak"));

    // Error case: cannot apply extension at jail root (no file name)
    let root = jail.jailed_join("").unwrap();
    let err = root.jailedpath_with_extension("x").unwrap_err();
    match err {
        JailedPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Unexpected error: {other:?}"),
    }

    // I/O operations sanity
    assert!(file.exists());
    assert!(file.is_file());
    assert!(!dir.is_file());
    assert!(dir.is_dir());
    let md = file.metadata().unwrap();
    assert!(md.len() > 0);
    assert_eq!(file.read_to_string().unwrap(), "hello");
    let bytes = file.read_bytes().unwrap();
    assert_eq!(bytes, b"hello");

    // Removal APIs
    let tmp_sub = jail.jailed_join("dir/tmp").unwrap();
    tmp_sub.create_dir_all().unwrap();
    let tmp_file = jail.jailed_join("dir/tmp/note.txt").unwrap();
    tmp_file.write_string("bye").unwrap();
    assert!(tmp_file.exists());
    tmp_file.remove_file().unwrap();
    assert!(!tmp_file.exists());
    tmp_sub.remove_dir().unwrap();
    assert!(!tmp_sub.exists());
    let deep_dir = jail.jailed_join("deep/a/b").unwrap();
    deep_dir.create_dir_all().unwrap();
    let deep_root = jail.jailed_join("deep").unwrap();
    deep_root.remove_dir_all().unwrap();
    assert!(!deep_root.exists());
}

#[test]
fn test_virtual_path_components_and_checks() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();
    let jp = jail.jailed_join("a/b.txt").unwrap();
    let vp = jp.clone().virtualize();

    // Virtual display/string is rooted
    assert_eq!(vp.virtualpath_to_string_lossy(), "/a/b.txt");

    // Virtual components
    assert_eq!(
        vp.virtualpath_file_name().unwrap().to_string_lossy(),
        "b.txt"
    );
    assert_eq!(vp.virtualpath_file_stem().unwrap().to_string_lossy(), "b");
    assert_eq!(vp.virtualpath_extension().unwrap().to_string_lossy(), "txt");

    // Starts/ends checks
    assert!(vp.virtualpath_starts_with("a"));
    assert!(vp.virtualpath_ends_with("b.txt"));

    // Virtual path manipulation
    let vparent = vp.virtualpath_parent().unwrap().unwrap();
    assert_eq!(vparent.virtualpath_to_string_lossy(), "/a");
    let vsib = vp.virtual_join("c.log").unwrap();
    assert_eq!(vsib.virtualpath_to_string_lossy(), "/a/b.txt/c.log");

    // Cross accessors should match
    assert_eq!(
        vp.jailedpath_to_string_lossy(),
        jp.jailedpath_to_string_lossy()
    );
    assert_eq!(
        vp.interop_path().to_string_lossy(),
        jp.interop_path().to_string_lossy()
    );

    // Delegated I/O operations from VirtualPath
    let vfile = jail.jailed_join("delegated/x.txt").unwrap().virtualize();
    let vdir = jail.jailed_join("delegated").unwrap().virtualize();
    vdir.create_dir_all().unwrap();
    vfile.write_bytes(b"vdata").unwrap();
    assert!(vfile.exists());
    assert!(vfile.is_file());
    assert!(vdir.is_dir());
    assert_eq!(vfile.read_bytes().unwrap(), b"vdata");
    assert_eq!(vfile.read_to_string().unwrap(), "vdata");
    vfile.remove_file().unwrap();
    assert!(!vfile.exists());
}
