use crate::{PathBoundary, StrictPathError};

#[test]
fn test_strict_path_accessors_and_manipulation() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Create a file and directories inside the PathBoundary to exercise I/O/metadata too.
    let dir = restriction.strict_join("dir").unwrap();
    dir.create_dir_all().unwrap();
    let file = restriction.strict_join("dir/file.txt").unwrap();
    file.write("hello").unwrap();

    // Basic accessors
    assert!(file.strictpath_to_str().is_some());
    assert_eq!(
        file.strictpath_to_string_lossy(),
        file.interop_path().to_string_lossy()
    );

    // Components
    assert_eq!(
        file.strictpath_file_name().unwrap().to_string_lossy(),
        "file.txt"
    );
    assert_eq!(
        file.strictpath_file_stem().unwrap().to_string_lossy(),
        "file"
    );
    assert_eq!(
        file.strictpath_extension().unwrap().to_string_lossy(),
        "txt"
    );

    // Starts/ends checks
    assert!(file.strictpath_starts_with(restriction.path()));
    assert!(file.strictpath_ends_with("file.txt"));

    // Parent
    let parent = file.strictpath_parent().unwrap().unwrap();
    assert!(parent.strictpath_ends_with("dir"));

    // strict_join (appends relative component)
    let joined = file.strict_join("sibling.log").unwrap();
    assert!(joined.strictpath_ends_with("file.txt/sibling.log"));

    // with file name/extension
    let renamed = file.strictpath_with_file_name("renamed.bin").unwrap();
    assert!(renamed.strictpath_ends_with("dir/renamed.bin"));
    let changed_ext = file.strictpath_with_extension("bak").unwrap();
    assert!(changed_ext.strictpath_ends_with("dir/file.bak"));

    // Error case: cannot apply extension at PathBoundary root (no file name)
    let root: crate::path::strict_path::StrictPath<()> =
        crate::path::strict_path::StrictPath::with_boundary(temp.path()).unwrap();
    let err = root.strictpath_with_extension("x").unwrap_err();
    match err {
        StrictPathError::PathEscapesBoundary { .. } => {}
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
    let bytes = file.read().unwrap();
    assert_eq!(bytes, b"hello");

    // Removal APIs
    let tmp_sub = restriction.strict_join("dir/tmp").unwrap();
    tmp_sub.create_dir_all().unwrap();
    let tmp_file = restriction.strict_join("dir/tmp/note.txt").unwrap();
    tmp_file.write("bye").unwrap();
    assert!(tmp_file.exists());
    tmp_file.remove_file().unwrap();
    assert!(!tmp_file.exists());
    tmp_sub.remove_dir().unwrap();
    assert!(!tmp_sub.exists());
    let deep_dir = restriction.strict_join("deep/a/b").unwrap();
    deep_dir.create_dir_all().unwrap();
    let deep_root = restriction.strict_join("deep").unwrap();
    deep_root.remove_dir_all().unwrap();
    assert!(!deep_root.exists());
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_virtual_path_components_and_checks() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let jp = restriction.strict_join("a/b.txt").unwrap();
    let vp = jp.clone().virtualize();

    // Virtual display/string is rooted
    assert_eq!(vp.virtualpath_display().to_string(), "/a/b.txt");

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
    assert_eq!(vparent.virtualpath_display().to_string(), "/a");
    let vsib = vp.virtual_join("c.log").unwrap();
    assert_eq!(vsib.virtualpath_display().to_string(), "/a/b.txt/c.log");

    // Cross accessors should match
    assert_eq!(
        vp.as_unvirtual().strictpath_to_string_lossy(),
        jp.strictpath_to_string_lossy()
    );
    assert_eq!(
        vp.interop_path().to_string_lossy(),
        jp.interop_path().to_string_lossy()
    );

    // Delegated I/O operations from VirtualPath
    let vfile = restriction
        .strict_join("delegated/x.txt")
        .unwrap()
        .virtualize();
    let vdir = restriction.strict_join("delegated").unwrap().virtualize();
    vdir.create_dir_all().unwrap();
    vfile.write(b"vdata").unwrap();
    assert!(vfile.exists());
    assert!(vfile.is_file());
    assert!(vdir.is_dir());
    assert_eq!(vfile.read().unwrap(), b"vdata");
    assert_eq!(vfile.read_to_string().unwrap(), "vdata");
    vfile.remove_file().unwrap();
    assert!(!vfile.exists());
}
