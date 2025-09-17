use crate::{PathBoundary, VirtualRoot};

#[test]
fn test_strict_and_virtual_path_read_dir() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    // Create a directory with children
    let items_dir = boundary.strict_join("items").unwrap();
    items_dir.create_dir_all().unwrap();
    let a_file = items_dir.strict_join("a.txt").unwrap();
    a_file.write("A").unwrap();
    let b_file = items_dir.strict_join("b.log").unwrap();
    b_file.write("B").unwrap();
    let sub_dir = items_dir.strict_join("sub").unwrap();
    sub_dir.create_dir_all().unwrap();

    // StrictPath::read_dir on a directory path
    let mut names: Vec<String> = items_dir
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["a.txt", "b.log", "sub"]);

    // Re-join discovered names via strict_join and ensure they exist
    for name in &names {
        let child = items_dir.strict_join(name).unwrap();
        assert!(child.exists());
    }

    // VirtualPath::read_dir delegates; re-join via virtual_join
    let vdir = items_dir.virtualize();
    let mut vnames: Vec<String> = vdir
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    vnames.sort();
    assert_eq!(vnames, names);

    for name in &vnames {
        let vchild = vdir.virtual_join(name).unwrap();
        assert!(vchild.exists());
    }
}

#[test]
fn test_conversion_helpers_for_strict_and_virtual_path() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    let dir = boundary.strict_join("workspace").unwrap();
    dir.create_dir_all().unwrap();

    // StrictPath -> PathBoundary conversion symmetry
    let b1 = dir.clone().try_into_boundary();
    assert_eq!(b1, boundary);

    // Simulate boundary deletion, then try_into_boundary_create recreates it
    let boundary_path = std::path::PathBuf::from(boundary.interop_path().to_os_string());
    std::fs::remove_dir_all(&boundary_path).unwrap();
    let b2 = dir.try_into_boundary_create();
    assert!(b2.exists());
    assert!(std::path::Path::new(&boundary_path).exists());

    // VirtualPath -> VirtualRoot conversion symmetry
    let vfile = b2.strict_join("workspace/note.txt").unwrap().virtualize();
    let vroot: VirtualRoot = vfile.clone().try_into_root();
    assert_eq!(vroot.as_unvirtual(), &b2);

    // Simulate root deletion, then try_into_root_create recreates it
    let root_path = std::path::PathBuf::from(vroot.interop_path().to_os_string());
    std::fs::remove_dir_all(&root_path).unwrap();
    let vroot2: VirtualRoot = vfile.try_into_root_create();
    assert!(vroot2.exists());
    assert!(std::path::Path::new(&root_path).exists());
}
