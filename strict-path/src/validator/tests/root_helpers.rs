use crate::{PathBoundary, VirtualRoot};

#[test]
fn test_path_boundary_root_helpers_read_and_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let root_path = tmp.path().join("rootdir");
    let boundary: PathBoundary = PathBoundary::try_new_create(&root_path).unwrap();

    // Create some entries inside the root
    let file = boundary.strict_join("file.txt").unwrap();
    file.write("x").unwrap();
    let sub = boundary.strict_join("sub").unwrap();
    sub.create_dir_all().unwrap();

    // read_dir on the root
    let mut names: Vec<String> = boundary
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["file.txt", "sub"]);

    // remove_dir should fail if not empty
    assert!(boundary.remove_dir().is_err());

    // remove_dir_all removes the whole tree
    boundary.remove_dir_all().unwrap();
    assert!(!root_path.exists());
}

#[test]
fn test_virtual_root_root_helpers_read_and_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let root_path = tmp.path().join("vrootdir");
    let vroot: VirtualRoot = VirtualRoot::try_new_create(&root_path).unwrap();

    // Create some entries inside the root
    let file = vroot.virtual_join("file.txt").unwrap();
    file.write("y").unwrap();
    let sub = vroot.virtual_join("sub").unwrap();
    sub.create_dir_all().unwrap();

    // read_dir on the virtual root
    let mut names: Vec<String> = vroot
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["file.txt", "sub"]);

    // remove_dir should fail if not empty
    assert!(vroot.remove_dir().is_err());

    // remove_dir_all removes the whole tree
    vroot.remove_dir_all().unwrap();
    assert!(!root_path.exists());
}
