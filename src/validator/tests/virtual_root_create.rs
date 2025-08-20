use crate::validator::virtual_root::VirtualRoot;

#[test]
fn test_virtual_root_try_new_create() {
    let base = tempfile::tempdir().expect("tempdir");
    let new_dir = base.path().join("new_vroot_dir");

    // Ensure it doesn't exist yet
    assert!(!new_dir.exists(), "new_dir should not exist yet");

    // try_new_create should create the directory and return a usable VirtualRoot
    let vroot = VirtualRoot::<()>::try_new_create(&new_dir).expect("try_new_create");

    // Directory now exists
    assert!(new_dir.exists(), "new_dir should have been created");

    // vroot.path() should point to the canonicalized directory
    let canon = new_dir.canonicalize().expect("canonicalize");
    assert_eq!(vroot.path(), canon.as_os_str());
}
