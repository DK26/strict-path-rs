use crate::validator::jail::Jail;
use crate::validator::virtual_root::VirtualRoot;

#[test]
fn test_jail_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("made_by_try_new_create");
    assert!(!target.exists());
    let jail = Jail::<()>::try_new_create(&target).unwrap();
    assert!(target.exists());
    // path() should point to the created directory
    assert_eq!(jail.path().to_path_buf(), target.canonicalize().unwrap());
}

#[test]
fn test_virtual_root_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("vroot_dir");
    let vroot = VirtualRoot::<()>::try_new_create(&root).unwrap();
    assert!(root.exists());
    assert_eq!(
        vroot.path().canonicalize().unwrap(),
        root.canonicalize().unwrap()
    );
}

#[test]
fn test_systempath_join_and_virtualpath_join_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(tmp.path()).unwrap();
    let vroot = VirtualRoot::<()>::try_new(tmp.path()).unwrap();

    let jp = jail.systempath_join("alpha/beta.txt").unwrap();
    assert!(jp.systempath_starts_with(jail.path()));

    let vp = vroot.virtualpath_join("alpha/beta.txt").unwrap();
    assert_eq!(vp.virtualpath_to_string_lossy(), "/alpha/beta.txt");
    // Conversions are explicit and consistent
    assert_eq!(
        vp.systempath_to_string_lossy(),
        jp.systempath_to_string_lossy()
    );
}
