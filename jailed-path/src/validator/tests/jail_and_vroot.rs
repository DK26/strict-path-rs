use crate::validator::jail::Jail;
use crate::VirtualRoot;

#[test]
fn test_jail_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("made_by_try_new_create");
    assert!(!target.exists());
    let jail = Jail::<()>::try_new_create(&target).unwrap();
    assert!(target.exists());
    // path() should point to the created directory
    assert_eq!(
        jail.interop_path(),
        target.canonicalize().unwrap().as_os_str()
    );
}

#[test]
fn test_virtual_root_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("vroot_dir");
    let vroot: VirtualRoot = VirtualRoot::try_new_create(&root).unwrap();
    assert!(root.exists());
    assert_eq!(
        vroot.interop_path(),
        root.canonicalize().unwrap().as_os_str()
    );
}

#[test]
fn test_jailed_join_and_virtual_join_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(tmp.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(tmp.path()).unwrap();

    let jp = jail.jailed_join("alpha/beta.txt").unwrap();
    assert!(jp.jailedpath_starts_with(jail.interop_path()));

    let vp = vroot.virtual_join("alpha/beta.txt").unwrap();
    assert_eq!(vp.virtualpath_to_string_lossy(), "/alpha/beta.txt");
    // Conversions are explicit and consistent
    assert_eq!(
        vp.jailedpath_to_string_lossy(),
        jp.jailedpath_to_string_lossy()
    );
}
