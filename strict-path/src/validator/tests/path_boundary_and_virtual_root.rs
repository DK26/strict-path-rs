use crate::PathBoundary;
use crate::VirtualRoot;

#[test]
fn test_restriction_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("made_by_try_new_create");
    assert!(!target.exists());
    let test_dir = PathBoundary::<()>::try_new_create(&target).unwrap();
    assert!(target.exists());
    // strictpath_display should point to the created directory
    assert_eq!(
        test_dir.strictpath_display().to_string(),
        target.canonicalize().unwrap().display().to_string()
    );
}

#[test]
fn test_path_boundary_into_strictpath_returns_root() {
    let tmp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(tmp.path()).unwrap();

    let root = test_dir.into_strictpath().unwrap();
    assert!(root.is_dir());
    assert_eq!(
        root.strictpath_display().to_string(),
        tmp.path().canonicalize().unwrap().display().to_string()
    );
}

#[test]
fn test_virtual_root_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("vroot_dir");
    let vroot: VirtualRoot = VirtualRoot::try_new_create(&root).unwrap();
    assert!(root.exists());
    assert_eq!(
        vroot.as_unvirtual().strictpath_display().to_string(),
        root.canonicalize().unwrap().display().to_string()
    );
}

#[test]
fn test_virtual_root_into_virtualpath_returns_root() {
    let tmp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(tmp.path()).unwrap();

    let root_virtual = vroot.into_virtualpath().unwrap();
    assert_eq!(root_virtual.virtualpath_display().to_string(), "/");
    assert!(root_virtual.as_unvirtual().is_dir());
}

#[test]
fn test_jailed_join_and_virtual_join_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new(tmp.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(tmp.path()).unwrap();

    let jp = test_dir.strict_join("alpha/beta.txt").unwrap();
    assert!(jp.strictpath_starts_with(test_dir.interop_path()));

    let vp = vroot.virtual_join("alpha/beta.txt").unwrap();
    assert_eq!(vp.virtualpath_display().to_string(), "/alpha/beta.txt");
    // Conversions are explicit and consistent
    assert_eq!(
        vp.as_unvirtual().strictpath_display().to_string(),
        jp.strictpath_display().to_string()
    );
}
