use crate::PathBoundary;
use crate::VirtualRoot;

#[test]
fn test_restriction_try_new_create_and_path() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("made_by_try_new_create");
    assert!(!target.exists());
    let boundary = PathBoundary::<()>::try_new_create(&target).unwrap();
    assert!(target.exists());
    // path() should point to the created directory
    assert_eq!(
        boundary.interop_path(),
        target.canonicalize().unwrap().as_os_str()
    );
}

#[test]
fn test_path_boundary_into_strictpath_returns_root() {
    let tmp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(tmp.path()).unwrap();

    let root = boundary.into_strictpath().unwrap();
    assert!(root.is_dir());
    assert_eq!(
        root.interop_path(),
        tmp.path().canonicalize().unwrap().as_os_str()
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
    let boundary: PathBoundary = PathBoundary::try_new(tmp.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(tmp.path()).unwrap();

    let jp = boundary.strict_join("alpha/beta.txt").unwrap();
    assert!(jp.strictpath_starts_with(boundary.interop_path()));

    let vp = vroot.virtual_join("alpha/beta.txt").unwrap();
    assert_eq!(vp.virtualpath_display().to_string(), "/alpha/beta.txt");
    // Conversions are explicit and consistent
    assert_eq!(
        vp.as_unvirtual().strictpath_to_string_lossy(),
        jp.strictpath_to_string_lossy()
    );
}
