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

#[cfg(feature = "tempfile")]
#[test]
fn test_path_boundary_temp_dir_arc_extends_raii() {
    let boundary: PathBoundary = PathBoundary::try_new_temp().expect("temp boundary");
    assert!(boundary.metadata().is_ok());

    let temp_dir_handle = boundary.temp_dir_arc().expect("missing tempdir handle");
    let boundary_path = std::path::PathBuf::from(boundary.interop_path().to_os_string());

    drop(boundary);
    {
        let reopened: PathBoundary = PathBoundary::try_new(&boundary_path)
            .expect("boundary should exist while handle alive");
        assert!(reopened.metadata().is_ok());
    }

    drop(temp_dir_handle);
    assert!(PathBoundary::<()>::try_new(&boundary_path).is_err());
}

#[cfg(feature = "tempfile")]
#[test]
fn test_virtual_root_try_new_temp_raii_and_virtual_join() {
    let vroot: VirtualRoot = VirtualRoot::try_new_temp().expect("virtual root creation");
    assert!(vroot.metadata().is_ok());
    let root_path = std::path::PathBuf::from(vroot.interop_path().to_os_string());

    let tenant_file = vroot
        .virtual_join("tenant/document.pdf")
        .expect("virtual join");
    assert_eq!(
        tenant_file.virtualpath_display().to_string(),
        "/tenant/document.pdf"
    );

    drop(tenant_file);
    drop(vroot);
    assert!(VirtualRoot::<()>::try_new(&root_path).is_err());
}

#[cfg(feature = "tempfile")]
#[test]
fn test_virtual_root_try_new_temp_with_prefix_behaves_like_builder() {
    let vroot: VirtualRoot =
        VirtualRoot::try_new_temp_with_prefix("session-").expect("virtual root temp prefix");
    assert!(vroot.metadata().is_ok());
    let root_path = std::path::PathBuf::from(vroot.interop_path().to_os_string());
    let dir_name = root_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("dir name utf8");
    assert!(dir_name.starts_with("session-"));

    drop(vroot);
    assert!(VirtualRoot::<()>::try_new(&root_path).is_err());
}
#[cfg(feature = "tempfile")]
#[test]
fn test_path_boundary_metadata_reflects_filesystem() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let boundary: PathBoundary = PathBoundary::try_new(&root_path).unwrap();

    let metadata = boundary.metadata().unwrap();
    assert!(metadata.is_dir());

    std::fs::remove_dir_all(&root_path).unwrap();
    assert!(boundary.metadata().is_err());
}

#[cfg(feature = "tempfile")]
#[test]
fn test_virtual_root_metadata_reflects_filesystem() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root_path = temp_dir.path().to_path_buf();
    let vroot: VirtualRoot = VirtualRoot::try_new(&root_path).unwrap();

    let metadata = vroot.metadata().unwrap();
    assert!(metadata.is_dir());

    std::fs::remove_dir_all(&root_path).unwrap();
    assert!(vroot.metadata().is_err());
}
