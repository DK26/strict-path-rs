use crate::path::strict_path::StrictPath;
#[cfg(feature = "virtual-path")]
use crate::path::virtual_path::VirtualPath;
use crate::PathBoundary;
#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_marker_type_is_zero_cost() {
    #[derive(Clone)]
    struct TestMarker;

    assert_eq!(
        std::mem::size_of::<StrictPath<()>>(),
        std::mem::size_of::<StrictPath<TestMarker>>(),
        "Marker types should not increase memory footprint"
    );

    // StrictPath storage footprint ~ PathBuf + Arc<...>
    let expected_size = std::mem::size_of::<PathBuf>() + std::mem::size_of::<Arc<()>>();
    assert_eq!(
        std::mem::size_of::<StrictPath<()>>(),
        expected_size,
        "StrictPath should not add overhead beyond underlying types"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    #[derive(Clone)]
    struct ImageResource;
    #[derive(Clone)]
    struct UserData;

    let temp = tempfile::tempdir().unwrap();
    let images_dir = PathBoundary::<ImageResource>::try_new(temp.path()).unwrap();
    let user_data_dir = PathBoundary::<UserData>::try_new(temp.path()).unwrap();

    let logo_file = images_dir.strict_join("img/logo.png").unwrap();
    let profile_file = user_data_dir.strict_join("user/profile.txt").unwrap();

    // The following lines are intentionally commented: they should not compile
    // process_user_file(&logo_file);
    // serve_image(&profile_file);

    // Runtime check: their System paths differ as they live under different jails
    assert_ne!(
        logo_file.strictpath_to_string_lossy(),
        profile_file.strictpath_to_string_lossy()
    );
}

#[test]
fn test_try_into_boundary_changes_marker() {
    #[derive(Clone)]
    struct VaultRoot;
    #[derive(Clone)]
    struct Confidential;
    #[derive(Clone)]
    struct Reports;

    let temp = tempfile::tempdir().unwrap();
    let vault_boundary = PathBoundary::<VaultRoot>::try_new(temp.path()).unwrap();
    let strict_root: StrictPath<VaultRoot> = StrictPath::with_boundary(temp.path()).unwrap();

    let confidential_boundary: PathBoundary<Confidential> = strict_root
        .clone()
        .change_marker::<Confidential>()
        .try_into_boundary()
        .unwrap();
    let inferred_boundary: PathBoundary<VaultRoot> =
        strict_root.clone().try_into_boundary().unwrap();
    let reports_boundary: PathBoundary<Reports> = strict_root
        .clone()
        .change_marker::<Reports>()
        .try_into_boundary()
        .unwrap();

    // All three boundaries point to the same filesystem location (temp root)
    assert_eq!(confidential_boundary, vault_boundary);
    assert_eq!(inferred_boundary, vault_boundary);
    assert_eq!(reports_boundary, vault_boundary);

    // The key validation: try_into_boundary() preserves the current marker type.
    // If you want a different marker, call change_marker() first. This is proven above:
    //   - strict_root (VaultRoot) -> try_into_boundary() = PathBoundary<VaultRoot>
    //   - strict_root (VaultRoot) -> change_marker<Reports>() -> try_into_boundary() = PathBoundary<Reports>
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_root_marker_conversion() {
    #[derive(Clone)]
    struct VaultRoot;
    #[derive(Clone)]
    struct Confidential;

    let temp = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::<VaultRoot>::try_new(temp.path()).unwrap();

    let virtual_root_path = vroot.clone().into_virtualpath().unwrap();

    // Conversion methods preserve the marker type automatically.
    // try_into_root() preserves VaultRoot marker.
    let preserved: VirtualRoot<VaultRoot> = virtual_root_path.clone().try_into_root().unwrap();
    assert_eq!(preserved, vroot);

    // change_marker() is only needed when you want a DIFFERENT marker type.
    let changed: VirtualRoot<Confidential> = virtual_root_path
        .change_marker::<Confidential>()
        .try_into_root()
        .unwrap();

    // Both roots point to the same filesystem location, but have different markers.
    // They're equal because PartialEq compares underlying paths, not marker types.
    assert_eq!(changed, vroot);
}

#[test]
fn test_change_marker_preserves_strict_path_semantics() {
    #[derive(Clone)]
    struct GuestAccess;
    #[derive(Clone)]
    struct UserAccess;
    #[derive(Clone)]
    struct AdminAccess;

    let temp = tempfile::tempdir().unwrap();
    let guest_boundary = PathBoundary::<GuestAccess>::try_new(temp.path()).unwrap();
    let guest_report = guest_boundary.strict_join("reports/weekly.txt").unwrap();

    let user_report = guest_report.clone().change_marker::<UserAccess>();
    let admin_report = user_report.clone().change_marker::<AdminAccess>();

    assert_eq!(
        guest_report.strictpath_display().to_string(),
        user_report.strictpath_display().to_string()
    );
    assert_eq!(
        user_report.strictpath_display().to_string(),
        admin_report.strictpath_display().to_string()
    );

    fn require_admin(_: StrictPath<AdminAccess>) {}

    require_admin(admin_report);
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_change_marker_preserves_virtual_view() {
    #[derive(Clone)]
    struct GuestWorkspace;
    #[derive(Clone)]
    struct EditorWorkspace;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("docs")).unwrap();
    let guest_root = VirtualRoot::<GuestWorkspace>::try_new(temp.path()).unwrap();
    let guest_doc = guest_root.virtual_join("docs/guide.md").unwrap();

    let editor_doc = guest_doc.clone().change_marker::<EditorWorkspace>();

    assert_eq!(
        guest_doc.virtualpath_display().to_string(),
        editor_doc.virtualpath_display().to_string()
    );
    assert_eq!(
        guest_doc.as_unvirtual().strictpath_display().to_string(),
        editor_doc.as_unvirtual().strictpath_display().to_string()
    );

    fn require_editor(_: VirtualPath<EditorWorkspace>) {}

    require_editor(editor_doc);
}

#[test]
fn test_strict_path_change_marker_single_reference() {
    // Test the optimal case: Arc has single reference, no clone needed
    #[derive(Clone)]
    struct ReadOnly;
    #[derive(Clone)]
    struct ReadWrite;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("data")).unwrap();
    std::fs::write(temp.path().join("data/file.txt"), b"content").unwrap();

    let boundary = PathBoundary::<ReadOnly>::try_new(temp.path()).unwrap();
    let read_path = boundary.strict_join("data/file.txt").unwrap();

    // At this point, read_path owns the only Arc reference to the boundary
    let write_path: StrictPath<ReadWrite> = read_path.change_marker();

    // Verify the path still works
    assert!(write_path.exists());
    assert_eq!(write_path.read_to_string().unwrap(), "content");

    // Verify type change
    fn accepts_write(_: StrictPath<ReadWrite>) {}
    accepts_write(write_path);
}

#[test]
fn test_strict_path_change_marker_shared_boundary() {
    // Test the case where boundary Arc is shared (clone needed)
    #[derive(Clone)]
    struct ReadOnly;
    #[derive(Clone)]
    struct ReadWrite;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("shared")).unwrap();

    let boundary = PathBoundary::<ReadOnly>::try_new(temp.path()).unwrap();
    let path1 = boundary.strict_join("shared/file1.txt").unwrap();
    let path2 = boundary.strict_join("shared/file2.txt").unwrap();

    // Both paths share the same Arc<PathBoundary>
    // Now change_marker on path1 while path2 still holds a reference
    let write_path1: StrictPath<ReadWrite> = path1.change_marker();

    // path2 should still work with original marker
    assert!(path2.strictpath_to_string_lossy().contains("file2.txt"));

    // write_path1 should work with new marker
    assert!(write_path1
        .strictpath_to_string_lossy()
        .contains("file1.txt"));
}

#[test]
fn test_strict_path_change_marker_chain() {
    // Test chaining multiple change_marker calls
    #[derive(Clone)]
    struct Level1;
    #[derive(Clone)]
    struct Level2;
    #[derive(Clone)]
    struct Level3;

    let temp = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::<Level1>::try_new(temp.path()).unwrap();
    let path1 = boundary.strict_join("test").unwrap();

    let _path2: StrictPath<Level2> = path1.change_marker();

    // All should point to same location
    fn level1_fn(_: StrictPath<Level1>) {}
    fn level2_fn(_: StrictPath<Level2>) {}
    fn level3_fn(_: StrictPath<Level3>) {}

    // Verify type system enforces correct types
    let path1 = boundary.strict_join("test").unwrap();
    level1_fn(path1.clone());
    level2_fn(path1.clone().change_marker());
    level3_fn(path1.change_marker::<Level2>().change_marker::<Level3>());
}

#[test]
fn test_strict_path_change_marker_preserves_io_operations() {
    // Verify all I/O operations work correctly after change_marker
    #[derive(Clone)]
    struct Original;
    #[derive(Clone)]
    struct Changed;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("io_test")).unwrap();
    std::fs::write(temp.path().join("io_test/data.txt"), b"test content").unwrap();

    let boundary = PathBoundary::<Original>::try_new(temp.path()).unwrap();
    let original_path = boundary.strict_join("io_test/data.txt").unwrap();
    let changed_path: StrictPath<Changed> = original_path.change_marker();

    // Test read operations
    assert!(changed_path.exists());
    assert!(changed_path.is_file());
    assert_eq!(changed_path.read_to_string().unwrap(), "test content");

    // Test write operations
    changed_path.write(b"new content").unwrap();
    assert_eq!(changed_path.read_to_string().unwrap(), "new content");

    // Test metadata
    let metadata = changed_path.metadata().unwrap();
    assert!(metadata.is_file());

    // Test path operations
    let parent = changed_path.strictpath_parent().unwrap().unwrap();
    assert!(parent.is_dir());
}

#[test]
fn test_strict_path_change_marker_with_joins() {
    // Test that strict_join works correctly after change_marker
    #[derive(Clone)]
    struct UserSpace;
    #[derive(Clone)]
    struct AdminSpace;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("data/sub")).unwrap();

    let boundary = PathBoundary::<UserSpace>::try_new(temp.path()).unwrap();
    let user_data = boundary.strict_join("data").unwrap();
    let admin_data: StrictPath<AdminSpace> = user_data.change_marker();

    // Join should work on changed path
    let admin_sub = admin_data.strict_join("sub").unwrap();
    assert!(admin_sub.strictpath_to_string_lossy().ends_with("sub"));

    // Marker should be preserved in joined path
    fn requires_admin(_: StrictPath<AdminSpace>) {}
    requires_admin(admin_sub);
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_root_change_marker() {
    // Test VirtualRoot::change_marker
    #[derive(Clone)]
    struct TenantA;
    #[derive(Clone)]
    struct TenantB;

    let temp = tempfile::tempdir().unwrap();
    let root_a = VirtualRoot::<TenantA>::try_new(temp.path()).unwrap();
    let root_b: VirtualRoot<TenantB> = root_a.clone().change_marker();

    // Both should point to same location
    assert_eq!(root_a.path(), root_b.path());

    // But have different marker types
    fn tenant_a_fn(_: VirtualRoot<TenantA>) {}
    fn tenant_b_fn(_: VirtualRoot<TenantB>) {}

    tenant_a_fn(root_a);
    tenant_b_fn(root_b);
}

#[test]
#[cfg(feature = "virtual-path")]
fn test_virtual_path_change_marker() {
    // Test VirtualPath::change_marker
    #[derive(Clone)]
    struct GuestAccess;
    #[derive(Clone)]
    struct MemberAccess;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("content")).unwrap();

    let guest_root = VirtualRoot::<GuestAccess>::try_new(temp.path()).unwrap();
    let guest_file = guest_root.virtual_join("content/public.txt").unwrap();
    let member_file: VirtualPath<MemberAccess> = guest_file.clone().change_marker();

    // Virtual display should be identical
    assert_eq!(
        guest_file.virtualpath_display().to_string(),
        member_file.virtualpath_display().to_string()
    );

    // System path should be identical
    assert_eq!(
        guest_file.as_unvirtual().interop_path(),
        member_file.as_unvirtual().interop_path()
    );

    // But marker types should differ
    fn guest_fn(_: VirtualPath<GuestAccess>) {}
    fn member_fn(_: VirtualPath<MemberAccess>) {}

    guest_fn(guest_file);
    member_fn(member_file);
}

#[test]
fn test_path_boundary_change_marker() {
    // Test PathBoundary::change_marker
    #[derive(Clone)]
    struct Development;
    #[derive(Clone)]
    struct Production;

    let temp = tempfile::tempdir().unwrap();
    let dev_boundary = PathBoundary::<Development>::try_new(temp.path()).unwrap();
    let prod_boundary: PathBoundary<Production> = dev_boundary.clone().change_marker();

    // Both should point to same directory
    assert_eq!(dev_boundary.path(), prod_boundary.path());

    // strict_join should work with new marker
    std::fs::write(temp.path().join("config.txt"), b"data").unwrap();
    let prod_config = prod_boundary.strict_join("config.txt").unwrap();
    assert!(prod_config.exists());

    // Type system should enforce marker types
    fn dev_fn(_: PathBoundary<Development>) {}
    fn prod_fn(_: PathBoundary<Production>) {}

    dev_fn(dev_boundary);
    prod_fn(prod_boundary);
}

#[test]
fn test_change_marker_with_tuple_markers() {
    // Test change_marker with complex tuple markers (authorization pattern)
    #[derive(Clone)]
    struct UserFiles;
    #[derive(Clone)]
    struct ReadOnly;
    #[derive(Clone)]
    struct ReadWrite;

    let temp = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::<(UserFiles, ReadOnly)>::try_new(temp.path()).unwrap();

    // Verify type enforcement
    fn accepts_readonly(_: StrictPath<(UserFiles, ReadOnly)>) {}
    fn accepts_readwrite(_: StrictPath<(UserFiles, ReadWrite)>) {}

    // Simulate authorization: upgrade from ReadOnly to ReadWrite
    let readonly_path = boundary.strict_join("document.txt").unwrap();
    accepts_readonly(readonly_path.clone());
    accepts_readwrite(readonly_path.change_marker());
}

#[test]
fn test_change_marker_does_not_mutate_original_boundary() {
    // Critical test: Verify that calling change_marker on a StrictPath does NOT
    // mutate the original PathBoundary. The boundary should remain usable with
    // its original marker type after we derive a path and change its marker.
    #[derive(Clone)]
    struct OriginalMarker;
    #[derive(Clone)]
    struct ChangedMarker;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("data")).unwrap();
    std::fs::write(temp.path().join("data/file1.txt"), b"content1").unwrap();
    std::fs::write(temp.path().join("data/file2.txt"), b"content2").unwrap();

    // Step 1: Create a boundary with OriginalMarker
    let boundary = PathBoundary::<OriginalMarker>::try_new(temp.path()).unwrap();

    // Step 2: Create StrictPath from boundary
    let path1 = boundary.strict_join("data/file1.txt").unwrap();

    // Step 3: Change marker on the derived path
    let _changed_path: StrictPath<ChangedMarker> = path1.change_marker();

    // Step 4: CRITICAL - Verify the original boundary still works with OriginalMarker
    // This proves that change_marker() did NOT mutate the shared Arc<PathBoundary>
    let path2 = boundary.strict_join("data/file2.txt").unwrap();

    // If the boundary was mutated, this would fail to compile or behave incorrectly
    fn requires_original(_: StrictPath<OriginalMarker>) {}
    requires_original(path2.clone());

    // Verify both paths are functional
    assert!(path2.exists());
    assert_eq!(path2.read_to_string().unwrap(), "content2");

    // Verify we can still create new paths with original marker
    let path3 = boundary.strict_join("data").unwrap();
    requires_original(path3);
}

#[test]
fn test_change_marker_with_multiple_references_to_boundary() {
    // Test the scenario where multiple StrictPath instances share the same
    // PathBoundary Arc, and we change_marker on one of them. This should
    // trigger Arc::try_unwrap to fail and clone the boundary.
    #[derive(Clone)]
    struct SharedMarker;
    #[derive(Clone)]
    struct ExclusiveMarker;

    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("shared")).unwrap();

    let boundary = PathBoundary::<SharedMarker>::try_new(temp.path()).unwrap();

    // Create two paths that share the same Arc<PathBoundary>
    let path1 = boundary.strict_join("shared/file1.txt").unwrap();
    let path2 = boundary.strict_join("shared/file2.txt").unwrap();

    // At this point, the Arc reference count is >= 2
    // Changing marker on path1 should clone the boundary (Arc::try_unwrap fails)
    let exclusive_path1: StrictPath<ExclusiveMarker> = path1.change_marker();

    // path2 should still work with SharedMarker - unchanged
    fn requires_shared(_: StrictPath<SharedMarker>) {}
    requires_shared(path2.clone());

    // exclusive_path1 should work with ExclusiveMarker
    fn requires_exclusive(_: StrictPath<ExclusiveMarker>) {}
    requires_exclusive(exclusive_path1.clone());

    // Both should point to different locations but same root
    assert!(exclusive_path1
        .strictpath_to_string_lossy()
        .contains("file1.txt"));
    assert!(path2.strictpath_to_string_lossy().contains("file2.txt"));

    // Original boundary should still be usable
    let path3 = boundary.strict_join("shared/file3.txt").unwrap();
    requires_shared(path3);
}

#[test]
fn test_change_marker_memory_safety() {
    // Stress test: ensure no memory leaks or panics with many conversions
    #[derive(Clone)]
    struct Type1;
    #[derive(Clone)]
    struct Type2;

    let temp = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::<Type1>::try_new(temp.path()).unwrap();

    for _ in 0..1000 {
        let path1 = boundary.strict_join("test").unwrap();
        let path2: StrictPath<Type2> = path1.change_marker();
        let path3: StrictPath<Type1> = path2.change_marker();

        // Verify path is still valid
        assert!(!path3.strictpath_to_string_lossy().is_empty());
    }
}
