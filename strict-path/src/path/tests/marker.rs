use crate::path::strict_path::StrictPath;
use crate::{PathBoundary, VirtualRoot};
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
fn test_try_into_boundary_rebrands_marker() {
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
        .try_into_boundary()
        .unwrap()
        .rebrand::<Confidential>();
    let inferred_boundary: PathBoundary<VaultRoot> =
        strict_root.clone().try_into_boundary().unwrap();

    assert_eq!(confidential_boundary, vault_boundary);
    assert_eq!(inferred_boundary, vault_boundary);

    let reports_boundary = vault_boundary.clone().rebrand::<Reports>();
    assert_eq!(reports_boundary, vault_boundary);

    let rebrand_boundary = vault_boundary.clone().rebrand::<Reports>();
    assert_eq!(rebrand_boundary, vault_boundary);

    // Nested directories become new boundaries when they already exist
    let reports_dir = vault_boundary.strict_join("reports").unwrap();
    reports_dir.create_dir_all().unwrap();
    let nested_boundary = reports_dir.clone().try_into_boundary().unwrap();
    let expected_boundary = reports_dir.clone().try_into_boundary().unwrap();
    assert_eq!(nested_boundary, expected_boundary);

    // Create-and-rebrand should also work without panicking
    let _: PathBoundary<Reports> = strict_root
        .clone()
        .try_into_boundary_create()
        .unwrap()
        .rebrand::<Reports>();
}

#[test]
fn test_virtual_root_rebrand() {
    #[derive(Clone)]
    struct VaultRoot;
    #[derive(Clone)]
    struct Confidential;

    let temp = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::<VaultRoot>::try_new(temp.path()).unwrap();
    let baseline = vroot.clone();

    let rebranded = vroot.rebrand::<Confidential>();
    assert_eq!(rebranded, baseline);
}
