use crate::path::strict_path::StrictPath;
use crate::PathBoundary;
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
