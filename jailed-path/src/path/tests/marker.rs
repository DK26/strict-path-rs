use crate::path::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_marker_type_is_zero_cost() {
    #[derive(Clone)]
    struct TestMarker;

    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        std::mem::size_of::<JailedPath<TestMarker>>(),
        "Marker types should not increase memory footprint"
    );

    // JailedPath storage footprint ~ PathBuf + Arc<...>
    let expected_size = std::mem::size_of::<PathBuf>() + std::mem::size_of::<Arc<()>>();
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        expected_size,
        "JailedPath should not add overhead beyond underlying types"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    #[derive(Clone)]
    struct ImageResource;
    #[derive(Clone)]
    struct UserData;

    let temp = tempfile::tempdir().unwrap();
    let jail_images = crate::validator::jail::Jail::<ImageResource>::try_new(temp.path()).unwrap();
    let jail_user = crate::validator::jail::Jail::<UserData>::try_new(temp.path()).unwrap();

    let img = jail_images.jailed_join("img/logo.png").unwrap();
    let usr = jail_user.jailed_join("user/profile.txt").unwrap();

    // The following lines are intentionally commented: they should not compile
    // process_user_file(&img);
    // serve_image(&usr);

    // Runtime check: their System paths differ as they live under different jails
    assert_ne!(
        img.jailedpath_to_string_lossy(),
        usr.jailedpath_to_string_lossy()
    );
}
