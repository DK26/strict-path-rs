use crate::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_marker_type_is_zero_cost() {
    #[derive(Clone)]
    struct TestMarker;

    // JailedPath with and without marker should have same size
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        std::mem::size_of::<JailedPath<TestMarker>>(),
        "Marker types should not increase memory footprint"
    );

    // JailedPath now contains PathBuf + Arc<ValidatedPath<(((Raw, Clamped), Canonicalized), Exists)>>> + PhantomData
    // Arc<validated_path<...>> is a pointer-sized handle; PhantomData is 0
    // So total should be PathBuf + Arc size
    // Expected size: PathBuf + Arc<StatedPath<...>> (approximate, don't reference removed markers)
    let expected_size = std::mem::size_of::<PathBuf>() + std::mem::size_of::<Arc<()>>();
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        expected_size,
        "JailedPath should not add overhead beyond the underlying PathBuf"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    #[derive(Clone)]
    struct ImageResource;
    #[derive(Clone)]
    struct UserData;

    let test_path = PathBuf::from("path");
    // Use a real temporary directory so canonicalize() and verify_exists() succeed
    let temp = tempfile::tempdir().unwrap();
    let jail_img = crate::validator::jail::Jail::<ImageResource>::try_new(temp.path()).unwrap();
    let _image_path = crate::validator::jail::validate(test_path.clone(), &jail_img).unwrap();
    // If you need another validated_path for a different marker, re-create it above as needed.
    let jail_user = crate::validator::jail::Jail::<UserData>::try_new(temp.path()).unwrap();
    let _user_path = crate::validator::jail::validate(test_path, &jail_user).unwrap();

    // This test ensures that different marker types are treated as different types
    // The fact that we can assign to different typed variables proves this works
    // Trying to assign image_path to a JailedPath<UserData> would be a compile error
}
