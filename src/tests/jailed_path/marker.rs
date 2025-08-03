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

    // JailedPath now contains PathBuf + Arc<validated_path<(Raw, Canonicalized)>> + PhantomData
    // Arc<validated_path<...>> is 8 bytes (pointer), validated_path is 24 bytes on Windows, PhantomData is 0
    // So total should be PathBuf + Arc size
    let expected_size = std::mem::size_of::<PathBuf>()
        + std::mem::size_of::<
            Arc<
                crate::validator::validated_path::ValidatedPath<(
                    crate::validator::validated_path::Raw,
                    crate::validator::validated_path::Canonicalized,
                )>,
            >,
        >();
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
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            "/test",
        )
        .canonicalize()
        .unwrap(),
    );
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(test_path.clone())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let _image_path: JailedPath<ImageResource> =
        JailedPath::new(Arc::clone(&jail_root), validated_path);
    // If you need another validated_path for a different marker, re-create it above as needed.
    let _user_path: JailedPath<UserData> = JailedPath::new(
        jail_root.clone(),
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            test_path,
        )
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap(),
    );

    // This test ensures that different marker types are treated as different types
    // The fact that we can assign to different typed variables proves this works
    // Trying to assign image_path to a JailedPath<UserData> would be a compile error
}
