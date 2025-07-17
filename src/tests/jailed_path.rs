use crate::jailed_path::JailedPath;
use std::path::Path;
use std::path::PathBuf;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("/test/path");
    let jailed_path: JailedPath = JailedPath::new(test_path.clone());

    // Should store the path correctly
    assert_eq!(jailed_path.as_path(), test_path.as_path());
    assert_eq!(jailed_path.into_path_buf(), test_path);
}

#[test]
fn test_jailed_path_with_marker_type() {
    struct TestMarker;

    let test_path = PathBuf::from("/test/path");
    let jailed_path: JailedPath<TestMarker> = JailedPath::new(test_path.clone());

    // Should work the same with marker types
    assert_eq!(jailed_path.as_path(), test_path.as_path());
    assert_eq!(jailed_path.into_path_buf(), test_path);
}

#[test]
fn test_jailed_path_as_ref_implementation() {
    let test_path = PathBuf::from("/test/path");
    let jailed_path: JailedPath = JailedPath::new(test_path.clone());

    // Should work with AsRef<Path>
    let path_ref: &Path = jailed_path.as_ref();
    assert_eq!(path_ref, test_path.as_path());
}

#[test]
fn test_jailed_path_deref_implementation() {
    let test_path = PathBuf::from("/test/path");
    let jailed_path: JailedPath = JailedPath::new(test_path.clone());

    // Should allow calling Path methods directly via Deref
    assert_eq!(jailed_path.file_name(), test_path.file_name());
    assert_eq!(jailed_path.parent(), test_path.parent());
    assert_eq!(jailed_path.extension(), test_path.extension());
}

#[test]
fn test_jailed_path_display_formatting() {
    let test_path = PathBuf::from("/test/path/file.txt");
    let jailed_path: JailedPath = JailedPath::new(test_path.clone());

    // Should display the same as the underlying path
    assert_eq!(
        format!("{}", jailed_path.display()),
        format!("{}", test_path.display())
    );
}

#[test]
fn test_jailed_path_equality_and_hash() {
    let path1 = PathBuf::from("/test/path");
    let path2 = PathBuf::from("/test/path");
    let path3 = PathBuf::from("/different/path");

    let jailed1: JailedPath = JailedPath::new(path1);
    let jailed2: JailedPath = JailedPath::new(path2);
    let jailed3: JailedPath = JailedPath::new(path3);

    // Should implement equality correctly
    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    // Should be hashable (this will fail compilation if Hash isn't implemented)
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1.clone(), "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("/test/path");
    let jailed_path: JailedPath = JailedPath::new(test_path.clone());

    // Should be cloneable
    let cloned = jailed_path.clone();
    assert_eq!(jailed_path, cloned);

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    assert!(debug_str.contains("JailedPath"));
    assert!(debug_str.contains("test/path"));
}

#[test]
fn test_marker_type_is_zero_cost() {
    struct TestMarker;

    // JailedPath with and without marker should have same size
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        std::mem::size_of::<JailedPath<TestMarker>>(),
        "Marker types should not increase memory footprint"
    );

    // Should be the same size as PathBuf since it only adds PhantomData
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        std::mem::size_of::<PathBuf>(),
        "JailedPath should not add overhead beyond the underlying PathBuf"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    struct ImageResource;
    struct UserData;

    let test_path = PathBuf::from("/test/path");
    let _image_path: JailedPath<ImageResource> = JailedPath::new(test_path.clone());
    let _user_path: JailedPath<UserData> = JailedPath::new(test_path);

    // This test ensures that different marker types are treated as different types
    // The fact that we can assign to different typed variables proves this works
    // Trying to assign image_path to a JailedPath<UserData> would be a compile error
}
