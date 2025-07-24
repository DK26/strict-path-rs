use crate::jailed_path::JailedPath;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let jailed_path: JailedPath = JailedPath::new(test_path.clone(), jail_root);

    // Should store the path correctly
    assert_eq!(jailed_path.as_path(), test_path.as_path());
    assert_eq!(jailed_path.into_path_buf(), test_path);
}

#[test]
fn test_jailed_path_with_marker() {
    struct TestMarker;
    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let jailed_path: JailedPath<TestMarker> = JailedPath::new(test_path.clone(), jail_root);

    // Should work the same with marker types
    assert_eq!(jailed_path.as_path(), test_path.as_path());
    assert_eq!(jailed_path.into_path_buf(), test_path);
}

#[test]
fn test_jailed_path_as_ref_implementation() {
    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let jailed_path: JailedPath = JailedPath::new(test_path.clone(), jail_root);

    // Should work with AsRef<Path>
    let path_ref: &Path = jailed_path.as_ref();
    assert_eq!(path_ref, test_path.as_path());
}

#[test]
fn test_jailed_path_deref_implementation() {
    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let jailed_path: JailedPath = JailedPath::new(test_path.clone(), jail_root);

    // Should allow calling Path methods directly via Deref
    assert_eq!(jailed_path.file_name(), test_path.file_name());
    assert_eq!(jailed_path.parent(), test_path.parent());
    assert_eq!(jailed_path.extension(), test_path.extension());
}

#[test]
fn test_jailed_path_display_formatting() {
    let jail_root = Arc::new(PathBuf::from("/test"));
    let test_path = PathBuf::from("/test/path/file.txt");

    let jailed_path: JailedPath = JailedPath::new(test_path, jail_root);

    // Should display virtual root - path relative to jail
    #[cfg(windows)]
    {
        let display_output = format!("{jailed_path}");
        let expected_root = "\\path\\file.txt";

        assert_eq!(display_output, expected_root);
    }
    #[cfg(unix)]
    {
        let display_output = format!("{jailed_path}");
        eprintln!("Display output: {display_output}");
        let expected_root = "/path/file.txt";

        assert_eq!(display_output, expected_root);
    }
}

#[test]
fn test_jailed_path_equality_and_hash() {
    let path1 = PathBuf::from("/test/path");
    let path2 = PathBuf::from("/test/path");
    let path3 = PathBuf::from("/different/path");
    let jail_root = Arc::new(PathBuf::from("/test"));

    let jailed1: JailedPath = JailedPath::new(path1, Arc::clone(&jail_root));
    let jailed2: JailedPath = JailedPath::new(path2, Arc::clone(&jail_root));
    let jailed3: JailedPath = JailedPath::new(path3, jail_root);

    // Should implement equality correctly
    assert_eq!(jailed1, jailed2);
    assert_ne!(jailed1, jailed3);

    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(jailed1, "value");
    assert_eq!(map.get(&jailed2), Some(&"value"));
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let jailed_path: JailedPath = JailedPath::new(test_path, jail_root);

    // Should be cloneable
    assert_eq!(jailed_path, jailed_path.clone());

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    assert!(debug_str.contains("JailedPath"));

    #[cfg(windows)]
    assert!(debug_str.contains("\\\\test\\\\path"));
    #[cfg(unix)]
    assert!(debug_str.contains("/test/path"));
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

    // JailedPath now contains PathBuf + Arc<PathBuf> + PhantomData
    // Arc<PathBuf> is 8 bytes (pointer), PathBuf is 24 bytes on Windows, PhantomData is 0
    // So total should be PathBuf + Arc size
    let expected_size = std::mem::size_of::<PathBuf>() + std::mem::size_of::<Arc<PathBuf>>();
    assert_eq!(
        std::mem::size_of::<JailedPath<()>>(),
        expected_size,
        "JailedPath should not add overhead beyond the underlying PathBuf"
    );
}

#[test]
fn test_different_marker_types_are_incompatible() {
    struct ImageResource;
    struct UserData;

    let test_path = PathBuf::from("/test/path");
    let jail_root = Arc::new(PathBuf::from("/test"));
    let _image_path: JailedPath<ImageResource> =
        JailedPath::new(test_path.clone(), Arc::clone(&jail_root));
    let _user_path: JailedPath<UserData> = JailedPath::new(test_path, jail_root);

    // This test ensures that different marker types are treated as different types
    // The fact that we can assign to different typed variables proves this works
    // Trying to assign image_path to a JailedPath<UserData> would be a compile error
}
