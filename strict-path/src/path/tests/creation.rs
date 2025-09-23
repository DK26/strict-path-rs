use crate::{path::strict_path::StrictPath, PathBoundary};
use std::path::PathBuf;

#[test]
fn test_strict_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let path = crate::validator::path_history::PathHistory::new(&test_path);
    let validated_path: StrictPath = temp_dir
        .strict_join(path.virtualize_to_restriction(&temp_dir))
        .unwrap();

    // Should store the path correctly
    let abs_path = temp_dir.path().join(&test_path);
    assert_eq!(
        validated_path.strictpath_to_string_lossy(),
        abs_path.to_string_lossy()
    );
}

#[test]
fn test_strict_path_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let file_path: StrictPath = temp_dir
        .strict_join(stated_path.virtualize_to_restriction(&temp_dir))
        .unwrap();

    // Should be debuggable
    let debug_str = format!("{file_path:?}");
    assert!(debug_str.contains("StrictPath"));
}

#[test]
fn test_virtual_path_as_unvirtual_strict_path() {
    use crate::validator::virtual_root::VirtualRoot;

    let temp = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::try_new(temp.path()).unwrap();
    let virtual_path = vroot.virtual_join("test/file.txt").unwrap();

    // Test that VirtualPath can be borrowed as StrictPath
    fn accepts_strict_path(jp: &StrictPath) -> String {
        jp.strictpath_to_string_lossy().to_string()
    }

    // This works - explicit borrow
    let strict_ref: &StrictPath = virtual_path.as_unvirtual();
    let result1 = accepts_strict_path(strict_ref);

    // Clone for comparison since unvirtual() consumes the value
    let virtual_path_clone = virtual_path.clone();
    let unvirtual = virtual_path_clone.unvirtual();
    let result2 = accepts_strict_path(&unvirtual);

    // Both should produce the same result
    assert_eq!(result1, result2);

    // Verify the borrow gives us the same underlying path
    assert_eq!(
        strict_ref.strictpath_to_string_lossy(),
        unvirtual.strictpath_to_string_lossy()
    );

    // Test that we can use simple function signatures with both types
    fn uses_simple_signature(path: &StrictPath) -> String {
        path.strictpath_to_string_lossy().to_string()
    }

    // Both should work with the simple function signature
    let result3 = uses_simple_signature(virtual_path.as_unvirtual()); // VirtualPath via &StrictPath
    let result4 = uses_simple_signature(&unvirtual); // StrictPath via &StrictPath
    assert_eq!(result3, result4);
}
