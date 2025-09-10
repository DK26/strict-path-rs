use crate::{path::jailed_path::JailedPath, Jail};
use std::path::PathBuf;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();
    let stated_path = crate::validator::path_history::PathHistory::new(&test_path);
    let jailed_path: JailedPath = jail
        .jailed_join(stated_path.virtualize_to_jail(&jail))
        .unwrap();

    // Should store the path correctly
    let abs_path = jail.path().join(&test_path);
    assert_eq!(
        jailed_path.jailedpath_to_string_lossy(),
        abs_path.to_string_lossy()
    );
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();
    let stated_path = crate::validator::path_history::PathHistory::new(test_path);
    let jailed_path: JailedPath = jail
        .jailed_join(stated_path.virtualize_to_jail(&jail))
        .unwrap();

    // Should be cloneable
    assert_eq!(jailed_path, jailed_path.clone());

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    assert!(debug_str.contains("JailedPath"));
}

#[test]
fn test_virtual_path_as_unvirtual_jailed_path() {
    use crate::validator::virtual_root::VirtualRoot;

    let temp = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::try_new(temp.path()).unwrap();
    let virtual_path = vroot.virtual_join("test/file.txt").unwrap();

    // Test that VirtualPath can be borrowed as JailedPath
    fn accepts_jailed_path(jp: &JailedPath) -> String {
        jp.jailedpath_to_string_lossy().to_string()
    }

    // This works - explicit borrow
    let jailed_ref: &JailedPath = virtual_path.as_unvirtual();
    let result1 = accepts_jailed_path(jailed_ref);

    // Clone for comparison since unvirtual() consumes the value
    let virtual_path_clone = virtual_path.clone();
    let unvirtual = virtual_path_clone.unvirtual();
    let result2 = accepts_jailed_path(&unvirtual);

    // Both should produce the same result
    assert_eq!(result1, result2);

    // Verify the borrow gives us the same underlying path
    assert_eq!(
        jailed_ref.jailedpath_to_string_lossy(),
        unvirtual.jailedpath_to_string_lossy()
    );

    // Test that we can use simple function signatures with both types
    fn uses_simple_signature(path: &JailedPath) -> String {
        path.jailedpath_to_string_lossy().to_string()
    }

    // Both should work with the simple function signature
    let result3 = uses_simple_signature(virtual_path.as_unvirtual()); // VirtualPath via &JailedPath
    let result4 = uses_simple_signature(&unvirtual); // JailedPath via &JailedPath
    assert_eq!(result3, result4);
}
