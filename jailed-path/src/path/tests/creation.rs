use crate::path::jailed_path::JailedPath;
use std::path::PathBuf;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail = crate::validator::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path: JailedPath = crate::validator::validate(
        crate::validator::virtualize_to_jail(test_path.clone(), &jail),
        &jail,
    )
    .unwrap();

    // Should store the path correctly
    let abs_path = jail.path().join(&test_path);
    assert_eq!(
        jailed_path.systempath_to_string(),
        abs_path.to_string_lossy()
    );
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail = crate::validator::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path: JailedPath = crate::validator::validate(
        crate::validator::virtualize_to_jail(test_path, &jail),
        &jail,
    )
    .unwrap();

    // Should be cloneable
    assert_eq!(jailed_path, jailed_path.clone());

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    assert!(debug_str.contains("JailedPath"));
}
