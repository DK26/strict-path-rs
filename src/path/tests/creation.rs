use crate::path::jailed::JailedPath;
use std::path::PathBuf;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail = crate::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path: JailedPath = crate::jail::validate(
        crate::jail::virtualize_to_jail(test_path.clone(), &jail),
        &jail,
    )
    .unwrap();

    // Should store the path correctly
    let abs_path = jail.path().join(&test_path);
    assert_eq!(jailed_path.realpath_to_string(), abs_path.to_string_lossy());
    assert_eq!(jailed_path.realpath_to_string(), abs_path.to_string_lossy());
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail = crate::jail::Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path: JailedPath =
        crate::jail::validate(crate::jail::virtualize_to_jail(test_path, &jail), &jail).unwrap();

    // Should be cloneable
    assert_eq!(jailed_path, jailed_path.clone());

    // Should be debuggable
    let debug_str = format!("{jailed_path:?}");
    // Only check for struct name, not path formatting
    assert!(
        debug_str.contains("JailedPath"),
        "Debug output should contain struct name"
    );
}
