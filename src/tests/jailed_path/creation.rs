use crate::jailed_path::JailedPath;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_jailed_path_creation() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::staged_path::StagedPath::<crate::validator::staged_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let staged =
        crate::validator::staged_path::StagedPath::<crate::validator::staged_path::Raw>::new(
            test_path.clone(),
        )
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, Arc::clone(&jail_root));

    // Should store the path correctly
    let abs_path = jail_root.as_path().join(&test_path);
    assert_eq!(jailed_path.real_path(), abs_path.as_path());
    assert_eq!(jailed_path.unjail(), abs_path);
}

#[test]
fn test_jailed_path_clone_and_debug() {
    let test_path = PathBuf::from("path");
    let temp = tempfile::tempdir().unwrap();
    let jail_root = Arc::new(
        crate::validator::staged_path::StagedPath::<crate::validator::staged_path::Raw>::new(
            temp.path(),
        )
        .canonicalize()
        .unwrap(),
    );
    let staged =
        crate::validator::staged_path::StagedPath::<crate::validator::staged_path::Raw>::new(
            test_path,
        )
        .clamp()
        .join_jail(&jail_root)
        .canonicalize()
        .unwrap()
        .boundary_check(&jail_root)
        .unwrap();
    let jailed_path: JailedPath = JailedPath::new(staged, jail_root);

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
