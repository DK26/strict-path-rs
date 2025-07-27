use crate::validator::PathValidator;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_clamped_path_type_safety() {
    let temp_dir = tempdir().unwrap();
    let validator = PathValidator::<()>::with_jail(temp_dir.path()).unwrap();

    // Test that ClampedPath can only be created through clamp_path
    let clamped = validator.clamp_path(Path::new("../../../etc/passwd"));

    // Verify it's properly clamped
    assert_eq!(clamped.as_path(), Path::new("etc/passwd"));

    // Test that joining with clamped path is safe
    let full_path = temp_dir.path().join(clamped.as_path());
    assert!(full_path.starts_with(temp_dir.path()));
}

#[test]
fn test_clamp_path_handles_virtual_root() {
    let temp_dir = tempdir().unwrap();
    let validator = PathValidator::<()>::with_jail(temp_dir.path()).unwrap();

    // Test absolute path handling
    let clamped1 = validator.clamp_path(Path::new("/user/file.txt"));
    let clamped2 = validator.clamp_path(Path::new("user/file.txt"));

    assert_eq!(clamped1.as_path(), clamped2.as_path());
    assert_eq!(clamped1.as_path(), Path::new("user/file.txt"));
}
