use crate::jailed_path::JailedPath;
use crate::validator::PathValidator;
use crate::JailedPathError;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn create_test_directory() -> std::io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let temp_base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let temp_dir = temp_base.join(format!("jailed_path_test_{}_{}", std::process::id(), nanos));

    // Create the main test directory
    fs::create_dir_all(&temp_dir)?;

    // Create a subdirectory structure for testing
    let sub_dir = temp_dir.join("subdir");
    fs::create_dir(&sub_dir)?;

    // Create a test file in the jail
    let test_file = temp_dir.join("test.txt");
    let mut file = fs::File::create(&test_file)?;
    writeln!(file, "test content")?;

    // Create a test file in subdirectory
    let sub_file = sub_dir.join("sub_test.txt");
    let mut file = fs::File::create(&sub_file)?;
    writeln!(file, "sub test content")?;

    Ok(temp_dir)
}

fn cleanup_test_directory(path: &std::path::Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn test_pathvalidator_creation_with_valid_directory() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");

    // Should successfully create validator with existing directory
    let result = PathValidator::<()>::with_jail(&temp_dir);
    assert!(
        result.is_ok(),
        "PathValidator creation should succeed with valid directory"
    );

    let validator = result.unwrap();
    assert_eq!(
        validator.jail().canonicalize().unwrap(),
        temp_dir.canonicalize().unwrap(),
        "Validator should store the canonical path of the jail"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_pathvalidator_creation_with_nonexistent_directory() {
    let nonexistent_path = "/this/path/does/not/exist/hopefully";

    // Should fail with PathResolutionError when directory doesn't exist
    let result = PathValidator::<()>::with_jail(nonexistent_path);
    assert!(
        result.is_err(),
        "PathValidator creation should fail with nonexistent directory"
    );

    match result.unwrap_err() {
        JailedPathError::PathResolutionError { path, source } => {
            assert_eq!(path.to_string_lossy(), nonexistent_path);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("Expected PathResolutionError, got: {other:?}"),
    }
}

#[test]
fn test_pathvalidator_creation_with_file_instead_of_directory() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let file_path = temp_dir.join("test.txt");

    // Should fail with InvalidJail when trying to use a file as jail
    let result = PathValidator::<()>::with_jail(&file_path);
    assert!(
        result.is_err(),
        "PathValidator creation should fail when jail is a file"
    );

    match result.unwrap_err() {
        JailedPathError::InvalidJail { jail, source } => {
            assert_eq!(jail, file_path);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            assert!(source.to_string().contains("not a directory"));
        }
        other => panic!("Expected InvalidJail, got: {other:?}"),
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_valid_relative_path() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should successfully validate existing file with relative path
    let result = validator.try_path("test.txt");
    assert!(
        result.is_ok(),
        "try_path should succeed with valid relative path"
    );

    let jailed_path = result.unwrap();
    assert!(
        jailed_path.as_path().ends_with("test.txt"),
        "JailedPath should point to the correct file"
    );
    assert!(
        jailed_path.as_path().starts_with(validator.jail()),
        "JailedPath should be within jail boundary"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_valid_subdirectory_path() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should successfully validate file in subdirectory
    let result = validator.try_path("subdir/sub_test.txt");
    assert!(
        result.is_ok(),
        "try_path should succeed with valid subdirectory path"
    );

    let jailed_path = result.unwrap();
    assert!(
        jailed_path.as_path().ends_with("sub_test.txt"),
        "JailedPath should point to the correct file"
    );
    assert!(
        jailed_path.as_path().starts_with(validator.jail()),
        "JailedPath should be within jail boundary"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_directory_traversal_attack() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should block directory traversal attempts
    let traversal_attempts = vec![
        "../../../etc/passwd",
        "../../..",
        "../outside.txt",
        "subdir/../../outside.txt",
        "subdir/../../../etc/passwd",
    ];

    for attempt in traversal_attempts {
        let result = validator.try_path(attempt);
        assert!(
            result.is_err(),
            "try_path should block traversal attempt: {attempt}"
        );

        match result.unwrap_err() {
            JailedPathError::PathEscapesBoundary {
                attempted_path,
                jail_boundary,
            } => {
                assert_eq!(jail_boundary, validator.jail().to_path_buf());
                assert!(
                    !attempted_path.starts_with(&jail_boundary),
                    "Attempted path should be outside jail boundary"
                );
            }
            JailedPathError::PathResolutionError { .. } => {
                // Also acceptable if the path resolution fails
            }
            other => {
                panic!("Expected PathEscapesBoundary or PathResolutionError, got: {other:?}")
            }
        }
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_absolute_path_inside_jail() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should allow absolute path that's within the jail
    let absolute_path = temp_dir.join("test.txt");
    let result = validator.try_path(&absolute_path);
    assert!(
        result.is_ok(),
        "try_path should allow absolute path within jail"
    );

    let jailed_path = result.unwrap();
    assert_eq!(jailed_path.as_path(), absolute_path.canonicalize().unwrap());

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_absolute_path_outside_jail() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Create another temp directory outside the jail
    let outside_base = std::env::temp_dir();
    let outside_dir = outside_base.join(format!("jailed_path_outside_test_{}", std::process::id()));
    fs::create_dir_all(&outside_dir).expect("Failed to create outside temp directory");
    let outside_file = outside_dir.join("outside.txt");
    fs::File::create(&outside_file).expect("Failed to create outside file");

    // Should block absolute path outside jail
    let result = validator.try_path(&outside_file);
    assert!(
        result.is_err(),
        "try_path should block absolute path outside jail"
    );

    match result.unwrap_err() {
        JailedPathError::PathEscapesBoundary {
            attempted_path,
            jail_boundary,
        } => {
            assert_eq!(attempted_path, outside_file.canonicalize().unwrap());
            assert_eq!(jail_boundary, validator.jail().to_path_buf());
        }
        other => panic!("Expected PathEscapesBoundary, got: {other:?}"),
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
    cleanup_test_directory(&outside_dir);
}

#[test]
fn test_try_path_with_nonexistent_file() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should fail with PathResolutionError for nonexistent file
    let result = validator.try_path("nonexistent.txt");
    assert!(
        result.is_err(),
        "try_path should fail with nonexistent file"
    );

    match result.unwrap_err() {
        JailedPathError::PathResolutionError { path, source } => {
            assert!(path.to_string_lossy().contains("nonexistent.txt"));
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("Expected PathResolutionError, got: {other:?}"),
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_marker_types_for_compile_time_safety() {
    // Define test marker types
    struct ImageResource;
    struct UserData;

    let temp_dir = create_test_directory().expect("Failed to create temp directory");

    // Create validators with different marker types
    let image_validator: PathValidator<ImageResource> =
        PathValidator::with_jail(&temp_dir).unwrap();
    let user_validator: PathValidator<UserData> = PathValidator::with_jail(&temp_dir).unwrap();

    // Both should work with the same file but produce different marker types
    let image_path: JailedPath<ImageResource> = image_validator.try_path("test.txt").unwrap();
    let user_path: JailedPath<UserData> = user_validator.try_path("test.txt").unwrap();

    // Paths should be the same but have different types (checked at compile time)
    assert_eq!(image_path.as_path(), user_path.as_path());

    // This ensures the PhantomData marker is working
    assert_eq!(
        std::mem::size_of::<JailedPath<ImageResource>>(),
        std::mem::size_of::<PathBuf>(),
        "JailedPath should be zero-cost with marker"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_validator_jail_accessor() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // jail() method should return the canonical jail path
    let jail_path = validator.jail();
    assert_eq!(jail_path, temp_dir.canonicalize().unwrap());

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_validator_clone_and_debug() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should be cloneable
    let cloned_validator = validator.clone();
    assert_eq!(validator.jail(), cloned_validator.jail());

    // Should be debuggable (just ensure it doesn't panic)
    let debug_str = format!("{validator:?}");
    assert!(debug_str.contains("PathValidator"));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}
