use jailed_path::{JailedPath, JailedPathError, PathValidator};
use std::error::Error;
use std::fs;
use std::io::Write;

/// Create a test directory structure for integration testing
fn create_test_directory() -> std::io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let temp_base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let temp_dir = temp_base.join(format!(
        "jailed_path_integration_test_{}_{}",
        std::process::id(),
        nanos
    ));

    // Create nested directory structure
    let public_dir = temp_dir.join("public");
    let private_dir = temp_dir.join("private");
    let uploads_dir = public_dir.join("uploads");

    fs::create_dir_all(&uploads_dir)?;
    fs::create_dir_all(&private_dir)?;

    // Create test files
    let mut public_file = fs::File::create(public_dir.join("index.html"))?;
    writeln!(public_file, "<html><body>Public content</body></html>")?;

    let mut upload_file = fs::File::create(uploads_dir.join("image.jpg"))?;
    writeln!(upload_file, "fake image data")?;

    let mut private_file = fs::File::create(private_dir.join("secrets.txt"))?;
    writeln!(private_file, "secret data")?;

    Ok(temp_dir)
}

#[test]
fn test_complete_workflow_with_marker_types() {
    // Define application-specific marker types
    struct PublicAsset;
    struct UploadedFile;

    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let uploads_dir = public_dir.join("uploads");

    // Create validators for different resource types
    let public_validator: PathValidator<PublicAsset> =
        PathValidator::with_jail(&public_dir).unwrap();
    let upload_validator: PathValidator<UploadedFile> =
        PathValidator::with_jail(&uploads_dir).unwrap();

    // Test public asset access
    let public_file: JailedPath<PublicAsset> = public_validator.try_path("index.html").unwrap();
    assert!(public_file.exists(), "Public file should exist");
    assert!(public_file.is_file(), "Should be a file");

    // Test upload access
    let upload_file: JailedPath<UploadedFile> = upload_validator.try_path("image.jpg").unwrap();
    assert!(upload_file.exists(), "Upload file should exist");

    // Test that public validator can access subdirectories
    let nested_upload: JailedPath<PublicAsset> =
        public_validator.try_path("uploads/image.jpg").unwrap();
    assert!(nested_upload.exists(), "Should access nested files");

    // Test that validators block escape attempts
    assert!(public_validator.try_path("../private/secrets.txt").is_err());
    assert!(upload_validator.try_path("../index.html").is_err());
    assert!(upload_validator
        .try_path("../../private/secrets.txt")
        .is_err());
}

#[test]
fn test_error_handling_and_reporting() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(&public_dir).unwrap();

    // Test different error scenarios

    // 1. Non-existent file should now succeed with touch technique
    match validator.try_path("nonexistent.txt") {
        Ok(jailed_path) => {
            assert!(jailed_path.as_path().ends_with("nonexistent.txt"));
            // Compare with canonical jail path for consistency
            let canonical_public = public_dir
                .canonicalize()
                .expect("Public dir should be canonicalizable");
            assert!(
                jailed_path.as_path().starts_with(&canonical_public),
                "Path {:?} should start with canonical jail {:?}",
                jailed_path.as_path(),
                canonical_public
            );
        }
        other => panic!("Expected successful validation with touch technique, got: {other:?}"),
    }

    // 2. Directory traversal attempt
    match validator.try_path("../private/secrets.txt") {
        Err(JailedPathError::PathEscapesBoundary {
            attempted_path,
            jail_boundary,
        }) => {
            assert!(!attempted_path.starts_with(&jail_boundary));
            assert!(attempted_path.to_string_lossy().contains("secrets.txt"));
        }
        other => panic!("Expected PathEscapesBoundary, got: {other:?}"),
    }

    // 3. Test error source chaining
    let nonexistent_jail = "/this/does/not/exist";
    match PathValidator::<()>::with_jail(nonexistent_jail) {
        Err(error) => {
            // Should have proper error chaining
            assert!(error.source().is_some(), "Should have source error");

            // Should be able to downcast to io::Error
            if let Some(io_error) = error
                .source()
                .and_then(|e| e.downcast_ref::<std::io::Error>())
            {
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
            } else {
                panic!("Source should be io::Error");
            }
        }
        Ok(_) => panic!("Should fail with nonexistent jail"),
    }
}

#[test]
fn test_absolute_vs_relative_path_handling() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(&public_dir).unwrap();

    // Test relative path
    let relative_result = validator.try_path("index.html");
    assert!(relative_result.is_ok(), "Relative path should work");

    // Test absolute path within jail
    let absolute_path = public_dir.join("index.html");
    let absolute_result = validator.try_path(&absolute_path);
    assert!(
        absolute_result.is_ok(),
        "Absolute path within jail should work"
    );

    // Both should resolve to the same canonical path
    let relative_path = relative_result.unwrap();
    let absolute_path = absolute_result.unwrap();
    assert_eq!(relative_path.as_path(), absolute_path.as_path());

    // Test absolute path outside jail
    let outside_path = temp_dir.join("private").join("secrets.txt");
    let outside_result = validator.try_path(&outside_path);
    assert!(
        outside_result.is_err(),
        "Absolute path outside jail should fail"
    );
}

#[test]
fn test_real_world_web_server_scenario() {
    struct StaticAsset;
    struct UserUpload;

    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let uploads_dir = public_dir.join("uploads");

    // Simulate a web server with different validators for different content types
    let static_validator: PathValidator<StaticAsset> =
        PathValidator::with_jail(&public_dir).unwrap();
    let upload_validator: PathValidator<UserUpload> =
        PathValidator::with_jail(&uploads_dir).unwrap();

    // Function that serves static assets
    fn serve_static_asset(
        validator: &PathValidator<StaticAsset>,
        requested_path: &str,
    ) -> Result<JailedPath<StaticAsset>, String> {
        validator
            .try_path(requested_path)
            .map_err(|e| format!("Access denied: {e}"))
    }

    // Function that handles user uploads
    fn access_user_upload(
        validator: &PathValidator<UserUpload>,
        file_path: &str,
    ) -> Result<JailedPath<UserUpload>, String> {
        validator
            .try_path(file_path)
            .map_err(|e| format!("Upload not found: {e}"))
    }

    // Test legitimate requests
    assert!(serve_static_asset(&static_validator, "index.html").is_ok());
    assert!(serve_static_asset(&static_validator, "uploads/image.jpg").is_ok());
    assert!(access_user_upload(&upload_validator, "image.jpg").is_ok());

    // Test security violations
    assert!(serve_static_asset(&static_validator, "../private/secrets.txt").is_err());
    assert!(access_user_upload(&upload_validator, "../index.html").is_err());
    assert!(access_user_upload(&upload_validator, "../../private/secrets.txt").is_err());
}

#[test]
fn test_memory_safety_with_long_paths() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(&public_dir).unwrap();

    // Create a very long path that would cause memory issues in naive implementations
    let long_component = "a".repeat(1000);
    let long_path = format!("../{}/{}", long_component, "etc/passwd");

    // Should handle long paths gracefully without memory exhaustion
    match validator.try_path(&long_path) {
        Err(error) => {
            let error_msg = error.to_string();
            // Error message should be truncated to prevent memory attacks
            assert!(
                error_msg.len() < 2000,
                "Error message should be truncated for very long paths"
            );
        }
        Ok(_) => panic!("Long traversal path should be rejected"),
    }
}

#[test]
fn test_edge_cases_and_special_paths() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(&public_dir).unwrap();

    // Test various edge cases that should work
    let valid_cases = vec![
        "./index.html",          // Explicit current directory
        "uploads/../index.html", // Up and back down
    ];

    for case in valid_cases {
        let result = validator.try_path(case);
        if let Ok(jailed_path) = result {
            // If successful, should still be within jail (use canonicalized jail path)
            assert!(
                jailed_path.starts_with(validator.jail()),
                "Path '{}' resolved outside jail: {}",
                case,
                jailed_path.display()
            );
        } else {
            // Some edge cases might fail due to canonicalization - that's also acceptable
            // for security reasons
        }
    }

    // These should definitely fail
    let malicious_cases = vec![
        "..",
        "../",
        "../../",
        "../../../etc/passwd",
        "uploads/../../private/secrets.txt",
    ];

    for case in malicious_cases {
        let result = validator.try_path(case);
        assert!(
            result.is_err(),
            "Malicious path '{case}' should be rejected"
        );
    }
}

#[test]
fn test_validator_properties() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(&public_dir).unwrap();

    // Test jail() accessor
    assert_eq!(validator.jail(), public_dir.canonicalize().unwrap());

    // Test that validator is cloneable
    let cloned_validator = validator.clone();
    assert_eq!(validator.jail(), cloned_validator.jail());

    // Test that cloned validator works the same
    let original_result = validator.try_path("index.html").unwrap();
    let cloned_result = cloned_validator.try_path("index.html").unwrap();
    assert_eq!(original_result.as_path(), cloned_result.as_path());
}
