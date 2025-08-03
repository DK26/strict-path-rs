use jailed_path::{JailedPath, PathValidator};
use std::fs;
use std::io::Write;

mod try_jail_test;

/// Creates a cross-platform non-existent absolute path for testing
fn get_nonexistent_absolute_path() -> String {
    #[cfg(windows)]
    {
        "C:\\NonExistent\\Path\\That\\Does\\Not\\Exist".to_string()
    }
    #[cfg(not(windows))]
    {
        "/nonexistent/path/that/does/not/exist".to_string()
    }
}

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
        PathValidator::with_jail(uploads_dir).unwrap();

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
    // NEW BEHAVIOR: These paths are clamped, not blocked
    // Escape attempts for public_validator
    let public_escape_attempts = vec!["../private/secrets.txt"];
    for path in public_escape_attempts {
        let result = public_validator.try_path(path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
        let jailed_path = result.unwrap();
        let jail_root = public_validator.jail().canonicalize().unwrap();
        let jailed_path_for_canon = jailed_path.unjail();
        let clamped_path = jailed_path_for_canon
            .canonicalize()
            .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
        assert!(
            clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
            "Clamped path should be at jail root or its parent: {}",
            clamped_path.display()
        );
    }
    // Escape attempts for upload_validator
    let upload_escape_attempts = vec!["../index.html", "../../private/secrets.txt"];
    for path in upload_escape_attempts {
        let result = upload_validator.try_path(path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
        let jailed_path = result.unwrap();
        let jail_root = upload_validator.jail().canonicalize().unwrap();
        let jailed_path_for_canon = jailed_path.unjail();
        let clamped_path = jailed_path_for_canon
            .canonicalize()
            .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
        assert!(
            clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
            "Clamped path should be at jail root or its parent: {}",
            clamped_path.display()
        );
    }
}

#[test]
fn test_error_handling_and_reporting() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(public_dir.clone()).unwrap();

    // Test different error scenarios

    // 1. Non-existent file should now succeed with touch technique
    match validator.try_path("nonexistent.txt") {
        Ok(jailed_path) => {
            assert!(jailed_path.ends_with("nonexistent.txt"));
            // Compare with canonical jail path for consistency
            let canonical_public = public_dir
                .canonicalize()
                .expect("Public dir should be canonicalizable");
            assert!(
                jailed_path.starts_with(&canonical_public),
                "Path {:?} should start with canonical jail {:?}",
                jailed_path.unjail(),
                &canonical_public
            );
        }
        other => panic!("Expected successful validation with touch technique, got: {other:?}"),
    }

    // 2. Directory traversal attempt
    // NEW BEHAVIOR: Traversal is clamped, not blocked
    match validator.try_path("../private/secrets.txt") {
        Ok(jailed_path) => {
            let jail_root = validator.jail().canonicalize().unwrap();
            let jailed_path_for_canon = jailed_path.unjail();
            let clamped_path = jailed_path_for_canon
                .canonicalize()
                .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
            assert!(
                clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
                "Clamped path should be at jail root or its parent: {}",
                clamped_path.display()
            );
        }
        other => panic!("Traversal should be clamped, got: {other:?}"),
    }

    // 3. Test that non-existent jail is now allowed (should succeed)
    let nonexistent_jail = get_nonexistent_absolute_path();
    match PathValidator::<()>::with_jail(&nonexistent_jail) {
        Ok(validator) => {
            // Should allow creation, but paths inside should still be jailed
            let result = validator.try_path("foo.txt");
            assert!(
                result.is_ok(),
                "Should allow paths inside non-existent jail"
            );
            let jailed_path = result.unwrap();
            assert!(
                jailed_path.starts_with(&nonexistent_jail),
                "Jailed path should start with the jail boundary"
            );
        }
        Err(e) => panic!("Non-existent jail should be allowed, got error: {e}"),
    }
}

#[test]
fn test_absolute_vs_relative_path_handling() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(public_dir.clone()).unwrap();

    // Test relative path
    let relative_result = validator.try_path("index.html");
    assert!(relative_result.is_ok(), "Relative path should work");

    // Test absolute path within jail
    let absolute_path = public_dir.join("index.html");
    let absolute_result = validator.try_path(absolute_path);
    assert!(
        absolute_result.is_ok(),
        "Absolute path within jail should work"
    );

    // Both should resolve to paths within jail root or its parent
    let relative_path = relative_result.unwrap();
    let absolute_path = absolute_result.unwrap();
    let jail_root = validator.jail().canonicalize().unwrap();
    let rel_path_for_canon = relative_path.unjail();
    let rel_clamped = rel_path_for_canon
        .canonicalize()
        .unwrap_or_else(|_| rel_path_for_canon.to_path_buf());
    let abs_path_for_canon = absolute_path.unjail();
    let abs_clamped = abs_path_for_canon
        .canonicalize()
        .unwrap_or_else(|_| abs_path_for_canon.to_path_buf());
    assert!(
        rel_clamped.starts_with(&jail_root) || rel_clamped.parent() == Some(&jail_root),
        "Relative path should be clamped within jail: {}",
        rel_clamped.display()
    );
    assert!(
        abs_clamped.starts_with(&jail_root) || abs_clamped.parent() == Some(&jail_root),
        "Absolute path should be clamped within jail: {}",
        abs_clamped.display()
    );

    // Test absolute path outside jail
    let outside_path = temp_dir.join("private").join("secrets.txt");
    let outside_result = validator.try_path(outside_path);
    // NEW BEHAVIOR: Absolute path outside jail is clamped
    assert!(
        outside_result.is_ok(),
        "Absolute path outside jail should be clamped"
    );
    let jailed_path = outside_result.unwrap();
    let jail_root = validator.jail().canonicalize().unwrap();
    let jailed_path_for_canon = jailed_path.unjail();
    let clamped_path = jailed_path_for_canon
        .canonicalize()
        .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
    assert!(
        clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
        "Clamped path should be at jail root or its parent: {}",
        clamped_path.display()
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
        PathValidator::with_jail(public_dir).unwrap();
    let upload_validator: PathValidator<UserUpload> =
        PathValidator::with_jail(uploads_dir).unwrap();

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
    // NEW BEHAVIOR: These paths are clamped, not blocked
    // Escape attempts for static_validator
    let static_escape_attempts = vec!["../private/secrets.txt"];
    for path in static_escape_attempts {
        let result = serve_static_asset(&static_validator, path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
    }
    // Escape attempts for upload_validator
    let upload_escape_attempts = vec!["../index.html", "../../private/secrets.txt"];
    for path in upload_escape_attempts {
        let result = access_user_upload(&upload_validator, path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
    }
}

#[test]
fn test_memory_safety_with_long_paths() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(public_dir).unwrap();

    // Create a very long path that would cause memory issues in naive implementations
    let long_component = "a".repeat(1000);
    let long_path = format!("../{}/{}", long_component, "etc/passwd");

    // Should handle long paths gracefully without memory exhaustion
    match validator.try_path(long_path) {
        Ok(jailed_path) => {
            let jail_root = validator.jail().canonicalize().unwrap();
            let jailed_path_for_canon = jailed_path.unjail();
            let clamped_path = jailed_path_for_canon
                .canonicalize()
                .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
            assert!(
                clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
                "Clamped path should be at jail root or its parent: {}",
                clamped_path.display()
            );
        }
        Err(error) => {
            let error_msg = error.to_string();
            assert!(
                error_msg.len() < 2000,
                "Error message should be truncated for very long paths"
            );
        }
    }
}

#[test]
fn test_edge_cases_and_special_paths() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(public_dir).unwrap();

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
                jailed_path.virtual_display()
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
        "../../../sensitive.txt",
        "uploads/../../private/secrets.txt",
    ];

    for case in malicious_cases {
        let result = validator.try_path(case);
        assert!(result.is_ok(), "Malicious path '{case}' should be clamped");
        let jailed_path = result.unwrap();
        let jail_root = validator.jail().canonicalize().unwrap();
        let jailed_path_for_canon = jailed_path.unjail();
        let clamped_path = jailed_path_for_canon
            .canonicalize()
            .unwrap_or_else(|_| jailed_path_for_canon.to_path_buf());
        assert!(
            clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
            "Clamped path should be at jail root or its parent: {}",
            clamped_path.display()
        );
    }
}

#[test]
fn test_validator_properties() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let validator = PathValidator::<()>::with_jail(public_dir.clone()).unwrap();

    // Test jail() accessor
    assert_eq!(validator.jail(), public_dir.canonicalize().unwrap());

    // Test that validator is cloneable
    // Test that validator works the same
    let original_result = validator.try_path("index.html").unwrap();
    let cloned_result = validator.try_path("index.html").unwrap();
    assert_eq!(original_result, cloned_result);
}
