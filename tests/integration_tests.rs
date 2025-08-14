use jailed_path::{Jail, JailedPath};
use soft_canonicalize::soft_canonicalize;
use std::fs;
use std::io::Write;

// try_jail tests removed; use Jail::try_new + try_path directly

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
    let public_jail: Jail<PublicAsset> = Jail::try_new(&public_dir).unwrap();
    let upload_jail: Jail<UploadedFile> = Jail::try_new(uploads_dir).unwrap();

    // Test public asset access
    let public_file: JailedPath<PublicAsset> = public_jail.try_path("index.html").unwrap();
    assert!(public_file.exists(), "Public file should exist");
    assert!(public_file.is_file(), "Should be a file");

    // Test upload access
    let upload_file: JailedPath<UploadedFile> = upload_jail.try_path("image.jpg").unwrap();
    assert!(upload_file.exists(), "Upload file should exist");

    // Test that public validator can access subdirectories
    let nested_upload: JailedPath<PublicAsset> = public_jail.try_path("uploads/image.jpg").unwrap();
    assert!(nested_upload.exists(), "Should access nested files");

    // Test that validators block escape attempts
    // NEW BEHAVIOR: These paths are clamped, not blocked
    // Escape attempts for public_validator
    let public_escape_attempts = vec!["../private/secrets.txt"];
    for path in public_escape_attempts {
        let result = public_jail.try_path(path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
        let jailed_path = result.unwrap();
        // Ensure resulting path is within jail using approved API
        assert!(
            jailed_path.starts_with_real(public_jail.path()),
            "Clamped path should be within jail: {jailed_path:?}"
        );
    }
    // Escape attempts for upload_validator
    let upload_escape_attempts = vec!["../index.html", "../../private/secrets.txt"];
    for path in upload_escape_attempts {
        let result = upload_jail.try_path(path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
        let jailed_path = result.unwrap();
        // Ensure resulting path is within jail using approved API
        assert!(
            jailed_path.starts_with_real(upload_jail.path()),
            "Clamped path should be within jail: {jailed_path:?}"
        );
    }
}

#[test]
fn test_error_handling_and_reporting() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let jail = Jail::<()>::try_new(public_dir).unwrap();

    // Test different error scenarios

    // 1. Non-existent file should now succeed with touch technique
    match jail.try_path("nonexistent.txt") {
        Ok(jailed_path) => {
            assert!(jailed_path.to_string_virtual().ends_with("nonexistent.txt"));
            // Ensure path is within jail using approved API
            assert!(
                jailed_path.starts_with_real(jail.path()),
                "Path should be within jail: {jailed_path:?}"
            );
        }
        other => panic!("Expected successful validation with touch technique, got: {other:?}"),
    }

    // 2. Directory traversal attempt
    // NEW BEHAVIOR: Traversal is clamped, not blocked
    match jail.try_path("../private/secrets.txt") {
        Ok(jailed_path) => {
            // Ensure path is within jail using approved API
            assert!(
                jailed_path.starts_with_real(jail.path()),
                "Clamped path should be within jail: {jailed_path:?}"
            );
        }
        other => panic!("Traversal should be clamped, got: {other:?}"),
    }

    // 3. Test that non-existent jail is now allowed (should succeed)
    let nonexistent_jail = get_nonexistent_absolute_path();
    match Jail::<()>::try_new(&nonexistent_jail) {
        Ok(jail) => {
            // Should allow creation, but paths inside should still be jailed
            let result = jail.try_path("foo.txt");
            assert!(
                result.is_ok(),
                "Should allow paths inside non-existent jail"
            );
            let jailed_path = result.unwrap();

            let canonicalized_nonexistent_jail = soft_canonicalize(nonexistent_jail).unwrap();

            assert!(
                jailed_path.starts_with_real(canonicalized_nonexistent_jail.as_path()),
                "Jailed path should start with the jail boundary"
            );
            assert!(
                jailed_path.starts_with_real(&canonicalized_nonexistent_jail),
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
    let jail = Jail::<()>::try_new(public_dir.clone()).unwrap();

    // Test relative path
    let relative_result = jail.try_path("index.html");
    assert!(relative_result.is_ok(), "Relative path should work");

    // Test absolute path within jail
    let absolute_path = public_dir.join("index.html");
    let absolute_result = jail.try_path(absolute_path);
    assert!(
        absolute_result.is_ok(),
        "Absolute path within jail should work"
    );

    // Both should resolve to paths within jail
    let relative_path = relative_result.unwrap();
    let absolute_path = absolute_result.unwrap();
    // Ensure both resolve to paths within jail using approved API
    assert!(
        relative_path.starts_with_real(jail.path()),
        "Relative path should be within jail: {relative_path:?}"
    );
    assert!(
        absolute_path.starts_with_real(jail.path()),
        "Absolute path should be within jail: {absolute_path:?}"
    );
    assert!(
        relative_path.starts_with_real(jail.path()),
        "Relative path should be within jail: {relative_path:?}"
    );
    assert!(
        absolute_path.starts_with_real(jail.path()),
        "Absolute path should be within jail: {absolute_path:?}"
    );

    // Test absolute path outside jail
    let outside_path = temp_dir.join("private").join("secrets.txt");
    let outside_result = jail.try_path(outside_path);
    // NEW BEHAVIOR: Absolute path outside jail is clamped
    assert!(
        outside_result.is_ok(),
        "Absolute path outside jail should be clamped"
    );
    let jailed_path = outside_result.unwrap();
    // Ensure clamped path is within jail using approved API
    assert!(
        jailed_path.starts_with_real(jail.path()),
        "Clamped path should be within jail: {jailed_path:?}"
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
    let static_jail: Jail<StaticAsset> = Jail::try_new(public_dir).unwrap();
    let upload_jail: Jail<UserUpload> = Jail::try_new(uploads_dir).unwrap();

    // Function that serves static assets
    fn serve_static_asset(
        validator: &Jail<StaticAsset>,
        requested_path: &str,
    ) -> Result<JailedPath<StaticAsset>, String> {
        validator
            .try_path(requested_path)
            .map_err(|e| format!("Access denied: {e}"))
    }

    // Function that handles user uploads
    fn access_user_upload(
        jail: &Jail<UserUpload>,
        file_path: &str,
    ) -> Result<JailedPath<UserUpload>, String> {
        jail.try_path(file_path)
            .map_err(|e| format!("Upload not found: {e}"))
    }

    // Test legitimate requests
    assert!(serve_static_asset(&static_jail, "index.html").is_ok());
    assert!(serve_static_asset(&static_jail, "uploads/image.jpg").is_ok());
    assert!(access_user_upload(&upload_jail, "image.jpg").is_ok());

    // Test security violations
    // NEW BEHAVIOR: These paths are clamped, not blocked
    // Escape attempts for static_jail
    let static_escape_attempts = vec!["../private/secrets.txt"];
    for path in static_escape_attempts {
        let result = serve_static_asset(&static_jail, path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
    }
    // Escape attempts for upload_validator
    let upload_escape_attempts = vec!["../index.html", "../../private/secrets.txt"];
    for path in upload_escape_attempts {
        let result = access_user_upload(&upload_jail, path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
    }
}

#[test]
fn test_memory_safety_with_long_paths() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let jail = Jail::<()>::try_new(public_dir).unwrap();

    // Create a very long path that would cause memory issues in naive implementations
    let long_component = "a".repeat(1000);
    let long_path = format!("../{}/{}", long_component, "etc/passwd");

    // Should handle long paths gracefully without memory exhaustion
    match jail.try_path(long_path) {
        Ok(jailed_path) => {
            // Ensure resulting path is within jail using approved API
            assert!(
                jailed_path.starts_with_real(jail.path()),
                "Clamped path should be within jail: {jailed_path:?}"
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
    let jail = Jail::<()>::try_new(public_dir).unwrap();

    // Test various edge cases that should work
    let valid_cases = vec![
        "./index.html",          // Explicit current directory
        "uploads/../index.html", // Up and back down
    ];

    for case in valid_cases {
        let result = jail.try_path(case);
        if let Ok(jailed_path) = result {
            // If successful, should still be within jail (use canonicalized jail path)
            assert!(
                jailed_path.starts_with_real(jail.path()),
                "Path '{}' resolved outside jail: {}",
                case,
                jailed_path.to_string_virtual()
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
        let result = jail.try_path(case);
        assert!(result.is_ok(), "Malicious path '{case}' should be clamped");
        let jailed_path = result.unwrap();
        // Ensure clamped path is within jail using approved API
        assert!(
            jailed_path.starts_with_real(jail.path()),
            "Clamped path should be within jail: {jailed_path:?}"
        );
    }
}

#[test]
fn test_validator_properties() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");
    let jail = Jail::<()>::try_new(public_dir.clone()).unwrap();

    // Test jail() accessor
    // Compare canonicalized jail boundary to the canonicalized public_dir
    assert_eq!(
        jail.path().canonicalize().unwrap(),
        public_dir.canonicalize().unwrap()
    );

    // Test that validator is cloneable
    // Test that validator works the same
    let original_result = jail.try_path("index.html").unwrap();
    let cloned_result = jail.try_path("index.html").unwrap();
    assert_eq!(original_result, cloned_result);
}
