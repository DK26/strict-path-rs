use jailed_path::{Jail, JailedPath};
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
        let jail_root = public_jail.jail().canonicalize().unwrap();
        // Use direct comparison - the JailedPath should start with the jail root
        assert!(
            jailed_path.starts_with(&jail_root),
            "Clamped path should be within jail root: {}",
            jailed_path
        );
    }
    // Escape attempts for upload_validator
    let upload_escape_attempts = vec!["../index.html", "../../private/secrets.txt"];
    for path in upload_escape_attempts {
        let result = upload_jail.try_path(path);
        assert!(result.is_ok(), "Escape attempt should be clamped: {path}");
        let jailed_path = result.unwrap();
        let jail_root = upload_jail.jail().canonicalize().unwrap();
        // Use direct comparison - the JailedPath should start with the jail root
        assert!(
            jailed_path.starts_with(&jail_root),
            "Clamped path should be within jail root: {}",
            jailed_path
        );
    }
}
