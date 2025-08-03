use jailed_path::try_jail;
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
        "jailed_path_try_jail_test_{}_{}",
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
fn test_try_jail_success() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");

    let jailed_path: jailed_path::JailedPath = try_jail(public_dir, "index.html").unwrap();
    assert!(jailed_path.ends_with("index.html"));
}

#[test]
fn test_try_jail_escape() {
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");

    let result: Result<jailed_path::JailedPath, jailed_path::JailedPathError> =
        try_jail(public_dir, "../private/secrets.txt");
    assert!(result.is_ok());
}

#[test]
fn test_try_jail_with_marker() {
    struct MyMarker;
    let temp_dir = create_test_directory().expect("Failed to create test directory");
    let public_dir = temp_dir.join("public");

    let jailed_path: jailed_path::JailedPath<MyMarker> =
        try_jail(public_dir, "index.html").unwrap();
    assert!(jailed_path.ends_with("index.html"));
    // You can add more assertions here to verify the marker type if needed, e.g., using `std::any::TypeId`
}
