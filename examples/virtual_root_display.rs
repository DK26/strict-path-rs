use jailed_path::{JailedPath, PathValidator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our example
    std::fs::create_dir_all("example_storage/users/alice/documents")?;

    // Create a validator for user files
    struct UserFiles;
    let validator: PathValidator<UserFiles> = PathValidator::with_jail("example_storage")?;

    // Validate and create jailed paths
    let user_doc: JailedPath<UserFiles> = validator.try_path("users/alice/documents/report.pdf")?;
    let user_image: JailedPath<UserFiles> = validator.try_path("users/alice/profile.jpg")?;

    println!("=== Virtual Root Display Demo ===");
    println!();

    // Display shows virtual root (user-friendly)
    println!("User sees clean paths:");
    println!("  Document: {user_doc}"); // Shows: /users/alice/documents/report.pdf
    println!("  Image:    {user_image}"); // Shows: /users/alice/profile.jpg
    println!();

    // Debug shows full internal structure
    println!("Debug shows full details:");
    println!("  Document: {user_doc:?}");
    println!("  Image:    {user_image:?}");
    println!();

    // Jail root is accessible if needed
    println!("Jail root: {}", validator.jail().display());
    println!("User jail root: {}", user_doc.jail().display());
    println!();

    // Still works with all Path methods via Deref
    println!("Path methods still work:");
    println!("  Document filename: {:?}", user_doc.file_name());
    println!("  Document extension: {:?}", user_doc.extension());
    println!("  Document parent: {:?}", user_doc.virtual_parent());
    println!();

    // Works with file operations (AsRef<Path>)
    println!("File operations work seamlessly:");
    match user_doc.metadata() {
        Ok(metadata) => println!("  Document exists: {} bytes", metadata.len()),
        Err(_) => println!("  Document doesn't exist (that's fine for this demo)"),
    }

    // Security: These would be rejected
    println!();
    println!("=== Security Demo ===");

    // These attacks are automatically clamped to stay within jail
    let attacks = vec![
        "../../../etc/passwd",
        "/etc/passwd",
        "users/alice/../../../sensitive.txt",
    ];

    for attack in attacks {
        match validator.try_path(attack) {
            Ok(clamped_path) => {
                // Verify the path was clamped to jail boundary
                assert_eq!(clamped_path.jail(), validator.jail());
                println!("  ✅ Attack clamped: {attack} → {clamped_path}");
            }
            Err(e) => println!("  ❌ Unexpected error for {attack}: {e}"),
        }
    }

    // Cleanup
    std::fs::remove_dir_all("example_storage").ok();

    Ok(())
}
