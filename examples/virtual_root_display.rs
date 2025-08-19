use jailed_path::{Jail, JailedPath};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our example
    std::fs::create_dir_all("example_storage/users/alice/documents")?;

    // Create a validator for user files
    #[derive(Clone, Debug)]
    struct UserFiles;
    let jail: Jail<UserFiles> = Jail::try_new("example_storage")?;

    // Validate and create jailed paths
    let user_doc: JailedPath<UserFiles> = jail.try_path("users/alice/documents/report.pdf")?;
    let user_image: JailedPath<UserFiles> = jail.try_path("users/alice/profile.jpg")?;

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
    println!("Jail root: {}", jail.path().to_string_lossy());
    println!(
        "User jail root: {}",
        user_doc.clone().virtualize().virtualpath_to_string()
    );
    println!();

    // Still works with the explicit virtual APIs
    println!("Path methods still work (virtual):");
    println!(
        "  Document filename: {:?}",
        user_doc.clone().virtualize().file_name_virtual()
    );
    println!(
        "  Document extension: {:?}",
        user_doc.clone().virtualize().extension_virtual()
    );
    println!(
        "  Document parent: {:?}",
        user_doc.clone().virtualize().parent_virtual().unwrap()
    );
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
        match jail.try_path(attack) {
            Ok(clamped_path) => {
                // Verify the path was clamped to jail boundary
                assert!(clamped_path.starts_with_real(jail.path()));
                println!(
                    "  Attack clamped: {} -> {}",
                    attack,
                    clamped_path.virtualize().virtualpath_to_string()
                );
            }
            Err(e) => println!("  Unexpected error for {attack}: {e}"),
        }
    }

    // Cleanup
    std::fs::remove_dir_all("example_storage").ok();

    Ok(())
}
