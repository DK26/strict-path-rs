use jailed_path::{Jail, JailedPath};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for the example
    let temp_dir = std::env::temp_dir().join("jailed_path_new_api_example");
    fs::create_dir_all(&temp_dir)?;

    println!("🔒 Demonstrating the new Jail API");
    println!("Using temp directory: {}", temp_dir.display());

    // 1. Create a jail using the new API
    let docs_jail: Jail = Jail::try_new(&temp_dir)?;
    println!("✅ Created jail at: {}", temp_dir.display());

    // 2. Validate paths using the jail
    let doc_path = docs_jail.try_path("file.doc")?;
    println!("📄 Validated path: {doc_path}");

    // 3. Test security - path traversal attempts are automatically clamped
    let attack_path = docs_jail.try_path("../../../etc/passwd")?;
    println!("🛡️  Attack attempt clamped to: {attack_path}");

    // Verify the attack was indeed neutralized - check that it starts with the jail root
    assert!(attack_path.starts_with_real(docs_jail.path()));
    println!("Security verified: attack path is contained within jail");

    // 4. Demonstrate type-safe markers for different jails
    struct Documents;
    struct Images;

    // Create subdirectories first
    fs::create_dir_all(temp_dir.join("docs"))?;
    fs::create_dir_all(temp_dir.join("images"))?;

    let doc_jail: Jail<Documents> = Jail::try_new(temp_dir.join("docs"))?;
    let img_jail: Jail<Images> = Jail::try_new(temp_dir.join("images"))?;

    // Create some test paths
    let doc_file: JailedPath<Documents> = doc_jail.try_path("report.pdf")?;
    let img_file: JailedPath<Images> = img_jail.try_path("photo.jpg")?;

    println!("📄 Document path: {doc_file}");
    println!("🖼️  Image path: {img_file}");

    // The following would cause a compile error (uncomment to test):
    // fn process_document(path: &JailedPath<Documents>) {}
    // process_document(&img_file); // ❌ Compile error: wrong marker type!

    println!("✅ Type safety verified: different jail markers prevent mix-ups");

    // 5. Built-in file operations
    doc_file.write_string("This is a secure document")?;
    let content = doc_file.read_to_string()?;
    println!("📄 File content: {content}");

    // Cleanup
    fs::remove_dir_all(&temp_dir).ok();
    println!("🧹 Cleaned up temp directory");

    println!("\n🎉 New Jail API demonstration complete!");
    println!("   The new API is more intuitive: Jail::try_new() creates a jail");

    Ok(())
}
