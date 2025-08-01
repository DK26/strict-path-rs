use jailed_path::{JailedFileOps, PathValidator};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our demonstration
    fs::create_dir_all("trait_demo")?;

    let validator = PathValidator::<()>::with_jail("trait_demo")?;
    let file_path = validator.try_path("demo.txt")?;

    println!("=== JailedFileOps Trait Demo ===");

    // Write to file using trait method
    file_path.write_string("Hello from JailedFileOps trait!")?;
    println!("✅ File written using trait method");

    // Check if file exists using trait method
    if file_path.exists() {
        println!("✅ File exists (checked with trait method)");

        // Read file using trait method
        let content = file_path.read_to_string()?;
        println!("📖 Content: {content}");

        // Get metadata using trait method
        let metadata = file_path.metadata()?;
        println!("📊 File size: {} bytes", metadata.len());

        // Check if it's a file using trait method
        if file_path.is_file() {
            println!("✅ Confirmed it's a file (checked with trait method)");
        }
    }

    // Write binary data using trait method
    file_path.write_bytes(b"Binary data from trait!")?;
    println!("✅ Binary data written using trait method");

    // Read as bytes using trait method
    let bytes = file_path.read_bytes()?;
    println!("📖 Read {} bytes using trait method", bytes.len());

    // Create a subdirectory using trait method
    let subdir = validator.try_path("subdir")?;
    subdir.create_dir_all()?;
    println!("✅ Directory created using trait method");

    if subdir.is_dir() {
        println!("✅ Confirmed it's a directory (checked with trait method)");
    }

    // Clean up using trait methods
    file_path.remove_file()?;
    println!("🗑️  File removed using trait method");

    subdir.remove_dir()?;
    println!("🗑️  Directory removed using trait method");

    // Clean up the demo directory
    fs::remove_dir_all("trait_demo")?;

    println!("\n🎉 All file operations completed successfully using the JailedFileOps trait!");
    println!("   Notice: No need to call .real_path() anywhere - the trait handles it!");

    Ok(())
}
