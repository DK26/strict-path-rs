use jailed_path::Jail;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our demonstration
    fs::create_dir_all("file_ops_demo")?;

    let jail = Jail::<()>::try_new("file_ops_demo")?;
    let file_path = jail.jailed_join("demo.txt")?;

    println!("=== JailedPath Built-in File Operations Demo ===");

    // Write to file using built-in method
    file_path.write_string("Hello from JailedPath built-in methods!")?;
    println!("-> File written using built-in method");

    // Check if file exists using built-in method
    if file_path.exists() {
        println!("-> File exists (checked with built-in method)");

        // Read file using built-in method
        let content = file_path.read_to_string()?;
        println!("Content: {content}");

        // Get metadata using built-in method
        let metadata = file_path.metadata()?;
        let size = metadata.len();
        println!("File size: {size} bytes");

        // Check if it's a file using built-in method
        if file_path.is_file() {
            println!("-> Confirmed it's a file (checked with built-in method)");
        }
    }

    // Write binary data using built-in method
    file_path.write_bytes(b"Binary data from built-in methods!")?;
    println!("-> Binary data written using built-in method");

    // Read as bytes using built-in method
    let bytes = file_path.read_bytes()?;
    let n = bytes.len();
    println!("Read {n} bytes using built-in method");

    // Create a subdirectory using built-in method
    let subdir = jail.jailed_join("subdir")?;
    subdir.create_dir_all()?;
    println!("-> Directory created using built-in method");

    if subdir.is_dir() {
        println!("-> Confirmed it's a directory (checked with built-in method)");
    }

    // Clean up using built-in methods
    file_path.remove_file()?;
    println!("-> File removed using built-in method");

    subdir.remove_dir()?;
    println!("-> Directory removed using built-in method");

    // Clean up the demo directory
    fs::remove_dir_all("file_ops_demo")?;

    println!("\nAll file operations completed successfully using JailedPath's built-in methods!");

    Ok(())
}

