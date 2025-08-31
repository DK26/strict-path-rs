use jailed_path::{VirtualRoot, JailedPathError};

fn main() -> Result<(), JailedPathError> {
    // Get the current directory as our path jail
    let current_dir = std::env::current_dir().unwrap();
    println!(
        "Setting up path validation jail at: {}",
        current_dir.display()
    );

    // Create a virtual root for user-facing paths
    let vroot: VirtualRoot = VirtualRoot::try_new(&current_dir)?;

    // Test valid path
    match vroot.try_virtual_path("Cargo.toml") {
        Ok(jailed_path) => {
            println!(
                "✓ Valid path: {}",
                jailed_path.virtualpath_to_string_lossy()
            );
        }
        Err(e) => {
            println!("✗ Unexpected error: {e}");
        }
    }

    // Test path with directory traversal (gets clamped to jail root)
    match vroot.try_virtual_path("../../../sensitive.txt") {
        Ok(clamped_path) => {
            println!(
                "✓ Path traversal clamped to jail root: {}",
                clamped_path.virtualpath_to_string_lossy()
            );
            println!("  System path: {}", clamped_path.systempath_to_string_lossy());
        }
        Err(e) => {
            println!("✗ Unexpected error for clamped path: {e}");
        }
    }

    println!("API test completed successfully!");
    Ok(())
}
