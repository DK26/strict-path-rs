use jailed_path::{Jail, JailedPathError};

fn main() -> Result<(), JailedPathError> {
    // Get the current directory as our path jail
    let current_dir = std::env::current_dir().unwrap();
    println!(
        "Setting up path validation jail at: {}",
        current_dir.display()
    );

    // Create a path validator
    let jail: Jail = Jail::try_new(&current_dir)?;

    // Test valid path
    match jail.try_path("Cargo.toml") {
        Ok(jailed_path) => {
            println!(
                "✓ Valid path: {}",
                jailed_path.virtualize().virtualpath_to_string()
            );
        }
        Err(e) => {
            println!("✗ Unexpected error: {e}");
        }
    }

    // Test path with directory traversal (gets clamped to jail root)
    match jail.try_path("../../../sensitive.txt") {
        Ok(clamped_path) => {
            println!(
                "✓ Path traversal clamped to jail root: {}",
                clamped_path.clone().virtualize().virtualpath_to_string()
            );
            println!("  Real path: {}", clamped_path.realpath_to_string());
        }
        Err(e) => {
            println!("✗ Unexpected error for clamped path: {e}");
        }
    }

    println!("API test completed successfully!");
    Ok(())
}
