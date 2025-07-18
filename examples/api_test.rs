use jailed_path::{JailedPathError, PathValidator};

fn main() -> Result<(), JailedPathError> {
    // Get the current directory as our path jail
    let current_dir = std::env::current_dir().unwrap();
    println!(
        "Setting up path validation jail at: {}",
        current_dir.display()
    );

    // Create a path validator
    let validator: PathValidator = PathValidator::with_jail(&current_dir)?;

    // Test valid path
    match validator.try_path("Cargo.toml") {
        Ok(jailed_path) => {
            println!("✓ Valid path: {}", jailed_path.display());
        }
        Err(e) => {
            println!("✗ Unexpected error: {e}");
        }
    }

    // Test invalid path (directory traversal)
    match validator.try_path("../../../sensitive.txt") {
        Ok(_) => {
            println!("✗ Path validation failed: traversal should have been blocked!");
        }
        Err(e) => {
            println!("✓ Correctly blocked traversal: {e}");
        }
    }

    println!("API test completed successfully!");
    Ok(())
}
