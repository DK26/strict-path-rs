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
            println!("✓ Valid path: {}", jailed_path.virtual_display());
        }
        Err(e) => {
            println!("✗ Unexpected error: {e}");
        }
    }

    // Test path with directory traversal (gets clamped to jail root)
    match validator.try_path("../../../sensitive.txt") {
        Ok(clamped_path) => {
            println!(
                "✓ Path traversal clamped to jail root: {}",
                clamped_path.virtual_display()
            );
            println!("  Real path: {}", clamped_path.real_path().display());
        }
        Err(e) => {
            println!("✗ Unexpected error for clamped path: {e}");
        }
    }

    println!("API test completed successfully!");
    Ok(())
}
