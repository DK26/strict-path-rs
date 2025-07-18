use soft_canonicalize::soft_canonicalize;
use std::path::Path;

fn main() -> std::io::Result<()> {
    println!("=== Soft Canonicalize - Basic Usage Examples ===\n");

    // Example 1: Existing path (works like std::fs::canonicalize)
    println!("1. Canonicalizing existing path:");
    let temp_dir = std::env::temp_dir();
    let existing = soft_canonicalize(&temp_dir)?;
    println!("   Input:  {:?}", temp_dir);
    println!("   Output: {:?}\n", existing);

    // Example 2: Non-existing path
    println!("2. Canonicalizing non-existing path:");
    let non_existing_path = temp_dir.join("some/deep/non/existing/path.txt");
    let non_existing = soft_canonicalize(&non_existing_path)?;
    println!("   Input:  {:?}", non_existing_path);
    println!("   Output: {:?}\n", non_existing);

    // Example 3: Relative path
    println!("3. Canonicalizing relative path:");
    let relative_path = Path::new("examples/relative/file.txt");
    let relative = soft_canonicalize(relative_path)?;
    println!("   Input:  {:?}", relative_path);
    println!("   Output: {:?}\n", relative);

    // Example 4: Directory traversal
    println!("4. Resolving directory traversal:");
    let traversal_path = Path::new("some/path/../other/file.txt");
    let traversal = soft_canonicalize(traversal_path)?;
    println!("   Input:  {:?}", traversal_path);
    println!("   Output: {:?}\n", traversal);

    // Example 5: Complex traversal pattern
    println!("5. Complex traversal pattern:");
    let complex_path = Path::new("deep/nested/path/../../final/file.txt");
    let complex = soft_canonicalize(complex_path)?;
    println!("   Input:  {:?}", complex_path);
    println!("   Output: {:?}\n", complex);

    // Example 6: Current directory references
    println!("6. Current directory references:");
    let current_dir_path = Path::new("./some/./path/./file.txt");
    let current_dir = soft_canonicalize(current_dir_path)?;
    println!("   Input:  {:?}", current_dir_path);
    println!("   Output: {:?}\n", current_dir);

    // Example 7: Mixed existing and non-existing
    println!("7. Mixed existing and non-existing components:");
    let mixed_path = temp_dir.join("new_folder/subfolder/file.txt");
    let mixed = soft_canonicalize(&mixed_path)?;
    println!("   Input:  {:?}", mixed_path);
    println!("   Output: {:?}\n", mixed);

    println!("All examples completed successfully!");
    Ok(())
}
