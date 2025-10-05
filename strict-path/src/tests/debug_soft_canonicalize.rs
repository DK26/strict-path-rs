// Debug test to verify soft-canonicalize behavior with symlinks
#[cfg(windows)]
use std::path::Path;

#[test]
#[cfg(windows)]
fn debug_soft_canonicalize_with_symlinks() {
    let temp = tempfile::tempdir().unwrap();

    // Setup directory structure
    let restriction = temp.path().join("restriction");
    std::fs::create_dir_all(&restriction).unwrap();

    let safe_dir = restriction.join("safe");
    std::fs::create_dir_all(&safe_dir).unwrap();

    let safe_file = safe_dir.join("file.txt");
    std::fs::write(&safe_file, "safe content").unwrap();

    let link_path = restriction.join("link");

    // Create symlink with relative target
    use std::os::windows::fs::symlink_file;
    let rel_target = Path::new("safe").join("file.txt");

    println!("\n=== TEST 1: Non-canonicalized paths ===");
    println!("restriction: {:?}", restriction);
    println!("link_path: {:?}", link_path);

    if let Err(e) = symlink_file(&rel_target, &link_path) {
        println!("Skipping test - symlink creation failed: {e:?}");
        return;
    }
    println!("✓ Symlink created");

    // Test soft-canonicalize with non-canonicalized anchor
    println!("\n--- Testing soft-canonicalize with clean paths ---");
    test_anchored_canonicalize(&restriction, "link");

    // Now test with canonicalized anchor
    println!("\n=== TEST 2: Canonicalized anchor ===");
    let restriction_canon = std::fs::canonicalize(&restriction).unwrap();
    println!("Canonicalized restriction: {:?}", restriction_canon);

    // The symlink already exists at the clean path
    let link_path_canon = restriction_canon.join("link");
    println!("link_path_canon: {:?}", link_path_canon);

    // Can we read it via canonicalized path?
    println!("Reading via canonicalized path: {:?}", link_path_canon);
    match std::fs::read_to_string(&link_path_canon) {
        Ok(content) => println!("✓ Read via canon path succeeded: '{}'", content),
        Err(e) => println!("✗ Read via canon path failed: {:?}", e),
    }

    println!("\n--- Testing soft-canonicalize with canonicalized anchor ---");
    test_anchored_canonicalize(&restriction_canon, "link");
}

#[cfg(windows)]
fn test_anchored_canonicalize(anchor: &Path, candidate: &str) {
    println!("Anchor: {:?}", anchor);
    println!("Candidate: {:?}", candidate);

    match soft_canonicalize::anchored_canonicalize(anchor, candidate) {
        Ok(result) => {
            println!("✓ anchored_canonicalize succeeded");
            println!("  Result: {:?}", result);
            println!("  Result exists: {}", result.exists());

            // Can we read it?
            match std::fs::read_to_string(&result) {
                Ok(content) => println!("  ✓ Read succeeded: '{}'", content),
                Err(e) => println!("  ✗ Read failed: {:?}", e),
            }
        }
        Err(e) => {
            println!("✗ anchored_canonicalize failed: {:?}", e);
        }
    }
}
