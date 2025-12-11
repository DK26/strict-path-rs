//! Tests for Windows junction prefix mismatch handling
//!
//! This tests the scenario where a junction inside the boundary points to a target
//! also inside the boundary.
//!
//! Issue: `soft-canonicalize` had a bug where the anchor path was verbatim (`\\?\C:\...`)
//! but the junction target was regular (`C:\...`), causing `strip_prefix` to fail
//! and the path to be treated as "outside" the boundary.

#[cfg(all(windows, feature = "junctions"))]
#[test]
fn test_junction_inside_boundary_prefix_mismatch() {
    use crate::PathBoundary;
    // use std::fs; // Unused

    let td = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::<()>::try_new_create(td.path()).unwrap();

    // Create a target directory inside the boundary
    let target_dir = boundary.strict_join("target").unwrap();
    target_dir.create_dir_all().unwrap();

    // Create a file in the target directory
    target_dir
        .strict_join("file.txt")
        .unwrap()
        .write(b"content")
        .unwrap();

    // Create a junction pointing to the target directory
    // link -> target
    let link_dir = boundary.strict_join("link").unwrap();

    // We use strict_junction helper which handles the creation
    // target_dir.strict_junction(link_path) creates a junction AT link_path pointing TO target_dir
    if let Err(e) = target_dir.strict_junction(link_dir.interop_path()) {
        eprintln!("Skipping test: failed to create junction: {:?}", e);
        return;
    }

    // Now try to access the file through the junction
    // boundary.strict_join("link/file.txt")
    // Should resolve to .../target/file.txt
    match boundary.strict_join("link/file.txt") {
        Ok(path) => {
            let path_str = path.strictpath_to_string_lossy();
            println!("Resolved path: {}", path_str);

            // It should be inside the boundary
            assert!(path.strictpath_starts_with(boundary.interop_path()));

            // It should exist
            assert!(path.exists());
        }
        Err(e) => {
            panic!("Failed to join path through junction: {:?}", e);
        }
    }
}
