//! Security tests for indirect symlinks to /proc/PID/root
//!
//! This tests if a symlink pointing to a magic /proc path is correctly handled.
//! If `soft_canonicalize` only checks the input path prefix, it might miss
//! that a symlink resolves to a magic /proc path, and then `std::fs::canonicalize`
//! would resolve it to `/`.

use crate::PathBoundary;
use std::path::PathBuf;

#[test]
fn test_indirect_symlink_to_proc_root() {
    // Create a temp directory
    let temp = tempfile::tempdir().unwrap();
    let link_path = temp.path().join("link_to_proc");

    // Create a symlink: link_to_proc -> /proc/self/root
    // We use /proc/self/root because it exists and is accessible
    let target = PathBuf::from("/proc/self/root");

    if let Err(e) = std::os::unix::fs::symlink(&target, &link_path) {
        eprintln!("Skipping test: failed to create symlink: {:?}", e);
        return;
    }

    // Now try to create a boundary from the symlink
    // If vulnerable: resolves to "/"
    // If secure: resolves to "/proc/self/root"
    match PathBoundary::<()>::try_new(&link_path) {
        Ok(boundary) => {
            let boundary_path = boundary.interop_path();
            let boundary_str = boundary_path.to_string_lossy();

            println!("Resolved boundary path: {}", boundary_str);

            // CRITICAL CHECK: It must NOT be "/"
            assert_ne!(
                boundary_str, "/",
                "SECURITY FAILURE: Indirect symlink to /proc/self/root resolved to /"
            );

            // Ideally, it should be /proc/self/root
            assert!(
                boundary_str.starts_with("/proc/self/root"),
                "Boundary should resolve to /proc/self/root, got: {}",
                boundary_str
            );
        }
        Err(e) => {
            // It might fail if /proc/self/root is not accessible, which is fine
            eprintln!("Boundary creation failed: {:?}", e);
        }
    }
}
