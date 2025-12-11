//! Comprehensive security tests for /proc filesystem handling
//!
//! This module provides exhaustive coverage for /proc magic symlink behaviors,
//! ensuring that `strict-path` (via `soft-canonicalize`) correctly handles
//! all variations of /proc paths to prevent container escapes.
//!
//! Covers soft-canonicalize issue #44: Indirect symlinks to /proc/PID/root

#[cfg(target_os = "linux")]
use crate::PathBoundary;
#[cfg(all(target_os = "linux", feature = "virtual-path"))]
use crate::VirtualRoot;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

// =============================================================================
// ISSUE #44 SPECIFIC TESTS
// These tests directly verify the fix for soft-canonicalize issue #44
// =============================================================================

/// Issue #44 core scenario: Indirect symlink to /proc/self/root
/// This is THE critical test that proves issue #44 is fixed.
#[cfg(target_os = "linux")]
#[test]
fn issue_44_indirect_symlink_to_proc_root() {
    let temp = tempfile::tempdir().unwrap();
    let link_path = temp.path().join("container_root");
    let target = PathBuf::from("/proc/self/root");

    std::os::unix::fs::symlink(&target, &link_path).unwrap();

    // THE BUG: Previously this would resolve to "/" instead of "/proc/self/root"
    match PathBoundary::<()>::try_new(&link_path) {
        Ok(boundary) => {
            let boundary_str = boundary.interop_path().to_string_lossy();

            // CRITICAL ASSERTION 1: Must NOT be "/"
            assert_ne!(
                boundary_str, "/",
                "ISSUE #44 NOT FIXED: Indirect symlink to /proc/self/root resolved to /"
            );

            // CRITICAL ASSERTION 2: Must preserve /proc/self/root prefix
            assert!(
                boundary_str.starts_with("/proc/self/root"),
                "ISSUE #44 NOT FIXED: Expected /proc/self/root prefix, got: {}",
                boundary_str
            );

            println!("Issue #44 FIXED: Resolved to {}", boundary_str);
        }
        Err(e) => {
            panic!("Issue #44 test failed unexpectedly: {:?}", e);
        }
    }
}

/// Issue #44 with suffix: Access file through indirect symlink
#[cfg(target_os = "linux")]
#[test]
fn issue_44_indirect_symlink_with_suffix() {
    let temp = tempfile::tempdir().unwrap();
    let link_path = temp.path().join("container");
    let target = PathBuf::from("/proc/self/root");

    std::os::unix::fs::symlink(&target, &link_path).unwrap();

    // Create boundary through the symlink, then join a path
    if let Ok(boundary) = PathBoundary::<()>::try_new(&link_path) {
        match boundary.strict_join("etc/passwd") {
            Ok(path) => {
                let path_str = path.strictpath_to_string_lossy();

                // Must be /proc/self/root/etc/passwd, NOT /etc/passwd
                assert!(
                    path_str.starts_with("/proc/self/root"),
                    "Path through indirect symlink escaped: {}",
                    path_str
                );
                assert_ne!(
                    path_str, "/etc/passwd",
                    "SECURITY BUG: Accessed host /etc/passwd through indirect symlink"
                );
            }
            Err(_) => {
                // Path doesn't exist is acceptable
            }
        }
    }
}

/// Issue #44 with VirtualRoot: Indirect symlink creates proper virtual boundary
#[cfg(all(target_os = "linux", feature = "virtual-path"))]
#[test]
fn issue_44_virtualroot_indirect_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let link_path = temp.path().join("vroot_link");
    let target = PathBuf::from("/proc/self/root");

    std::os::unix::fs::symlink(&target, &link_path).unwrap();

    match VirtualRoot::<()>::try_new(&link_path) {
        Ok(vroot) => {
            let vroot_str = vroot.interop_path().to_string_lossy();

            // Must NOT be "/"
            assert_ne!(
                vroot_str, "/",
                "ISSUE #44 NOT FIXED: VirtualRoot through indirect symlink resolved to /"
            );

            // Must preserve /proc prefix
            assert!(
                vroot_str.starts_with("/proc/self/root"),
                "ISSUE #44 NOT FIXED: VirtualRoot lost prefix: {}",
                vroot_str
            );

            // Test virtual_join through this root
            if let Ok(vpath) = vroot.virtual_join("etc/passwd") {
                let system_path = vpath.as_unvirtual().strictpath_to_string_lossy();
                assert!(
                    system_path.starts_with("/proc/self/root"),
                    "VirtualPath escaped via indirect symlink: {}",
                    system_path
                );
            }
        }
        Err(e) => {
            panic!("VirtualRoot indirect symlink test failed: {:?}", e);
        }
    }
}

// =============================================================================
// CHAINED SYMLINK TESTS
// =============================================================================

/// Test chained symlinks pointing to /proc/self/root
/// link1 -> link2 -> /proc/self/root
#[cfg(target_os = "linux")]
#[test]
fn test_chained_symlinks_to_proc_root() {
    let temp = tempfile::tempdir().unwrap();
    let link2 = temp.path().join("link2");
    let link1 = temp.path().join("link1");
    let target = PathBuf::from("/proc/self/root");

    // Create chain: link1 -> link2 -> /proc/self/root
    std::os::unix::fs::symlink(&target, &link2).unwrap();
    std::os::unix::fs::symlink(&link2, &link1).unwrap();

    match PathBoundary::<()>::try_new(&link1) {
        Ok(boundary) => {
            let boundary_str = boundary.interop_path().to_string_lossy();
            println!("Resolved chained boundary: {}", boundary_str);

            assert_ne!(boundary_str, "/", "Chained symlink resolved to /");
            assert!(
                boundary_str.starts_with("/proc/self/root"),
                "Chained symlink lost prefix: {}",
                boundary_str
            );
        }
        Err(e) => eprintln!("Chained symlink test failed: {:?}", e),
    }
}

/// Test triple-chained symlinks
#[cfg(target_os = "linux")]
#[test]
fn test_triple_chained_symlinks_to_proc() {
    let temp = tempfile::tempdir().unwrap();
    let link3 = temp.path().join("link3");
    let link2 = temp.path().join("link2");
    let link1 = temp.path().join("link1");
    let target = PathBuf::from("/proc/self/root");

    // Create chain: link1 -> link2 -> link3 -> /proc/self/root
    std::os::unix::fs::symlink(&target, &link3).unwrap();
    std::os::unix::fs::symlink(&link3, &link2).unwrap();
    std::os::unix::fs::symlink(&link2, &link1).unwrap();

    match PathBoundary::<()>::try_new(&link1) {
        Ok(boundary) => {
            let boundary_str = boundary.interop_path().to_string_lossy();
            assert_ne!(boundary_str, "/", "Triple-chained symlink resolved to /");
            assert!(
                boundary_str.starts_with("/proc/self/root"),
                "Triple-chained symlink lost prefix: {}",
                boundary_str
            );
        }
        Err(e) => eprintln!("Triple-chained symlink test: {:?}", e),
    }
}

// =============================================================================
// /proc/self/cwd TESTS
// =============================================================================

/// Test /proc/self/cwd magic symlink
#[cfg(target_os = "linux")]
#[test]
fn test_proc_self_cwd_preservation() {
    let target = PathBuf::from("/proc/self/cwd");

    // Direct access
    if let Ok(boundary) = PathBoundary::<()>::try_new(&target) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/", "/proc/self/cwd resolved to /");
        assert!(
            boundary_str.starts_with("/proc/self/cwd"),
            "/proc/self/cwd lost prefix: {}",
            boundary_str
        );
    }

    // Indirect access via symlink
    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("link_to_cwd");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&link) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/", "Symlink to /proc/self/cwd resolved to /");
        assert!(
            boundary_str.starts_with("/proc/self/cwd"),
            "Symlink to /proc/self/cwd lost prefix: {}",
            boundary_str
        );
    }
}

// =============================================================================
// /proc/thread-self/root TESTS
// =============================================================================

/// Test /proc/thread-self/root magic symlink
#[cfg(target_os = "linux")]
#[test]
fn test_proc_thread_self_root_preservation() {
    let target = PathBuf::from("/proc/thread-self/root");

    // Direct access
    if let Ok(boundary) = PathBoundary::<()>::try_new(&target) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/", "/proc/thread-self/root resolved to /");
        assert!(
            boundary_str.starts_with("/proc/thread-self/root"),
            "/proc/thread-self/root lost prefix: {}",
            boundary_str
        );
    }
}

/// Test indirect symlink to /proc/thread-self/root
#[cfg(target_os = "linux")]
#[test]
fn test_indirect_symlink_to_proc_thread_self_root() {
    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("thread_root_link");
    let target = PathBuf::from("/proc/thread-self/root");

    std::os::unix::fs::symlink(&target, &link).unwrap();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&link) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(
            boundary_str, "/",
            "Indirect symlink to /proc/thread-self/root resolved to /"
        );
        assert!(
            boundary_str.starts_with("/proc/thread-self/root"),
            "Indirect symlink lost /proc/thread-self/root prefix: {}",
            boundary_str
        );
    }
}

// =============================================================================
// /proc/{PID}/root TESTS (with actual PID)
// =============================================================================

/// Test /proc/{PID}/root with actual process ID
#[cfg(target_os = "linux")]
#[test]
fn test_proc_pid_root_with_actual_pid() {
    let pid = std::process::id();
    let target = PathBuf::from(format!("/proc/{}/root", pid));

    if !target.exists() {
        eprintln!("Skipping: /proc/{}/root does not exist", pid);
        return;
    }

    if let Ok(boundary) = PathBoundary::<()>::try_new(&target) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/", "/proc/{}/root resolved to /", pid);
        assert!(
            boundary_str.contains("/proc/") && boundary_str.contains("/root"),
            "/proc/{}/root lost prefix: {}",
            pid,
            boundary_str
        );
    }
}

/// Test indirect symlink to /proc/{PID}/root
#[cfg(target_os = "linux")]
#[test]
fn test_indirect_symlink_to_proc_pid_root() {
    let pid = std::process::id();
    let target = PathBuf::from(format!("/proc/{}/root", pid));

    if !target.exists() {
        eprintln!("Skipping: /proc/{}/root does not exist", pid);
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("pid_root_link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&link) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(
            boundary_str, "/",
            "Indirect symlink to /proc/{}/root resolved to /",
            pid
        );
    }
}

// =============================================================================
// DEEP LINK TESTS
// =============================================================================

/// Test symlink pointing deep into /proc
/// link -> /proc/self/root/etc
#[cfg(target_os = "linux")]
#[test]
fn test_symlink_deep_into_proc() {
    let temp = tempfile::tempdir().unwrap();
    let link = temp.path().join("link_deep");
    // Note: /proc/self/root/etc usually exists
    let target = PathBuf::from("/proc/self/root/etc");

    if !target.exists() {
        eprintln!("Skipping deep link test: /proc/self/root/etc does not exist");
        return;
    }

    std::os::unix::fs::symlink(&target, &link).unwrap();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&link) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/etc", "Deep link resolved to host /etc");
        assert!(
            boundary_str.starts_with("/proc/self/root"),
            "Deep link lost /proc prefix: {}",
            boundary_str
        );
    }
}

// =============================================================================
// SYMLINK LOOP TESTS
// =============================================================================

/// Test symlink loop involving /proc
/// link1 -> link2 -> link1
/// This should fail gracefully, not hang
#[cfg(target_os = "linux")]
#[test]
fn test_symlink_loop_handling() {
    let temp = tempfile::tempdir().unwrap();
    let link1 = temp.path().join("loop1");
    let link2 = temp.path().join("loop2");

    std::os::unix::fs::symlink(&link2, &link1).unwrap();
    std::os::unix::fs::symlink(&link1, &link2).unwrap();

    // Should return an error (Too many levels of symbolic links), not hang
    let result = PathBoundary::<()>::try_new(&link1);
    assert!(result.is_err(), "Symlink loop should fail");
}

// =============================================================================
// MIXED CHAIN TESTS
// =============================================================================

/// Test mixed chain: link -> dir -> link -> /proc/self/root
#[cfg(target_os = "linux")]
#[test]
fn test_mixed_chain_to_proc() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("subdir");
    std::fs::create_dir(&dir).unwrap();

    let inner_link = dir.join("inner");
    let target = PathBuf::from("/proc/self/root");
    std::os::unix::fs::symlink(&target, &inner_link).unwrap();

    let outer_link = temp.path().join("outer");
    std::os::unix::fs::symlink(&inner_link, &outer_link).unwrap();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&outer_link) {
        let boundary_str = boundary.interop_path().to_string_lossy();
        assert_ne!(boundary_str, "/", "Mixed chain resolved to /");
        assert!(
            boundary_str.starts_with("/proc/self/root"),
            "Mixed chain lost prefix: {}",
            boundary_str
        );
    }
}

// =============================================================================
// SECURITY SCENARIOS FROM ISSUE #44
// =============================================================================

/// Security scenario: Container boundary validation bypass
/// This is the attack scenario described in issue #44
#[cfg(target_os = "linux")]
#[test]
fn security_container_boundary_bypass_prevented() {
    let temp = tempfile::tempdir().unwrap();
    let container_root_link = temp.path().join("container_root");
    let target = PathBuf::from("/proc/self/root");

    std::os::unix::fs::symlink(&target, &container_root_link).unwrap();

    // Simulate the attack from issue #44:
    // 1. Create boundary from symlink
    // 2. Attempt to access file through boundary
    // 3. Verify it stays within the namespace

    match PathBoundary::<()>::try_new(&container_root_link) {
        Ok(boundary) => {
            // The boundary should be /proc/self/root, NOT /
            let boundary_str = boundary.interop_path().to_string_lossy();

            if boundary_str == "/" {
                panic!(
                    "SECURITY VULNERABILITY: Container boundary resolved to /, \
                     this would allow accessing any file on the host!"
                );
            }

            // Try to access /etc/shadow through the boundary
            match boundary.strict_join("etc/shadow") {
                Ok(path) => {
                    let path_str = path.strictpath_to_string_lossy();
                    // MUST be /proc/self/root/etc/shadow, NOT /etc/shadow
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "SECURITY BUG: Accessed host path: {}",
                        path_str
                    );
                }
                Err(_) => {
                    // Path doesn't exist or access denied - this is fine
                }
            }

            // Try traversal attack
            match boundary.strict_join("../../../etc/shadow") {
                Ok(path) => {
                    let path_str = path.strictpath_to_string_lossy();
                    // Even if somehow accepted, must stay in namespace
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "SECURITY BUG: Traversal escaped to: {}",
                        path_str
                    );
                }
                Err(_) => {
                    // Expected: traversal rejected
                }
            }
        }
        Err(e) => {
            panic!("Unexpected boundary creation failure: {:?}", e);
        }
    }
}

/// Security: Verify host root is NEVER accessible through indirect /proc symlinks
#[cfg(target_os = "linux")]
#[test]
fn security_host_root_never_accessible() {
    let temp = tempfile::tempdir().unwrap();

    // Create multiple indirection patterns
    let patterns = [
        ("/proc/self/root", "direct_proc"),
        ("/proc/self/root", "indirect_single"),
    ];

    for (target, name) in patterns {
        let link = temp.path().join(name);
        std::os::unix::fs::symlink(target, &link).unwrap();

        if let Ok(boundary) = PathBoundary::<()>::try_new(&link) {
            let boundary_str = boundary.interop_path().to_string_lossy();

            assert_ne!(
                boundary_str, "/",
                "Pattern '{}' (-> {}) resolved to host root /",
                name, target
            );
        }
    }
}
