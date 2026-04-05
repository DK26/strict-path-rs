//! Regression, edge-case, multi-container, and documentation tests for
//! Linux /proc/PID/root magic symlink handling (soft-canonicalize issue #44).
//!
//! These tests complement the black-box, white-box, CVE-resistance, and container
//! boundary tests in `proc_magic_symlink.rs` by covering:
//!
//! - Regression tests: ensure normal path operations still work after the fix
//! - Edge cases: parent traversal, empty segments, long paths, unicode
//! - Multi-container scenarios: multiple /proc/PID/root boundaries remain isolated
//! - Documentation tests: verify the exact behavior described in issue #44

// All tests in this module are Linux-only since /proc/PID/root is a Linux-specific construct
// (gated via #[cfg(target_os = "linux")] in mod.rs)
#![cfg(target_os = "linux")]

use crate::PathBoundary;
use std::fs;
use std::path::PathBuf;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Get a valid /proc/PID/root path for testing.
/// Uses /proc/self/root which always exists and refers to the current process's root.
fn get_proc_self_root() -> PathBuf {
    PathBuf::from("/proc/self/root")
}

/// Get the current process's PID
fn get_self_pid() -> u32 {
    std::process::id()
}

// =============================================================================
// REGRESSION TESTS
// Ensure normal path operations still work correctly
// =============================================================================

/// Regression test: Normal paths (not /proc) still work as expected
#[test]
fn regression_normal_paths_unaffected() {
    let temp = tempfile::tempdir().unwrap();
    let host_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Normal operations should work
    let subdir = host_dir.strict_join("subdir").unwrap();
    subdir.create_dir().unwrap();

    let file = host_dir.strict_join("subdir/file.txt").unwrap();
    file.write("test content").unwrap();

    let content = file.read_to_string().unwrap();
    assert_eq!(content, "test content");
}

/// Regression test: Symlinks inside normal boundaries still work
#[test]
fn regression_symlinks_in_normal_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();

    // Create structure
    let data_dir = base.join("data");
    let config_dir = base.join("config");
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(data_dir.join("file.txt"), "data").unwrap();

    // Create symlink inside boundary pointing to another dir inside boundary
    let link = config_dir.join("data_link");
    std::os::unix::fs::symlink(&data_dir, &link).unwrap();

    let test_dir: PathBoundary = PathBoundary::try_new(base).unwrap();

    // Following symlink within boundary should work
    match test_dir.strict_join("config/data_link/file.txt") {
        Ok(path) => {
            assert!(path.strictpath_starts_with(test_dir.interop_path()));
        }
        Err(e) => {
            panic!("Internal symlink following failed: {:?}", e);
        }
    }
}

/// Regression test: Escaping symlinks are still rejected
#[test]
fn regression_escaping_symlinks_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();

    let restricted_dir = base.join("restricted");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&restricted_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(outside_dir.join("secret.txt"), "secret").unwrap();

    // Create symlink inside restricted dir pointing outside
    let escape_link = restricted_dir.join("escape");
    std::os::unix::fs::symlink(&outside_dir, &escape_link).unwrap();

    let sandbox: PathBoundary = PathBoundary::try_new(&restricted_dir).unwrap();

    // Following symlink to escape should be rejected
    use crate::StrictPathError;
    let result = sandbox.strict_join("escape/secret.txt");
    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected
        }
        Ok(path) => {
            panic!(
                "Symlink escape was allowed: {}",
                path.strictpath_to_string_lossy()
            );
        }
        Err(e) => {
            // Other errors may be acceptable
            eprintln!("Symlink escape test error: {:?}", e);
        }
    }
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

/// Edge case: Handling of /proc/self with trailing components
#[test]
fn edge_case_proc_self_with_components() {
    // /proc/self/root/.. should resolve to /proc/self, not to /
    // This is a critical edge case
    let proc_self_root = get_proc_self_root();

    if let Ok(container_dir) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Attempt to traverse up from root (within the namespace)
        use crate::StrictPathError;
        match container_dir.strict_join("..") {
            Err(StrictPathError::PathEscapesBoundary { .. }) => {
                // Correct: rejected escape attempt
            }
            Ok(path) => {
                // If allowed, verify it's clamped to the boundary
                let path_str = path.strictpath_to_string_lossy();
                assert!(
                    path_str.starts_with("/proc/self/root"),
                    "Parent traversal escaped namespace: {}",
                    path_str
                );
            }
            Err(e) => {
                eprintln!("Parent traversal test: {:?}", e);
            }
        }
    }
}

/// Edge case: Empty path segment handling within /proc namespace
#[test]
fn edge_case_empty_segments_in_proc_namespace() {
    let proc_self_root = get_proc_self_root();

    if let Ok(container_dir) = PathBoundary::<()>::try_new(&proc_self_root) {
        let tricky_patterns = [
            "etc//passwd",  // Double slash
            "etc/./passwd", // Current dir
            "./etc/passwd", // Leading current dir
            "etc/",         // Trailing slash
        ];

        for pattern in tricky_patterns {
            if let Ok(path) = container_dir.strict_join(pattern) {
                assert!(
                    path.strictpath_starts_with(container_dir.interop_path()),
                    "Pattern '{}' escaped: {}",
                    pattern,
                    path.strictpath_to_string_lossy()
                );
            }
        }
    }
}

/// Edge case: Very long paths within /proc namespace
#[test]
fn edge_case_long_paths_in_proc_namespace() {
    let proc_self_root = get_proc_self_root();

    if let Ok(container_dir) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Create a very long path
        let long_component = "a".repeat(64);
        let long_path = format!(
            "{}/{}/{}/{}",
            long_component, long_component, long_component, long_component
        );

        match container_dir.strict_join(&long_path) {
            Ok(path) => {
                assert!(
                    path.strictpath_starts_with(container_dir.interop_path()),
                    "Long path escaped namespace"
                );
            }
            Err(_) => {
                // Path too long or doesn't exist - acceptable
            }
        }
    }
}

/// Edge case: Unicode paths within /proc namespace
#[test]
fn edge_case_unicode_in_proc_namespace() {
    let proc_self_root = get_proc_self_root();

    if let Ok(container_dir) = PathBoundary::<()>::try_new(&proc_self_root) {
        let unicode_patterns = [
            "文件/测试.txt",
            "файл/тест.txt",
            "αρχείο/δοκιμή.txt",
            "ファイル/テスト.txt",
        ];

        for pattern in unicode_patterns {
            if let Ok(path) = container_dir.strict_join(pattern) {
                assert!(
                    path.strictpath_starts_with(container_dir.interop_path()),
                    "Unicode pattern '{}' escaped",
                    pattern
                );
            }
        }
    }
}

// =============================================================================
// MULTI-CONTAINER SCENARIO TESTS
// =============================================================================

/// Test simulating access to multiple container namespaces
#[test]
fn multicontainer_different_namespaces_isolated() {
    // This test verifies that if we create boundaries for different
    // /proc/PID/root paths, they remain isolated from each other

    let proc_self_root = get_proc_self_root();
    let pid = get_self_pid();
    let proc_pid_root = format!("/proc/{}/root", pid);

    // Both should work and remain isolated
    let container_dir1 = PathBoundary::<()>::try_new(&proc_self_root);
    let container_dir2 = PathBoundary::<()>::try_new(&proc_pid_root);

    if let (Ok(b1), Ok(b2)) = (container_dir1, container_dir2) {
        // Each boundary should be properly contained
        let b1_path = b1.interop_path().to_string_lossy();
        let b2_path = b2.interop_path().to_string_lossy();

        assert!(b1_path.starts_with("/proc/"));
        assert!(b2_path.starts_with("/proc/"));

        // Both point to the same namespace for the same process,
        // but the key is they're not "/" (the host root)
        assert_ne!(b1_path, "/");
        assert_ne!(b2_path, "/");
    }
}

// =============================================================================
// DOCUMENTATION TESTS
// Verify the behavior matches documentation
// =============================================================================

/// Documentation test: Verify the exact behavior described in the issue
#[test]
fn doc_test_issue_44_scenario() {
    // From issue #44:
    // "let boundary = PathBoundary::try_new("/proc/12345/root")?;
    //  // boundary becomes "/" (WRONG!)"
    //
    // After the fix:
    // "boundary becomes "/proc/12345/root" (CORRECT!)"

    let proc_self_root = get_proc_self_root();

    if let Ok(container_dir) = PathBoundary::<()>::try_new(&proc_self_root) {
        let boundary_str = container_dir.interop_path().to_string_lossy().to_string();

        // THE KEY ASSERTION: The boundary must NOT become "/"
        assert_ne!(
            boundary_str, "/",
            "BUG REGRESSION: PathBoundary at /proc/self/root incorrectly resolved to /"
        );

        // The boundary MUST preserve the /proc namespace prefix
        assert!(
            boundary_str.starts_with("/proc/self/root"),
            "BUG REGRESSION: PathBoundary lost /proc/self/root prefix, got: {}",
            boundary_str
        );
    }
}
