//! Security tests for Linux /proc/PID/root magic symlink handling
//!
//! ## Vulnerability Background (soft-canonicalize issue #44)
//!
//! `/proc/PID/root` and `/proc/PID/cwd` are "magic symlinks" in Linux that provide
//! access to a process's root filesystem and current working directory within its
//! mount namespace (e.g., a container).
//!
//! ### The Problem
//!
//! `std::fs::canonicalize` (and by extension, older versions of `soft_canonicalize`)
//! calls `readlink()` on these magic symlinks, which returns `/`. This completely
//! loses the namespace context:
//!
//! ```text
//! // DANGEROUS OLD BEHAVIOR:
//! soft_canonicalize("/proc/1234/root") → "/"
//! soft_canonicalize("/proc/1234/root/etc/passwd") → "/etc/passwd"
//! ```
//!
//! ### Security Impact
//!
//! When using `PathBoundary::try_new("/proc/PID/root")` to create a container boundary,
//! the boundary silently becomes `/` (host root!), making security checks useless:
//!
//! ```text
//! // ATTACK SCENARIO:
//! let boundary = PathBoundary::try_new("/proc/12345/root")?;
//! // boundary becomes "/" (WRONG!)
//!
//! boundary.strict_join("../../../etc/shadow")?;
//! // This now checks against "/" not the container root!
//! // SECURITY BYPASS!
//! ```
//!
//! ### The Fix (proc-canonicalize integration)
//!
//! `soft-canonicalize` v0.5.0 integrates `proc-canonicalize` which preserves the
//! namespace prefix instead of resolving it:
//!
//! ```text
//! // CORRECT NEW BEHAVIOR:
//! soft_canonicalize("/proc/1234/root") → "/proc/1234/root"
//! soft_canonicalize("/proc/1234/root/etc/passwd") → "/proc/1234/root/etc/passwd"
//! ```
//!
//! ## Test Categories
//!
//! These tests validate that `strict-path` correctly handles Linux namespace boundaries:
//!
//! 1. **Black-box tests**: Test from attacker's perspective without knowledge of internals
//! 2. **White-box tests**: Test internal behavior and edge cases
//! 3. **CVE resistance tests**: Test against known container escape patterns
//! 4. **Container boundary tests**: Test PathBoundary/VirtualRoot with /proc paths
//! 5. **Regression tests**: Ensure the fix doesn't break normal paths

// All tests in this module are Linux-only since /proc/PID/root is a Linux-specific construct
// (gated via #[cfg(target_os = "linux")] in mod.rs)

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{PathBoundary, StrictPathError};
use std::fs;
use std::path::{Path, PathBuf};

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
// BLACK-BOX SECURITY TESTS
// Tests from an attacker's perspective without knowledge of internal implementation
// =============================================================================

/// Black-box test: Verify /proc/self/root is preserved as a path prefix
/// This is the fundamental test that the magic symlink is NOT resolved to "/"
#[test]
fn blackbox_proc_self_root_prefix_preserved() {
    let proc_self_root = get_proc_self_root();

    // Create a boundary at /proc/self/root
    // The key security property: this should NOT become "/"
    match PathBoundary::<()>::try_new(&proc_self_root) {
        Ok(boundary) => {
            // The boundary's interop path must preserve the /proc/self/root prefix
            let boundary_path = boundary.interop_path();
            let boundary_str = boundary_path.to_string_lossy();

            assert!(
                boundary_str.starts_with("/proc/self/root"),
                "SECURITY FAILURE: /proc/self/root was resolved to {} instead of preserving the namespace prefix",
                boundary_str
            );

            // Additional sanity check: it should NOT be just "/"
            assert_ne!(
                boundary_str, "/",
                "SECURITY FAILURE: /proc/self/root was incorrectly resolved to /"
            );
        }
        Err(e) => {
            // On systems where /proc/self/root isn't accessible, skip gracefully
            eprintln!("Skipping test: /proc/self/root not accessible: {e:?}");
        }
    }
}

/// Black-box test: Attacker attempts to escape container boundary using traversal
#[test]
fn blackbox_container_escape_via_traversal_rejected() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Attack pattern: escape using parent directory traversal
        let attack_patterns = [
            "../etc/shadow",
            "../../etc/passwd",
            "../../../var/log/auth.log",
            "../../../../root/.ssh/id_rsa",
            "../../../../../etc/sudoers",
        ];

        for attack_input in attack_patterns {
            let result = boundary.strict_join(attack_input);
            match result {
                Err(StrictPathError::PathEscapesBoundary { .. }) => {
                    // Expected: traversal attack correctly rejected
                }
                Err(StrictPathError::PathResolutionError { .. }) => {
                    // Also acceptable: path doesn't exist
                }
                Ok(path) => {
                    // Verify the path is still within the boundary (clamped)
                    let path_str = path.strictpath_to_string_lossy();
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "SECURITY FAILURE: Attack pattern '{}' escaped to: {}",
                        attack_input,
                        path_str
                    );
                }
                Err(e) => {
                    panic!(
                        "Unexpected error for attack pattern '{}': {:?}",
                        attack_input, e
                    );
                }
            }
        }
    }
}

/// Black-box test: Attacker attempts to access host /etc/passwd via /proc path
#[test]
fn blackbox_host_etc_passwd_access_blocked() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // The boundary is at /proc/self/root
        // Accessing "etc/passwd" should give /proc/self/root/etc/passwd
        // NOT /etc/passwd on the host
        match boundary.strict_join("etc/passwd") {
            Ok(passwd_path) => {
                let path_str = passwd_path.strictpath_to_string_lossy();

                // CRITICAL: The path MUST be within /proc/self/root
                assert!(
                    path_str.starts_with("/proc/self/root"),
                    "SECURITY FAILURE: etc/passwd resolved to host path: {}",
                    path_str
                );

                // CRITICAL: It must NOT be the raw /etc/passwd
                assert_ne!(
                    path_str, "/etc/passwd",
                    "SECURITY FAILURE: Boundary bypass allowed access to /etc/passwd"
                );
            }
            Err(e) => {
                // Path doesn't exist or resolution failed - this is acceptable
                eprintln!("Expected: etc/passwd access resulted in: {:?}", e);
            }
        }
    }
}

/// Black-box test: Attacker creates boundary then attempts absolute path escape
#[test]
fn blackbox_absolute_path_escape_rejected() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Attempt to use absolute paths to escape
        let absolute_escape_attempts = ["/etc/shadow", "/root/.bashrc", "/var/log/syslog", "/home"];

        for attack_input in absolute_escape_attempts {
            let result = boundary.strict_join(attack_input);
            match result {
                Err(StrictPathError::PathEscapesBoundary { .. }) => {
                    // Expected: absolute path escape rejected
                }
                Err(StrictPathError::PathResolutionError { .. }) => {
                    // Also acceptable
                }
                Ok(path) => {
                    // If accepted, must still be within the namespace boundary
                    let path_str = path.strictpath_to_string_lossy();
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "SECURITY FAILURE: Absolute path '{}' escaped to: {}",
                        attack_input,
                        path_str
                    );
                }
                Err(e) => {
                    panic!("Unexpected error for '{}': {:?}", attack_input, e);
                }
            }
        }
    }
}

// =============================================================================
// WHITE-BOX SECURITY TESTS
// Tests with knowledge of internal implementation details
// =============================================================================

/// White-box test: Verify /proc/PID/root patterns are all preserved
#[test]
fn whitebox_all_proc_root_variants_preserved() {
    // All magic symlink patterns that should be preserved
    let magic_patterns = [
        "/proc/self/root",
        "/proc/thread-self/root",
        // Note: We can't test /proc/1/root without root privileges
    ];

    // Also test with actual PID
    let pid = get_self_pid();
    let pid_pattern = format!("/proc/{}/root", pid);

    let mut all_patterns: Vec<&str> = magic_patterns.to_vec();
    let pid_pattern_ref: &str = &pid_pattern;
    all_patterns.push(pid_pattern_ref);

    for pattern in all_patterns {
        if !Path::new(pattern).exists() {
            continue;
        }

        match PathBoundary::<()>::try_new(pattern) {
            Ok(boundary) => {
                let boundary_path = boundary.interop_path();
                let boundary_str = boundary_path.to_string_lossy();

                // Extract the expected prefix (everything up to and including "root")
                // Pattern: /proc/{something}/root
                assert!(
                    boundary_str.starts_with("/proc/"),
                    "Boundary for '{}' doesn't start with /proc/: {}",
                    pattern,
                    boundary_str
                );
                assert!(
                    boundary_str.contains("/root"),
                    "Boundary for '{}' doesn't contain /root: {}",
                    pattern,
                    boundary_str
                );
                assert_ne!(
                    boundary_str, "/",
                    "SECURITY FAILURE: '{}' was resolved to /",
                    pattern
                );
            }
            Err(e) => {
                eprintln!("Pattern '{}' not accessible: {:?}", pattern, e);
            }
        }
    }
}

/// White-box test: Verify /proc/PID/cwd patterns are also preserved
#[test]
fn whitebox_proc_cwd_patterns_preserved() {
    let cwd_patterns = ["/proc/self/cwd", "/proc/thread-self/cwd"];

    let pid = get_self_pid();
    let pid_cwd = format!("/proc/{}/cwd", pid);

    for pattern in cwd_patterns
        .iter()
        .chain(std::iter::once(&pid_cwd.as_str()))
    {
        let pattern = *pattern;
        if !Path::new(pattern).exists() {
            continue;
        }

        match PathBoundary::<()>::try_new(pattern) {
            Ok(boundary) => {
                let boundary_path = boundary.interop_path();
                let boundary_str = boundary_path.to_string_lossy();

                // The path should preserve the /proc/.../ prefix structure
                // Note: /proc/self/cwd may resolve to the actual CWD path, but the
                // proc-canonicalize fix should preserve the magic symlink prefix
                // when the path IS the magic symlink itself
                assert!(
                    boundary_str.starts_with("/proc/") || boundary_str == pattern,
                    "Boundary for '{}' unexpectedly resolved: {}",
                    pattern,
                    boundary_str
                );
            }
            Err(e) => {
                eprintln!("Pattern '{}' not accessible: {:?}", pattern, e);
            }
        }
    }
}

/// White-box test: Verify symlink resolution inside /proc namespace is handled correctly
#[test]
fn whitebox_symlink_inside_proc_namespace() {
    // Create a temp directory to simulate container filesystem
    let temp = tempfile::tempdir().unwrap();
    let container_root = temp.path();

    // Create a symlink inside the "container" that points to a valid internal path
    let etc_dir = container_root.join("etc");
    let var_dir = container_root.join("var");
    fs::create_dir_all(&etc_dir).unwrap();
    fs::create_dir_all(&var_dir).unwrap();

    // Create /etc/passwd inside container
    fs::write(etc_dir.join("passwd"), "root:x:0:0::/root:/bin/bash").unwrap();

    // Create a symlink /var/log -> /etc (valid inside container)
    let log_link = var_dir.join("log");
    std::os::unix::fs::symlink(&etc_dir, &log_link).unwrap();

    // Now create a boundary and test symlink following
    let boundary: PathBoundary = PathBoundary::try_new(container_root).unwrap();

    // Following the symlink should stay within the boundary
    match boundary.strict_join("var/log/passwd") {
        Ok(path) => {
            assert!(
                path.strictpath_starts_with(boundary.interop_path()),
                "Symlink escape: {} is outside boundary",
                path.strictpath_to_string_lossy()
            );
        }
        Err(e) => {
            // Symlink resolution may fail if target doesn't exist correctly
            eprintln!("Symlink test: {:?}", e);
        }
    }
}

/// White-box test: Verify that deeply nested /proc paths don't lose context
#[test]
fn whitebox_nested_proc_paths_preserve_context() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Test deeply nested paths within the namespace
        let nested_paths = [
            "usr/local/bin",
            "home/user/.config",
            "var/lib/dpkg/status",
            "etc/apt/sources.list.d",
        ];

        for nested_input in nested_paths {
            match boundary.strict_join(nested_input) {
                Ok(path) => {
                    let path_str = path.strictpath_to_string_lossy();
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "Nested path '{}' lost namespace context: {}",
                        nested_input,
                        path_str
                    );
                }
                Err(_) => {
                    // Path doesn't exist - acceptable
                }
            }
        }
    }
}

// =============================================================================
// CVE RESISTANCE TESTS
// Tests against known container escape CVE patterns
// =============================================================================

/// CVE resistance test: Symlink-based container escape patterns
/// Similar to CVE-2019-5736 (runc container escape via /proc/self/exe)
#[test]
fn cve_resistance_runc_style_proc_self_escape() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Attack patterns inspired by runc CVE-2019-5736
        let attack_patterns = [
            "../proc/self/exe",       // Escape via /proc/self/exe
            "../../proc/self/fd/0",   // Escape via file descriptors
            "../../../proc/1/root",   // Escape to init's root
            "../../../../proc/1/cwd", // Escape to init's cwd
        ];

        for attack_input in attack_patterns {
            let result = boundary.strict_join(attack_input);
            match result {
                Err(StrictPathError::PathEscapesBoundary { .. }) => {
                    // Expected: escape attempt rejected
                }
                Err(StrictPathError::PathResolutionError { .. }) => {
                    // Also acceptable: path doesn't exist
                }
                Ok(path) => {
                    // If somehow accepted, verify containment
                    let path_str = path.strictpath_to_string_lossy();
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "CVE-2019-5736 style escape succeeded: '{}' -> '{}'",
                        attack_input,
                        path_str
                    );
                }
                Err(e) => {
                    // Other errors are acceptable
                    eprintln!("Pattern '{}': {:?}", attack_input, e);
                }
            }
        }
    }
}

/// CVE resistance test: Docker/Podman escape via /proc paths
/// Related to container escape vulnerabilities in container runtimes
#[test]
fn cve_resistance_container_runtime_escape_patterns() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Patterns used in various container escape attempts
        let escape_patterns = [
            // Break out of overlay filesystem
            "../../../host/etc/passwd",
            // Access docker socket
            "../../../var/run/docker.sock",
            // Access kubelet credentials
            "../../../var/lib/kubelet/pods",
            // Access host's /proc
            "../proc",
            "../../../proc/1/ns/mnt",
        ];

        for attack_input in escape_patterns {
            let result = boundary.strict_join(attack_input);
            match result {
                Err(StrictPathError::PathEscapesBoundary { .. }) => {
                    // Expected: container escape rejected
                }
                Err(_) => {
                    // Other errors acceptable
                }
                Ok(path) => {
                    // Verify containment if accepted
                    let path_str = path.strictpath_to_string_lossy();
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "Container escape pattern '{}' succeeded: {}",
                        attack_input,
                        path_str
                    );
                }
            }
        }
    }
}

/// CVE resistance test: Namespace confusion attacks
/// Attacker tries to confuse the namespace boundary detection
#[test]
fn cve_resistance_namespace_confusion_attacks() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Tricky patterns that might confuse namespace detection
        let confusion_patterns = [
            "proc/self/root",         // Without leading slash
            "./proc/self/root",       // Relative form
            "proc/../etc/passwd",     // Inject proc in path
            "./../../../proc/1/root", // Mixed relative + absolute
        ];

        for attack_input in confusion_patterns {
            let result = boundary.strict_join(attack_input);
            match result {
                Ok(path) => {
                    let path_str = path.strictpath_to_string_lossy();
                    // Must stay within namespace boundary
                    assert!(
                        path_str.starts_with("/proc/self/root"),
                        "Namespace confusion attack '{}' escaped: {}",
                        attack_input,
                        path_str
                    );
                }
                Err(_) => {
                    // Rejection is acceptable
                }
            }
        }
    }
}

// =============================================================================
// PATHBOUNDARY CONTAINER BOUNDARY TESTS
// =============================================================================

/// PathBoundary test: Creating boundary at /proc/self/root maintains isolation
#[test]
fn pathboundary_proc_root_maintains_isolation() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // The boundary should be exactly at /proc/self/root
        let boundary_path_str = boundary.interop_path().to_string_lossy().to_string();

        // Not just "/", must preserve namespace
        assert!(
            boundary_path_str.starts_with("/proc/self/root"),
            "PathBoundary lost namespace context: {}",
            boundary_path_str
        );

        // Any path operation must stay within this boundary
        if let Ok(etc_path) = boundary.strict_join("etc") {
            assert!(
                etc_path.strictpath_starts_with(boundary.interop_path()),
                "Path escaped PathBoundary"
            );
        }
    }
}

/// PathBoundary test: Strict join with traversal is rejected
#[test]
fn pathboundary_strict_join_rejects_traversal() {
    let proc_self_root = get_proc_self_root();

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Traversal must be rejected
        let result = boundary.strict_join("../../../etc/passwd");

        match result {
            Err(StrictPathError::PathEscapesBoundary { .. }) => {
                // Correct behavior
            }
            Ok(path) => {
                // If somehow accepted (e.g., path doesn't exist), verify containment
                let path_str = path.strictpath_to_string_lossy();
                assert!(
                    path_str.starts_with("/proc/self/root"),
                    "Traversal escaped boundary: {}",
                    path_str
                );
            }
            Err(_) => {
                // Other errors acceptable
            }
        }
    }
}

// =============================================================================
// VIRTUALROOT CONTAINER BOUNDARY TESTS
// =============================================================================

#[cfg(feature = "virtual-path")]
mod virtual_path_tests {
    use super::*;

    /// VirtualRoot test: Creating virtual root at /proc/self/root
    #[test]
    fn virtualroot_proc_root_maintains_isolation() {
        let proc_self_root = get_proc_self_root();

        if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
            let vroot_path_str = vroot.interop_path().to_string_lossy().to_string();

            // Must preserve namespace
            assert!(
                vroot_path_str.starts_with("/proc/self/root"),
                "VirtualRoot lost namespace context: {}",
                vroot_path_str
            );
        }
    }

    /// VirtualRoot test: Virtual join clamps traversal within namespace
    #[test]
    fn virtualroot_virtual_join_clamps_to_namespace() {
        let proc_self_root = get_proc_self_root();

        if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
            // Virtual join clamps traversal
            match vroot.virtual_join("../../../etc/passwd") {
                Ok(vpath) => {
                    // Virtual path must stay within the /proc/self/root namespace
                    let system_path = vpath.as_unvirtual().strictpath_to_string_lossy();
                    assert!(
                        system_path.starts_with("/proc/self/root"),
                        "VirtualPath escaped namespace: {}",
                        system_path
                    );

                    // Virtual display should show clamped path
                    let virtual_display = vpath.virtualpath_display().to_string();
                    assert!(
                        virtual_display.starts_with('/'),
                        "Virtual display must be rooted: {}",
                        virtual_display
                    );
                }
                Err(e) => {
                    eprintln!("Virtual join error (acceptable): {:?}", e);
                }
            }
        }
    }

    /// VirtualRoot test: Virtual path display is isolated from host
    #[test]
    fn virtualroot_display_is_isolated() {
        let proc_self_root = get_proc_self_root();

        if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
            if let Ok(vpath) = vroot.virtual_join("etc/passwd") {
                // Virtual display should show /etc/passwd (virtual view)
                let display = vpath.virtualpath_display().to_string();
                assert!(display.starts_with('/'));

                // Should NOT leak the real host path
                assert!(
                    !display.contains("/proc/self/root"),
                    "Virtual display leaked namespace path: {}",
                    display
                );
            }
        }
    }

    /// VirtualRoot test: Absolute inputs clamp to virtual namespace
    #[test]
    fn virtualroot_absolute_input_clamped_to_namespace() {
        let proc_self_root = get_proc_self_root();

        if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
            // Absolute path input should be clamped to the virtual root
            match vroot.virtual_join("/etc/shadow") {
                Ok(vpath) => {
                    let system_path = vpath.as_unvirtual().strictpath_to_string_lossy();
                    assert!(
                        system_path.starts_with("/proc/self/root"),
                        "Absolute input escaped namespace: {}",
                        system_path
                    );
                }
                Err(e) => {
                    eprintln!("Absolute input clamping error (acceptable): {:?}", e);
                }
            }
        }
    }
}

// =============================================================================
// REGRESSION TESTS
// Ensure normal path operations still work correctly
// =============================================================================

/// Regression test: Normal paths (not /proc) still work as expected
#[test]
fn regression_normal_paths_unaffected() {
    let temp = tempfile::tempdir().unwrap();
    let normal_boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Normal operations should work
    let subdir = normal_boundary.strict_join("subdir").unwrap();
    subdir.create_dir().unwrap();

    let file = normal_boundary.strict_join("subdir/file.txt").unwrap();
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

    let boundary: PathBoundary = PathBoundary::try_new(base).unwrap();

    // Following symlink within boundary should work
    match boundary.strict_join("config/data_link/file.txt") {
        Ok(path) => {
            assert!(path.strictpath_starts_with(boundary.interop_path()));
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

    let jail_dir = base.join("jail");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&jail_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(outside_dir.join("secret.txt"), "secret").unwrap();

    // Create symlink inside jail pointing outside
    let escape_link = jail_dir.join("escape");
    std::os::unix::fs::symlink(&outside_dir, &escape_link).unwrap();

    let boundary: PathBoundary = PathBoundary::try_new(&jail_dir).unwrap();

    // Following symlink to escape should be rejected
    let result = boundary.strict_join("escape/secret.txt");
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

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Attempt to traverse up from root (within the namespace)
        match boundary.strict_join("..") {
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

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        let tricky_patterns = [
            "etc//passwd",  // Double slash
            "etc/./passwd", // Current dir
            "./etc/passwd", // Leading current dir
            "etc/",         // Trailing slash
        ];

        for pattern in tricky_patterns {
            if let Ok(path) = boundary.strict_join(pattern) {
                assert!(
                    path.strictpath_starts_with(boundary.interop_path()),
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

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        // Create a very long path
        let long_component = "a".repeat(64);
        let long_path = format!(
            "{}/{}/{}/{}",
            long_component, long_component, long_component, long_component
        );

        match boundary.strict_join(&long_path) {
            Ok(path) => {
                assert!(
                    path.strictpath_starts_with(boundary.interop_path()),
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

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        let unicode_patterns = [
            "文件/测试.txt",
            "файл/тест.txt",
            "αρχείο/δοκιμή.txt",
            "ファイル/テスト.txt",
        ];

        for pattern in unicode_patterns {
            if let Ok(path) = boundary.strict_join(pattern) {
                assert!(
                    path.strictpath_starts_with(boundary.interop_path()),
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
    let boundary1 = PathBoundary::<()>::try_new(&proc_self_root);
    let boundary2 = PathBoundary::<()>::try_new(&proc_pid_root);

    if let (Ok(b1), Ok(b2)) = (boundary1, boundary2) {
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

    if let Ok(boundary) = PathBoundary::<()>::try_new(&proc_self_root) {
        let boundary_str = boundary.interop_path().to_string_lossy().to_string();

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
