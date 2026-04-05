// I/O security tests: append(), write(), create_file(), open_file(), read() through
// symlinks/junctions that escape the boundary, plus circular/recursive symlink tests.

#[cfg(all(feature = "virtual-path", unix))]
use crate::VirtualRoot;
#[cfg(all(
    feature = "virtual-path",
    any(unix, all(windows, feature = "junctions"))
))]
use crate::{PathBoundary, StrictPathError};

// ============================================================
// I/O Security Tests for append(), write(), create_file(), open_file()
// ============================================================

/// Security test: append() through a symlink pointing outside boundary should be blocked.
/// The symlink resolution during strict_join must detect the escape.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_append_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file that attacker wants to modify
    let outside_file = outside_dir.join("sensitive.log");
    std::fs::write(&outside_file, "original content\n").unwrap();

    // Create symlink inside boundary pointing to outside file
    let link_inside = restriction_dir.join("log.txt");
    unixfs::symlink(&outside_file, &link_inside).unwrap();

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path containing the symlink - should detect escape
    let result = restricted_dir.strict_join("log.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected during join
        }
        Ok(strict_path) => {
            // If join succeeded (shouldn't with proper symlink resolution),
            // verify append would still be safe
            let append_result = strict_path.append("malicious log entry\n");
            if append_result.is_ok() {
                let outside_content = std::fs::read_to_string(&outside_file).unwrap();
                assert_eq!(
                    outside_content, "original content\n",
                    "SECURITY FAILURE: append() modified file outside boundary via symlink"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify outside file was not modified
    let final_content = std::fs::read_to_string(&outside_file).unwrap();
    assert_eq!(
        final_content, "original content\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: create_file() through a symlink directory pointing outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_create_file_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create symlink inside boundary pointing to outside directory
    let link_to_outside = restriction_dir.join("escape_dir");
    unixfs::symlink(&outside_dir, &link_to_outside).unwrap();

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path through the symlink
    let result = restricted_dir.strict_join("escape_dir/new_file.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, create_file should still be safe
            let create_result = strict_path.create_file();
            if create_result.is_ok() {
                assert!(
                    !outside_dir.join("new_file.txt").exists(),
                    "SECURITY FAILURE: create_file() created file outside boundary"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify no file was created outside
    assert!(
        !outside_dir.join("new_file.txt").exists(),
        "No file should be created outside boundary"
    );
}

/// Security test: open_file() through a symlink pointing to sensitive file outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_open_file_through_symlink_escape_is_blocked() {
    use std::io::Read;
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create sensitive file outside boundary
    let sensitive_file = outside_dir.join("secrets.txt");
    std::fs::write(&sensitive_file, "API_KEY=supersecret123").unwrap();

    // Create symlink inside boundary pointing to sensitive file
    let link_inside = restriction_dir.join("config.txt");
    unixfs::symlink(&sensitive_file, &link_inside).unwrap();

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path to the symlink
    let result = restricted_dir.strict_join("config.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, open_file should be blocked or return safe content
            match strict_path.open_file() {
                Ok(mut file) => {
                    let mut contents = String::new();
                    let _ = file.read_to_string(&mut contents);
                    assert!(
                        !contents.contains("supersecret123"),
                        "SECURITY FAILURE: open_file() leaked sensitive data via symlink"
                    );
                }
                Err(_) => {
                    // I/O error is acceptable
                }
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }
}

/// Security test: write() through a preexisting malicious symlink should be blocked.
/// This simulates a poisoned filesystem scenario (e.g., after vulnerable archive extraction).
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_write_through_preexisting_malicious_symlink() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create original outside file
    let target_outside = outside_dir.join("important.cfg");
    std::fs::write(&target_outside, "original config\n").unwrap();

    // Simulate poisoned filesystem: symlink already exists inside boundary
    let poison_link = restriction_dir.join("config.cfg");
    unixfs::symlink(&target_outside, &poison_link).unwrap();

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Try to write through the poisoned symlink
    let join_result = restricted_dir.strict_join("config.cfg");

    match join_result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: escape detected via symlink resolution
        }
        Ok(strict_path) => {
            // If join succeeded, write must not affect outside file
            let write_result = strict_path.write("malicious config\n");
            if write_result.is_ok() {
                let outside_content = std::fs::read_to_string(&target_outside).unwrap();
                assert_eq!(
                    outside_content, "original config\n",
                    "SECURITY FAILURE: write() modified file outside boundary via symlink"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Final verification
    let final_content = std::fs::read_to_string(&target_outside).unwrap();
    assert_eq!(
        final_content, "original config\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: VirtualPath append() through symlink escape should be clamped.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_virtual_append_through_symlink_clamps_or_blocks() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let vroot_dir = base.join("vroot");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&vroot_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file
    let outside_log = outside_dir.join("system.log");
    std::fs::write(&outside_log, "system log\n").unwrap();

    // Create symlink inside vroot pointing outside
    let link_inside = vroot_dir.join("user.log");
    unixfs::symlink(&outside_log, &link_inside).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&vroot_dir).unwrap();

    // VirtualPath should either block the symlink escape or clamp it
    match vroot.virtual_join("user.log") {
        Ok(vpath) => {
            // If join succeeded (after clamping), append should not modify outside file
            let _ = vpath.append("user content\n");
            let outside_content = std::fs::read_to_string(&outside_log).unwrap();
            assert_eq!(
                outside_content, "system log\n",
                "VirtualPath must not allow writes outside virtual root"
            );
        }
        Err(_) => {
            // Rejection is also acceptable
        }
    }
}

/// Security test for Windows: append() through junction pointing outside should be blocked.
#[cfg(feature = "virtual-path")]
#[cfg(feature = "junctions")]
#[test]
#[cfg(windows)]
fn test_append_through_junction_escape_is_blocked() {
    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create outside file that attacker wants to modify
    let outside_file = outside_dir.join("sensitive.log");
    std::fs::write(&outside_file, "original content\n").unwrap();

    // Create junction inside boundary pointing to outside directory
    let junction_inside = restriction_dir.join("escape");
    junction::create(&outside_dir, &junction_inside).expect("junction creation");

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path through the junction
    let result = restricted_dir.strict_join("escape/sensitive.log");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: junction escape detected during join
        }
        Ok(strict_path) => {
            // If join succeeded, verify append would still be safe
            let append_result = strict_path.append("malicious log entry\n");
            if append_result.is_ok() {
                let outside_content = std::fs::read_to_string(&outside_file).unwrap();
                assert_eq!(
                    outside_content, "original content\n",
                    "SECURITY FAILURE: append() modified file outside boundary via junction"
                );
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }

    // Verify outside file was not modified
    let final_content = std::fs::read_to_string(&outside_file).unwrap();
    assert_eq!(
        final_content, "original content\n",
        "Outside file must remain unmodified"
    );
}

/// Security test: read() through symlink pointing to sensitive file outside should be blocked.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_read_through_symlink_escape_is_blocked() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // Create sensitive file outside boundary
    let sensitive_file = outside_dir.join("passwd");
    std::fs::write(&sensitive_file, "root:x:0:0:root:/root:/bin/bash").unwrap();

    // Create symlink inside boundary pointing to sensitive file
    let link_inside = restriction_dir.join("data.txt");
    unixfs::symlink(&sensitive_file, &link_inside).unwrap();

    let restricted_dir: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    // Attempt to join path to the symlink
    let result = restricted_dir.strict_join("data.txt");

    match result {
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: symlink escape detected
        }
        Ok(strict_path) => {
            // If join succeeded, read must not leak sensitive data
            match strict_path.read_to_string() {
                Ok(contents) => {
                    assert!(
                        !contents.contains("root:x:0:0"),
                        "SECURITY FAILURE: read() leaked sensitive data via symlink"
                    );
                }
                Err(_) => {
                    // I/O error is acceptable
                }
            }
        }
        Err(other) => panic!("Unexpected error: {other:?}"),
    }
}

// ============================================================
// Circular/Recursive Symlink Tests
// ============================================================

/// Security test: circular symlinks (a → b → a) must produce a clean error,
/// not hang, crash, or cause stack overflow during canonicalization.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_circular_symlink_produces_clean_error() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("boundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();

    // Create circular symlinks: link_a → link_b, link_b → link_a
    let link_a = restriction_dir.join("link_a");
    let link_b = restriction_dir.join("link_b");
    unixfs::symlink(&link_b, &link_a).unwrap();
    unixfs::symlink(&link_a, &link_b).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();
    let vroot: VirtualRoot<()> = VirtualRoot::try_new(&restriction_dir).unwrap();

    // StrictPath must produce a clean error (PathResolutionError or PathEscapesBoundary)
    match restriction.strict_join("link_a") {
        Err(StrictPathError::PathResolutionError { .. })
        | Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: circular symlink detected and rejected cleanly
        }
        Ok(_) => panic!("Circular symlink must not succeed silently"),
        Err(other) => panic!("Unexpected error for circular symlink: {other:?}"),
    }

    // VirtualPath must also handle gracefully: either reject cleanly or clamp
    // within the boundary. On some platforms (e.g., macOS) virtual_join may
    // succeed by clamping the unresolvable symlink to the root — that is
    // acceptable VirtualPath behavior as long as containment holds.
    match vroot.virtual_join("link_a") {
        Err(StrictPathError::PathResolutionError { .. })
        | Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected on some platforms: circular symlink rejected cleanly
        }
        Ok(vpath) => {
            // Acceptable: VirtualPath clamped the result within the boundary
            assert!(
                vpath
                    .as_unvirtual()
                    .strictpath_starts_with(vroot.interop_path()),
                "Circular symlink must remain within boundary if accepted"
            );
        }
        Err(other) => panic!("Unexpected virtual error for circular symlink: {other:?}"),
    }
}

/// Security test: self-referencing symlink (a → a) must produce a clean error.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_self_referencing_symlink_produces_clean_error() {
    use std::os::unix::fs as unixfs;

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("boundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();

    // Create self-referencing symlink: loop → loop
    let self_link = restriction_dir.join("loop");
    unixfs::symlink(&self_link, &self_link).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();

    match restriction.strict_join("loop") {
        Err(StrictPathError::PathResolutionError { .. })
        | Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Expected: self-referencing symlink rejected cleanly
        }
        Ok(_) => panic!("Self-referencing symlink must not succeed silently"),
        Err(other) => panic!("Unexpected error for self-link: {other:?}"),
    }
}

/// Security test (Windows): circular junctions must produce a clean error.
#[cfg(feature = "virtual-path")]
#[cfg(feature = "junctions")]
#[test]
#[cfg(windows)]
fn test_circular_junction_produces_clean_error() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("boundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();

    // Create two directories and then create junctions that point to each other
    let dir_a = restriction_dir.join("dir_a");
    let dir_b = restriction_dir.join("dir_b");

    // First create dir_b as real dir, then dir_a as junction to dir_b
    std::fs::create_dir_all(&dir_b).unwrap();
    match junction::create(&dir_b, &dir_a) {
        Ok(_) => {
            // Now replace dir_b with junction to dir_a (removing real dir_b first)
            std::fs::remove_dir_all(&dir_b).ok();
            match junction::create(&dir_a, &dir_b) {
                Ok(_) => {
                    // Both junctions created; test traversal through them
                    let restriction: PathBoundary =
                        PathBoundary::try_new(&restriction_dir).unwrap();

                    match restriction.strict_join("dir_a/subfile.txt") {
                        Err(StrictPathError::PathResolutionError { .. })
                        | Err(StrictPathError::PathEscapesBoundary { .. }) => {
                            // Expected: circular junction produces clean error
                        }
                        Ok(_) => {
                            // May succeed if OS resolves junctions without looping;
                            // the key guarantee is no hang/crash
                        }
                        Err(other) => {
                            panic!("Unexpected error for circular junction: {other:?}")
                        }
                    }
                }
                Err(junction_err) => {
                    eprintln!("Note: Could not create second circular junction: {junction_err}; skipping test");
                }
            }
        }
        Err(junction_err) => {
            eprintln!(
                "Note: Could not create first circular junction: {junction_err}; skipping test"
            );
        }
    }
}
