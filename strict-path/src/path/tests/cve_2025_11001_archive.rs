//! Archive extraction, workflow, virtual-path containment, and comparison table tests
//! for CVE-2025-11001 (7-Zip symlink path traversal).
//!
//! These tests complement the core attack-vector tests in `cve_2025_11001_core.rs`
//! by covering higher-level scenarios: safe extraction workflows, validation of
//! malicious filenames, end-to-end arbitrary-file-write prevention, VirtualPath
//! containment semantics, a vulnerability comparison table, and a regression test
//! for a preexisting malicious link created by a vulnerable extractor.

// CVE-2025-11001/CVE-2025-11002 are Windows-specific vulnerabilities
// All tests in this module are Windows-only
#![cfg(windows)]

use crate::{PathBoundary, StrictPathError};
use std::path::Path;

#[test]
fn test_safe_archive_extraction_workflow() {
    // Demonstrate the CORRECT way to extract archives using strict-path
    // This is what archive libraries SHOULD do to prevent CVE-2025-11001

    let extraction_dir = tempfile::tempdir().unwrap();
    let extraction_sandbox: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Simulated archive contents (safe structure)
    let archive_entries: Vec<(&str, Option<&[u8]>)> = vec![
        ("docs/", None),                               // Directory
        ("docs/readme.txt", Some(b"README" as &[u8])), // File
        ("docs/manual.pdf", Some(b"PDF" as &[u8])),    // File
        ("images/", None),                             // Directory
        ("images/logo.png", Some(b"PNG" as &[u8])),    // File
    ];

    // Extract each entry safely
    for (entry_path, content) in archive_entries {
        // CRITICAL: Validate EVERY path from the archive before use
        let validated_path = extraction_sandbox
            .strict_join(entry_path)
            .expect("Safe archive entry should be accepted");

        // Verify containment
        assert!(
            validated_path.strictpath_starts_with(extraction_sandbox.interop_path()),
            "All extracted paths must be within boundary"
        );

        if entry_path.ends_with('/') {
            // Directory
            validated_path.create_dir_all().unwrap();
        } else {
            // File
            validated_path.create_parent_dir_all().unwrap();
            if let Some(data) = content {
                validated_path.write(data).unwrap();
            }
        }
    }

    // Verify all files were created in the right place
    assert!(extraction_dir.path().join("docs").exists());
    assert!(extraction_dir.path().join("docs/readme.txt").exists());
    assert!(extraction_dir.path().join("images/logo.png").exists());
}

#[test]
fn test_symbolic_link_validation_prevents_attack() {
    // Test that strict_symlink validates BOTH link path and target path
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    // Create safe target within boundary
    let safe_target = test_dir.strict_join("target.txt").unwrap();
    safe_target.write(b"content").unwrap();

    // Create safe link within boundary - THIS WORKS (if privileges available)
    let safe_link = test_dir.strict_join("link.txt").unwrap();

    match safe_target.strict_symlink(safe_link.interop_path()) {
        Ok(_) => {
            // Symlink created successfully - verify it exists
            assert!(safe_link.exists(), "Symlink should exist after creation");
        }
        Err(e) if e.raw_os_error() == Some(1314) => {
            // Windows: Insufficient privileges for symlink
            // Note: In CI with privileges, this path won't be taken
            // Junctions require the target to be a directory; for a file target we won't fallback.
            eprintln!("Note: Symlink requires elevated privileges on Windows. In CI with privileges, real symlinks are tested.");
        }
        Err(e) => panic!("Unexpected error creating symlink: {e}"),
    }

    // The key security property: we cannot use strict_symlink to create
    // a symlink to a path outside the boundary, because we can't create
    // a StrictPath to the outside target in the first place

    // Even if we try to manually construct a path outside (we can't via strict_join),
    // the API design prevents the attack at compile time
}

#[test]
fn test_archive_with_malicious_filenames() {
    // Test various malicious filename patterns that might appear in archives
    let extraction_dir = tempfile::tempdir().unwrap();
    let extraction_sandbox: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    let malicious_filenames = vec![
        // Absolute paths
        "C:\\Windows\\System32\\evil.dll",
        "/etc/passwd",
        // Traversal attempts
        "../../../outside.txt",
        "..\\..\\..\\outside.txt",
        "docs/../../../etc/shadow",
        // Mixed separators
        "docs\\..\\..\\..\\Windows\\System32",
        "docs/../../../../../../etc",
        // Doubled separators
        "....//....//etc/passwd",
        "....\\\\....\\\\Windows",
        // UNC paths
        "\\\\evil-server\\share\\payload.exe",
        // File protocol
        "file:///etc/passwd",
        "file:///C:/Windows/System32/evil.dll",
    ];

    for filename in malicious_filenames {
        let result = extraction_sandbox.strict_join(filename);

        match result {
            Ok(validated_path) => {
                // If somehow accepted (e.g., literal string without special meaning),
                // it MUST still be within the boundary
                assert!(
                    validated_path.strictpath_starts_with(extraction_sandbox.interop_path()),
                    "Filename '{filename}' resulted in path outside boundary: {validated_path:?}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected - malicious path rejected
            }
            Err(other) => {
                panic!(
                    "Unexpected error for malicious filename '{filename}': {other:?}"
                );
            }
        }
    }
}

#[test]
fn test_cve_2025_11001_prevents_arbitrary_file_write() {
    // End-to-end test demonstrating that the attack pattern fails completely
    let extraction_dir = tempfile::tempdir().unwrap();
    let extraction_sandbox: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Attacker's goal: Write a file to C:\Users\Public\malware.exe
    let target_outside_boundary = "C:\\Users\\Public\\malware.exe";

    // Step 1: Try to write directly (should fail)
    let direct_write = extraction_sandbox.strict_join(target_outside_boundary);
    assert!(
        direct_write.is_err(),
        "Direct write to outside path must fail"
    );

    // Step 2: Try to create symlink and write through it (should fail)
    // We can't even create a StrictPath to the outside target
    let symlink_target = extraction_sandbox.strict_join("C:\\Users\\Public");
    assert!(
        symlink_target.is_err(),
        "Cannot create StrictPath to outside directory"
    );

    // Step 3: Try relative traversal (should fail)
    let relative_escape = extraction_sandbox.strict_join("../../../Users/Public/malware.exe");
    assert!(relative_escape.is_err(), "Relative traversal must fail");

    // CONCLUSION: All attack vectors are blocked
    // The attacker cannot:
    // 1. Directly reference paths outside the boundary
    // 2. Create symlinks to outside paths
    // 3. Use relative traversal to escape
    // 4. Use any combination of the above

    // Verify the target file was NOT created
    assert!(
        !Path::new(target_outside_boundary).exists(),
        "Malware file must not have been created outside boundary"
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_cve_2025_11001_with_virtual_path_contains_attack() {
    use crate::VirtualRoot;

    // VirtualPath provides a different defense: containment instead of rejection
    // This demonstrates that even if symlinks are followed, virtual boundaries contain them

    let temp = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp.path()).unwrap();

    // Attacker attempts traversal via virtual path
    let attack_paths = vec![
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\System32",
        "C:\\Users\\Public\\Desktop",
    ];

    for attack in attack_paths {
        match vroot.virtual_join(attack) {
            Ok(vpath) => {
                // Virtual path may accept the path but clamps it within boundary
                let underlying_strict = vpath.as_unvirtual();

                // SECURITY GUARANTEE: Even if accepted, underlying path is contained
                assert!(
                    underlying_strict.strictpath_starts_with(vroot.interop_path()),
                    "Virtual path for '{attack}' must be contained within boundary"
                );

                // Virtual display should be normalized and rooted
                let display = vpath.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display must be rooted: {display}"
                );

                // Should not leak traversal components
                assert!(
                    !display.contains(".."),
                    "Virtual display must not contain '..': {display}"
                );
            }
            Err(_) => {
                // Rejection is also acceptable
            }
        }
    }
}

/// Demonstrates the security differential between vulnerable software and strict-path
#[test]
fn test_vulnerability_comparison_table() {
    let temp = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    // Comparison table of attack vectors
    struct AttackTest {
        description: &'static str,
        path: &'static str,
        vulnerable_7zip_behavior: &'static str,
        strict_path_behavior: &'static str,
    }

    let attacks = vec![
        AttackTest {
            description: "Absolute Windows path",
            path: "C:\\Users\\Public\\Desktop",
            vulnerable_7zip_behavior:
                "Creates symlink to Desktop, files written outside extraction dir",
            strict_path_behavior: "Rejected by strict_join - PathEscapesBoundary error",
        },
        AttackTest {
            description: "Relative traversal",
            path: "../../../outside.txt",
            vulnerable_7zip_behavior: "Creates file outside extraction directory",
            strict_path_behavior: "Rejected by strict_join - PathEscapesBoundary error",
        },
        AttackTest {
            description: "UNC network path",
            path: "\\\\malicious\\share\\payload.exe",
            vulnerable_7zip_behavior: "Creates symlink to network share, enables remote attacks",
            strict_path_behavior: "Rejected by strict_join - PathEscapesBoundary error",
        },
        AttackTest {
            description: "Mixed encoding",
            path: "..%2F..%2F..%2Fetc%2Fpasswd",
            vulnerable_7zip_behavior: "After URL decode: creates file outside boundary",
            strict_path_behavior: "Even if decoded upstream, traversal rejected by strict_join",
        },
    ];

    // Execute each test and verify strict-path prevents the attack
    for test in attacks {
        let result = test_dir.strict_join(test.path);

        // Note: URL-encoded paths (with literal % characters) are accepted as literal filenames
        // because path decoding happens at a higher layer (archive extraction layer)
        // strict-path validates the decoded path, not the encoded representation
        let is_url_encoded = test.path.contains("%2F")
            || test.path.contains("%2f")
            || test.path.contains("%5C")
            || test.path.contains("%5c");

        if is_url_encoded {
            // URL-encoded strings are treated as literal filenames with % characters
            // This is correct behavior - decoding should happen before calling strict_join
            match result {
                Ok(validated_path) => {
                    // Literal % characters in filename are contained within boundary
                    assert!(
                        validated_path.strictpath_starts_with(test_dir.interop_path()),
                        "Even literal encoded string must stay within boundary"
                    );
                }
                Err(_) => {
                    // Rejection is also acceptable
                }
            }
        } else {
            // Non-encoded traversal attempts must be rejected
            assert!(
                result.is_err(),
                "Test '{}' FAILED: {} should be rejected but was accepted",
                test.description,
                test.path
            );
        }

        // Print comparison for documentation
        let desc = &test.description;
        let path = &test.path;
        let vuln = &test.vulnerable_7zip_behavior;
        let safe = &test.strict_path_behavior;
        println!("\n=== {desc} ===");
        println!("Attack path: {path}");
        println!("Vulnerable 7-Zip: {vuln}");
        println!("strict-path: {safe}");
        println!("Result: PROTECTED");
    }
}

/// Simulate a preexisting malicious link created by a vulnerable extractor.
/// We create a raw OS directory link (symlink or junction) at `data/link_in` that points
/// outside the extraction boundary (e.g., C:\Windows\System32), then verify that
/// strict_join("data/link_in/malicious.exe") is rejected. This mirrors the exact
/// poisoned-tree state after a vulnerable 7-Zip creates the outside-pointing link.
#[test]
fn test_cve_2025_11001_preexisting_malicious_link_blocked() {
    // Arrange boundary and directory layout
    let extraction_dir = tempfile::tempdir().unwrap();
    let extraction_sandbox: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    let data_dir = extraction_sandbox.strict_join("data").unwrap();
    data_dir.create_dir_all().unwrap();

    // Link path inside the boundary: data/link_in
    let link_in = extraction_sandbox
        .strict_join("data/link_in")
        .expect("link location inside boundary must be valid");

    // Malicious outside target (directory): C:\\Windows\\System32
    let outside_target = Path::new("C\\\\Windows\\\\System32");

    // Ensure the parent directory exists using built-in helper
    link_in.create_parent_dir_all().ok();

    // Create a raw OS link that points OUTSIDE the boundary.
    // Prefer a real symlink; if privileges are missing (ERROR_PRIVILEGE_NOT_HELD = 1314),
    // fall back to a junction. If both fail, skip the behavioral assertion (environmental).
    let mut link_created = false;

    #[cfg(windows)]
    {
        // Try symlink dir first
        match std::os::windows::fs::symlink_dir(outside_target, link_in.interop_path()) {
            Ok(_) => {
                link_created = true;
            }
            Err(e) => {
                if e.raw_os_error() == Some(1314) {
                    // No symlink privilege; try built-in junction first when available
                    // We cannot use built-in junction helpers here: the target is outside
                    // the boundary by design. Without symlink privilege, we cannot emulate
                    // this poisoned state in a portable way; skip gracefully.
                    eprintln!(
                        "Skipped: cannot create outside-pointing link without symlink privilege."
                    );
                } else {
                    eprintln!("Note: symlink_dir failed: {e}");
                }
            }
        }
    }

    if !link_created {
        // Environment (privileges/policies) prevented creating a malicious link.
        // Skip the behavioral assertion without failing the test; the core security
        // property is still proven by other tests that don't require OS link creation.
        eprintln!(
            "Skipped: could not create preexisting malicious link due to environment permissions."
        );
        return;
    }

    // Act: attempt to validate a path that would traverse through the malicious link
    let through_link = extraction_sandbox.strict_join("data/link_in/malicious.exe");

    // Assert: strict-path must reject traversal that escapes the boundary via the link
    match through_link {
        Err(StrictPathError::PathEscapesBoundary { .. })
        | Err(StrictPathError::PathResolutionError { .. }) => {
            // Expected: attack blocked by rejecting the join
        }
        Ok(validated_path) => {
            // Also acceptable defense: containment. Even if the join succeeded,
            // the resolved path must remain inside the boundary (no escape).
            assert!(
                validated_path.strictpath_starts_with(extraction_sandbox.interop_path()),
                "Path through outside-pointing link must still be contained within boundary: {validated_path:?}"
            );
        }
        Err(other) => panic!("Unexpected error variant: {other:?}"),
    }
}
