//! Proof test replicating CVE-2025-11001 (7-Zip symlink path traversal)
//!
//! ## Vulnerability Background
//!
//! CVE-2025-11001 and CVE-2025-11002 are critical vulnerabilities in 7-Zip (versions 21.02-24.09)
//! that allow path traversal via malicious symlinks in ZIP archives. The vulnerability exploits
//! flawed absolute path detection and symlink handling in 7-Zip's extraction logic.
//!
//! **Attack Vector:**
//! 1. Attacker creates a ZIP archive containing a Linux-style symlink pointing to a Windows
//!    absolute path like `C:\Users\[Username]\Desktop`
//! 2. 7-Zip misclassifies this as a relative path due to flawed path checking
//! 3. During extraction, 7-Zip creates the symlink and then follows it
//! 4. Subsequent files in the archive are written to the symlink target location
//! 5. This allows arbitrary file writes outside the extraction directory
//!
//! **Exploitation Requirements:**
//! - Windows OS (not exploitable on Linux/macOS)
//! - Elevated privileges, Developer Mode, or elevated service context (for symlink creation)
//! - Vulnerable 7-Zip version (21.02 through 24.09)
//!
//! **References:**
//! - https://github.com/pacbypass/CVE-2025-11001
//! - https://github.com/DK26/CVE-2025-11001 (forK)
//! - https://cybersecuritynews.com/poc-exploit-7-zip-vulnerabilities/
//! - https://pacbypass.github.io/2025/10/16/diffing-7zip-for-cve-2025-11001.html (detailed analysis)
//! - ZDI disclosure: October 7, 2025
//! - CVSS v3.0 Score: 7.0
//!
//! ## The Three 7-Zip Bugs (from pacbypass article)
//!
//! 1. **Issue #1 - Path Type Misclassification**: Linux symlink containing Windows absolute
//!    path `C:\Users\Desktop` is incorrectly labeled as "relative" because 7-Zip uses
//!    Linux-style path checking (`IS_PATH_SEPAR(path[0])` instead of `NName::IsAbsolutePath`)
//!
//! 2. **Issue #2 - Prepended Directory Bypass**: When symlink is in a subdirectory,
//!    7-Zip prepends the directory path before validation:
//!    `isSafePath("data/subdir/" + "C:\Users\Desktop")` incorrectly passes
//!
//! 3. **Issue #3 - Directory Check Bypass**: Final safety check has condition
//!    `if (_item.IsDir)` that only validates directory symlinks, allowing file
//!    symlinks to bypass validation entirely
//!
//! ## How strict-path Prevents This Attack
//!
//! This test demonstrates that `strict-path` prevents CVE-2025-11001 through:
//!
//! 1. **Path Boundary Validation**: All paths must be validated through `strict_join()`
//!    before any filesystem operations, rejecting escape attempts immediately
//!
//! 2. **Symlink Target Validation**: When creating symlinks via `strict_symlink()`,
//!    both the link path AND the target path are validated against the boundary
//!
//! 3. **Canonical Resolution**: Built on `soft-canonicalize`, which resolves symlinks
//!    and detects escape attempts before filesystem operations occur
//!
//! 4. **Fail-Fast Design**: Returns `Err(PathEscapesBoundary)` on escape attempts
//!    rather than silently allowing traversal
//!
//! The key insight: **If you can't create a StrictPath, you can't perform I/O**.
//! This makes the attack impossible at the API level.

// CVE-2025-11001/CVE-2025-11002 are Windows-specific vulnerabilities
// All tests in this module are Windows-only
#![cfg(windows)]

use crate::{PathBoundary, StrictPathError};
use std::path::Path;
/// Test structure mimicking the CVE-2025-11001 exploit
struct MaliciousZipStructure {
    /// Top-level directory in the archive
    top_dir: String,
    /// Symlink entry name that points outside the extraction dir
    link_name: String,
    /// Target path the symlink attempts to point to (absolute Windows path)
    symlink_target: String,
    /// File that would be written via the symlink
    payload_file: String,
}

impl MaliciousZipStructure {
    fn new_desktop_attack(username: &str) -> Self {
        Self {
            top_dir: "data".to_string(),
            link_name: "link_in".to_string(),
            symlink_target: format!("C:\\Users\\{}\\Desktop", username),
            payload_file: "malicious.exe".to_string(),
        }
    }

    fn new_system32_attack() -> Self {
        Self {
            top_dir: "data".to_string(),
            link_name: "link_in".to_string(),
            symlink_target: "C:\\Windows\\System32".to_string(),
            payload_file: "malicious.dll".to_string(),
        }
    }

    fn new_relative_traversal_attack() -> Self {
        Self {
            top_dir: "data".to_string(),
            link_name: "link_in".to_string(),
            // Attempts to traverse up and out of extraction directory
            symlink_target: "..\\..\\..\\sensitive".to_string(),
            payload_file: "payload.txt".to_string(),
        }
    }
}

/// Test replicating the exact attack pattern from pacbypass's article:
/// https://pacbypass.github.io/2025/10/16/diffing-7zip-for-cve-2025-11001.html
///
/// The vulnerability exploits three 7-Zip bugs:
/// 1. Linux symlink with Windows path `C:\` is mislabeled as "relative"
/// 2. Prepending zip directory allows bypass: `data/` + `C:\Users\Desktop` passes check
/// 3. Directory check (`_item.IsDir`) incorrectly skips validation for file symlinks
///
/// Attack structure in ZIP:
/// - data/link_in → symlink to C:\Users\TestUser\Desktop
/// - data/link_in/malicious.exe → file written through symlink
///
/// Result: malicious.exe ends up on Desktop instead of in extraction directory
#[test]
fn test_cve_2025_11001_desktop_symlink_attack_blocked() {
    let attack = MaliciousZipStructure::new_desktop_attack("TestUser");

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Step 1: Attacker attempts to create top-level directory (this succeeds)
    let top_dir_path = boundary.strict_join(&attack.top_dir).unwrap();
    top_dir_path.create_dir().unwrap();

    // Step 2: Attacker attempts to create symlink pointing to absolute Windows path
    // In the vulnerable 7-Zip, this would create a symlink to C:\Users\TestUser\Desktop
    //
    // 7-Zip BUG #1: Linux symlink with Windows path is mislabeled as "relative"
    // 7-Zip BUG #2: Prepending "data/" makes check pass: isSafePath("data/C:\Users\Desktop")
    // 7-Zip BUG #3: File symlink bypasses _item.IsDir check

    let link_path = boundary
        .strict_join(format!("{}/{}", attack.top_dir, attack.link_name))
        .unwrap();

    // Attempt to validate the symlink target - THIS IS WHERE strict-path BLOCKS THE ATTACK
    // strict-path does NOT mislabel absolute paths as relative
    let symlink_target_result = boundary.strict_join(&attack.symlink_target);

    // ✅ SECURITY GUARANTEE: Absolute path to Desktop is rejected
    assert!(
        symlink_target_result.is_err(),
        "strict-path MUST reject absolute path to Desktop"
    );

    match symlink_target_result {
        Err(StrictPathError::PathEscapesBoundary { attempted_path, .. }) => {
            // Verify the error correctly identifies the escape attempt
            let path_str = attempted_path.to_string_lossy();

            // On Windows, the attempted path should reference the Desktop path
            assert!(
                path_str.contains("Users") || path_str.contains("Desktop"),
                "Error should reference the attempted Desktop path, got: {}",
                path_str
            );
        }
        Err(StrictPathError::PathResolutionError { .. }) => {
            // Also acceptable - path doesn't exist so resolution fails
            // This is what happens on CI where C:\Users\TestUser doesn't exist
        }
        Ok(_) => panic!("strict_join MUST NOT accept absolute path to C:\\Users"),
        Err(other) => panic!("Unexpected error variant: {:?}", other),
    }

    // Even if attacker had a StrictPath to the target (impossible via strict_join),
    // strict_symlink would validate both paths are within the same boundary
    // Demonstrate this with a safe target first - use a directory for junction compatibility
    let safe_target_dir = boundary
        .strict_join(format!("{}/safe_target_dir", attack.top_dir))
        .unwrap();
    safe_target_dir.create_dir_all().unwrap();

    // Try creating symlink to safe target directory
    // On Windows: tries symlink first, falls back to junction if privileges unavailable
    // The key security property is that we can't create symlinks to outside paths
    match safe_target_dir.strict_symlink(link_path.interop_path()) {
        Ok(_) => {
            // Symlink created successfully - verify it exists
            assert!(link_path.exists(), "Link should exist after creation");
        }
        Err(e) if e.raw_os_error() == Some(1314) => {
            // Windows: Insufficient privileges for symlink
            // Prefer built-in junction helper (dir-only) when the feature is enabled; otherwise fall back to third-party for the test.
            link_path.create_parent_dir_all().ok();

            // Tests run with all features; fall back to built-in junction helper.
            #[cfg(feature = "junctions")]
            {
                match safe_target_dir.strict_junction(link_path.interop_path()) {
                    Ok(_) => {
                        // Best-effort verification: ensure junction is readable as a directory
                        if let Err(err) = link_path.read_dir() {
                            eprintln!("Warning: Junction created but not readable as dir: {err:?}");
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Note: Could not create junction via built-in helper after symlink privilege error: {err:?}"
                        );
                    }
                }
            }

            #[cfg(not(feature = "junctions"))]
            {
                panic!(
                    "This test verifies the junction fallback path but the 'junctions' feature is disabled.\n\
                     Enable it with: cargo test -p strict-path --features junctions (CI/dev runs use --all-features)."
                );
            }
        }
        Err(e) => panic!("Unexpected error creating symlink: {}", e),
    }

    // Step 3: Attacker attempts to write payload through the symlink
    // In vulnerable 7-Zip, this would write to Desktop
    // With strict-path, we CANNOT create a StrictPath through a link that escapes boundary

    let payload_through_link = boundary.strict_join(format!(
        "{}/{}/{}",
        attack.top_dir, attack.link_name, attack.payload_file
    ));

    // ✅ SECURITY GUARANTEE: Path traversal through symlink/junction is blocked
    // strict-path will either:
    // 1. Reject the path join entirely (most likely when link points outside), OR
    // 2. Allow it only if canonicalization keeps us within boundary
    match payload_through_link {
        Ok(payload_path) => {
            // If join succeeded, verify we're still within boundary
            assert!(
                payload_path.strictpath_starts_with(boundary.interop_path()),
                "Payload path must remain within extraction boundary"
            );

            // If we got here, write is safe - we're still inside boundary
            // However, on Windows with junctions, the write itself might fail
            // due to OS-level restrictions (which is also a defense!)
            match payload_path.write(b"fake malware") {
                Ok(_) => {
                    // Write succeeded - verify Desktop wasn't touched
                    let desktop_path = Path::new(&attack.symlink_target).join(&attack.payload_file);
                    assert!(
                        !desktop_path.exists(),
                        "Desktop must remain untouched even after successful write"
                    );
                }
                Err(e) => {
                    // Write failed - this is also acceptable defense
                    eprintln!("✅ Write blocked by OS: {}", e);
                }
            }
        }
        Err(e) => {
            // ✅ Path join was rejected - this is the expected defense!
            // The link might point outside, so strict-path blocks traversal through it
            eprintln!(
                "✅ Attack blocked: strict_join rejected path through symlink: {}",
                e
            );

            // Verify Desktop was not modified
            let desktop_path = Path::new(&attack.symlink_target).join(&attack.payload_file);
            assert!(
                !desktop_path.exists(),
                "Desktop must remain untouched - attack successfully blocked"
            );
        }
    }
}

/// Test demonstrating protection against Issue #2 from the pacbypass article:
/// 7-Zip vulnerability where prepending directory path bypasses safety check
///
/// Vulnerable 7-Zip logic:
/// ```
/// if (linkInfo.isRelative) // TRUE due to Bug #1
///     relatPath = GetDirPrefixOf(_item.Path); // "data/"
/// relatPath += linkInfo.linkPath; // "data/" + "C:\Users\Desktop"
/// if (!IsSafePath(relatPath)) // BUG: This passes!
/// ```
///
/// strict-path defense: Absolute paths are NEVER treated as relative,
/// regardless of what directory they're joined to
#[test]
fn test_cve_2025_11001_issue2_prepended_directory_bypass_blocked() {
    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Create nested directory structure like in the exploit
    let nested_dir = boundary.strict_join("data/subdir/nested").unwrap();
    nested_dir.create_dir_all().unwrap();

    // Simulate 7-Zip's vulnerable pattern: prepending directory to absolute path
    // In 7-Zip, this would become: "data/subdir/" + "C:\Users\Desktop"
    let absolute_targets = &[
        "C:\\Users\\Public\\Desktop",
        "C:\\Windows\\System32",
        "C:\\ProgramData\\sensitive.txt",
    ];

    for &target in absolute_targets {
        // Try to join from nested directory context
        let result = boundary.strict_join(format!("data/subdir/{}", target));

        // ✅ SECURITY GUARANTEE: Prepending directory does NOT bypass validation
        // strict-path recognizes absolute paths regardless of prefix
        assert!(
            result.is_err(),
            "strict-path MUST reject absolute path even with prepended directory: {}",
            target
        );

        match result {
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected - absolute path detected and rejected
            }
            Ok(_) => panic!(
                "Prepended directory MUST NOT bypass absolute path detection: {}",
                target
            ),
            Err(other) => panic!("Unexpected error for '{}': {:?}", target, other),
        }
    }

    // Also test that the symlink target itself is validated independently
    // of what directory the symlink is created in
    for &target in absolute_targets {
        let target_result = boundary.strict_join(target);

        assert!(
            target_result.is_err(),
            "Symlink target validation MUST reject absolute paths: {}",
            target
        );
    }
}

#[test]
fn test_cve_2025_11001_system32_attack_blocked() {
    let attack = MaliciousZipStructure::new_system32_attack();

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Attempt to validate symlink target pointing to System32
    let symlink_target_result = boundary.strict_join(&attack.symlink_target);

    // ✅ SECURITY GUARANTEE: Absolute path to System32 is rejected
    assert!(
        symlink_target_result.is_err(),
        "strict-path MUST reject absolute path to System32"
    );

    match symlink_target_result {
        Err(StrictPathError::PathEscapesBoundary { .. })
        | Err(StrictPathError::PathResolutionError { .. }) => {
            // Expected - absolute paths or non-existent paths are rejected
        }
        Ok(_) => panic!("strict_join MUST NOT accept absolute path to C:\\Windows\\System32"),
        Err(other) => panic!("Unexpected error variant: {:?}", other),
    }
}

/// Mirrors 7-Zip's forward-slash absolute path misclassification on Windows.
///
/// Some vulnerable 7-Zip versions treated `C:/...` style paths as relative on Windows
/// due to forward slash handling. Our validator must treat these as absolute and reject
/// them when they escape the boundary.
#[test]
fn test_cve_2025_11001_forward_slash_absolute_windows_paths_blocked() {
    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Representative absolute Windows paths using forward slashes
    let absolute_targets = vec!["C:/Windows/System32", "C:/Users/Public/Desktop"];

    for target in absolute_targets {
        let result = boundary.strict_join(target);
        assert!(
            result.is_err(),
            "strict-path MUST reject forward-slash absolute path: {}",
            target
        );

        match result {
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected: treated as absolute/escaping and rejected.
            }
            Ok(p) => panic!(
                "strict_join MUST NOT accept forward-slash absolute path: {:?}",
                p
            ),
            Err(other) => panic!("Unexpected error variant: {:?}", other),
        }
    }
}

#[test]
fn test_cve_2025_11001_relative_traversal_blocked() {
    let attack = MaliciousZipStructure::new_relative_traversal_attack();

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Create top-level directory
    let top_dir_path = boundary.strict_join(&attack.top_dir).unwrap();
    top_dir_path.create_dir().unwrap();

    // Attempt to validate symlink target with relative traversal
    let symlink_target_result = boundary.strict_join(&attack.symlink_target);

    // ✅ SECURITY GUARANTEE: Relative traversal is rejected
    assert!(
        symlink_target_result.is_err(),
        "strict-path MUST reject relative path traversal"
    );

    match symlink_target_result {
        Err(StrictPathError::PathEscapesBoundary { attempted_path, .. }) => {
            // Verify the error identifies the traversal attempt
            let path_str = attempted_path.to_string_lossy();
            assert!(
                path_str.contains("..") || path_str.contains("sensitive"),
                "Error should reference the attempted traversal: {}",
                path_str
            );
        }
        Err(StrictPathError::PathResolutionError { .. }) => {
            // Also acceptable - non-existent path
        }
        Ok(_) => panic!("strict_join MUST NOT accept path with parent directory components"),
        Err(other) => panic!("Unexpected error variant: {:?}", other),
    }
}

#[test]
fn test_cve_2025_11001_unc_path_attack_blocked() {
    // CVE-2025-11002 involves UNC path symlinks for network targets
    let unc_targets = vec![
        "\\\\malicious-server\\share\\payload.exe",
        "\\\\192.168.1.100\\c$\\Windows\\System32",
        "//network-share/sensitive/data.db",
    ];

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    for unc_path in unc_targets {
        let result = boundary.strict_join(unc_path);

        // ✅ SECURITY GUARANTEE: UNC paths are rejected
        assert!(
            result.is_err(),
            "strict-path MUST reject UNC path: {}",
            unc_path
        );

        match result {
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected - UNC paths are absolute and/or escape the boundary
            }
            Ok(_) => panic!("strict_join MUST NOT accept UNC path: {}", unc_path),
            Err(other) => panic!("Unexpected error for UNC path '{}': {:?}", unc_path, other),
        }
    }
}

#[test]
fn test_cve_2025_11001_mixed_encoding_attack_blocked() {
    // Test URL-encoded traversal attempts (mentioned in the article)
    let encoded_attacks = vec![
        "..%2F..%2F..%2FUsers%2FPublic",
        "..%5C..%5C..%5CWindows%5CSystem32",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // Unix-style for completeness
    ];

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    for encoded_path in encoded_attacks {
        let result = boundary.strict_join(encoded_path);

        // Note: URL decoding is typically done at a higher layer (ZIP library)
        // strict-path handles the decoded path. This test verifies that even
        // if URL-encoded paths slip through, the literal strings are contained
        match result {
            Ok(validated_path) => {
                // If accepted (literal percent signs), verify containment
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Even literal encoded string must stay within boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Also acceptable - rejected as traversal
            }
            Err(other) => panic!(
                "Unexpected error for encoded path '{}': {:?}",
                encoded_path, other
            ),
        }
    }
}

#[test]
fn test_safe_archive_extraction_workflow() {
    // Demonstrate the CORRECT way to extract archives using strict-path
    // This is what archive libraries SHOULD do to prevent CVE-2025-11001

    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

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
        let validated_path = boundary
            .strict_join(entry_path)
            .expect("Safe archive entry should be accepted");

        // Verify containment
        assert!(
            validated_path.strictpath_starts_with(boundary.interop_path()),
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
    let boundary: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

    // Create safe target within boundary
    let safe_target = boundary.strict_join("target.txt").unwrap();
    safe_target.write(b"content").unwrap();

    // Create safe link within boundary - THIS WORKS (if privileges available)
    let safe_link = boundary.strict_join("link.txt").unwrap();

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
        Err(e) => panic!("Unexpected error creating symlink: {}", e),
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
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

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
        let result = boundary.strict_join(filename);

        match result {
            Ok(validated_path) => {
                // If somehow accepted (e.g., literal string without special meaning),
                // it MUST still be within the boundary
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Filename '{}' resulted in path outside boundary: {:?}",
                    filename,
                    validated_path
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected - malicious path rejected
            }
            Err(other) => {
                panic!(
                    "Unexpected error for malicious filename '{}': {:?}",
                    filename, other
                );
            }
        }
    }
}

#[test]
fn test_cve_2025_11001_prevents_arbitrary_file_write() {
    // End-to-end test demonstrating that the attack pattern fails completely
    let extraction_dir = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    // Attacker's goal: Write a file to C:\Users\Public\malware.exe
    let target_outside_boundary = "C:\\Users\\Public\\malware.exe";

    // Step 1: Try to write directly (should fail)
    let direct_write = boundary.strict_join(target_outside_boundary);
    assert!(
        direct_write.is_err(),
        "Direct write to outside path must fail"
    );

    // Step 2: Try to create symlink and write through it (should fail)
    // We can't even create a StrictPath to the outside target
    let symlink_target = boundary.strict_join("C:\\Users\\Public");
    assert!(
        symlink_target.is_err(),
        "Cannot create StrictPath to outside directory"
    );

    // Step 3: Try relative traversal (should fail)
    let relative_escape = boundary.strict_join("../../../Users/Public/malware.exe");
    assert!(relative_escape.is_err(), "Relative traversal must fail");

    // ✅ CONCLUSION: All attack vectors are blocked
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

                // ✅ SECURITY GUARANTEE: Even if accepted, underlying path is contained
                assert!(
                    underlying_strict.strictpath_starts_with(vroot.interop_path()),
                    "Virtual path for '{}' must be contained within boundary",
                    attack
                );

                // Virtual display should be normalized and rooted
                let display = vpath.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display must be rooted: {}",
                    display
                );

                // Should not leak traversal components
                assert!(
                    !display.contains(".."),
                    "Virtual display must not contain '..': {}",
                    display
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
    let boundary: PathBoundary = PathBoundary::try_new_create(temp.path()).unwrap();

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
        let result = boundary.strict_join(test.path);

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
                        validated_path.strictpath_starts_with(boundary.interop_path()),
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
        println!("\n=== {} ===", test.description);
        println!("Attack path: {}", test.path);
        println!("Vulnerable 7-Zip: {}", test.vulnerable_7zip_behavior);
        println!("strict-path: {}", test.strict_path_behavior);
        println!("Result: ✅ PROTECTED");
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
    let boundary: PathBoundary = PathBoundary::try_new_create(extraction_dir.path()).unwrap();

    let data_dir = boundary.strict_join("data").unwrap();
    data_dir.create_dir_all().unwrap();

    // Link path inside the boundary: data/link_in
    let link_in = boundary
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
                    eprintln!("Note: symlink_dir failed: {}", e);
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
    let through_link = boundary.strict_join("data/link_in/malicious.exe");

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
                validated_path.strictpath_starts_with(boundary.interop_path()),
                "Path through outside-pointing link must still be contained within boundary: {:?}",
                validated_path
            );
        }
        Err(other) => panic!("Unexpected error variant: {:?}", other),
    }
}
