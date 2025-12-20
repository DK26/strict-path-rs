//! Tests for Windows junction prefix mismatch handling
//!
//! This module tests junction handling with the updated dependencies:
//! - DK26/junction fork: fixes tesuji/junction#30 (verbatim prefix handling)
//! - DK26/soft-canonicalize dev branch: component-aware prefix comparison
//!
//! Issue background:
//! 1. Junction crate bug: Passing verbatim paths (`\\?\C:\...`) to `junction::create()`
//!    caused broken junctions with double-prefix corruption (`\??\\\?\C:\...`).
//! 2. Prefix mismatch: Junction targets are always returned in non-verbatim format
//!    (`C:\...`) by Windows, regardless of input format. This caused `strip_prefix`
//!    failures when comparing against verbatim anchor paths.
//!
//! See WINDOWS_JUNCTION_HANDLING.md for detailed documentation.

/// Test 1: Junction inside boundary resolves correctly without path duplication.
///
/// This tests that when a junction inside the boundary points to a target also
/// inside the boundary, the resolved path:
/// - Does NOT have duplicated path segments
/// - Does NOT contain current working directory contamination
/// - IS inside the boundary
#[cfg(all(windows, feature = "junctions"))]
#[test]
fn test_junction_inside_boundary_prefix_mismatch() {
    use crate::PathBoundary;

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
            println!("Resolved path: {path_str}");

            // It should be inside the boundary
            assert!(path.strictpath_starts_with(boundary.interop_path()));

            // It should exist
            assert!(path.exists());
        }
        Err(e) => {
            panic!("Failed to join path through junction: {e:?}");
        }
    }
}

/// Test 2: Junction within anchor produces correct path without duplication.
///
/// This is an explicit regression test for the prefix mismatch bug that caused
/// path duplication (e.g., `\\?\C:\...\data\...\data\file.txt`).
#[cfg(all(windows, feature = "junctions"))]
#[test]
fn test_junction_within_anchor_no_duplication() {
    use crate::PathBoundary;

    let td = tempfile::tempdir().unwrap();
    let anchor = td.path();
    let boundary = PathBoundary::<()>::try_new_create(anchor).unwrap();

    // Create: anchor/data/target and anchor/links/junc -> anchor/data/target
    let data_target = boundary.strict_join("data/target").unwrap();
    data_target.create_dir_all().unwrap();

    let links_dir = boundary.strict_join("links").unwrap();
    links_dir.create_dir_all().unwrap();

    // Create junction: links/junc -> data/target
    let junc_path = links_dir.strict_join("junc").unwrap();
    if let Err(e) = data_target.strict_junction(junc_path.interop_path()) {
        eprintln!("Skipping test: failed to create junction: {e:?}");
        return;
    }

    // Resolve path through junction using strict-path
    let result = boundary.strict_join("links/junc").unwrap();
    let result_str = result.strictpath_to_string_lossy();
    println!("Resolved path: {result_str}");

    // CRITICAL: Result should NOT have duplicated path segments
    // The bug caused paths like: \\?\C:\Users\...\data\target\Users\...\data\target
    assert_eq!(
        result_str.matches("data").count(),
        1,
        "Path should contain 'data' exactly once: {result_str}"
    );

    // Verify the path resolves to the actual target, not the junction
    // The resolved path should end with data\target (the junction target)
    assert!(
        result_str.contains("data") && result_str.contains("target"),
        "Result should resolve through junction to data/target: {result_str}"
    );
}

/// Test 3: Junction creation with canonicalized (verbatim) target paths works.
///
/// This tests the DK26/junction fork fix for tesuji/junction#30.
/// With junction 1.3, passing verbatim paths to `junction::create()` would create
/// broken junctions with double-prefix corruption (`\??\\\?\C:\...`).
#[cfg(all(windows, feature = "junctions"))]
#[test]
fn test_junction_creation_with_verbatim_target() {
    let td = tempfile::tempdir().unwrap();

    // Create target directory
    let target_dir = td.path().join("target");
    std::fs::create_dir(&target_dir).unwrap();

    // Canonicalize returns verbatim path: \\?\C:\...
    let canonical_target = std::fs::canonicalize(&target_dir).unwrap();
    let canonical_str = canonical_target.to_string_lossy();
    println!("Canonical target: {canonical_str}");

    // On Windows, canonicalize should return verbatim path
    assert!(
        canonical_str.starts_with(r"\\?\"),
        "Canonicalized path should be verbatim, got: {canonical_str}"
    );

    // Create junction using canonicalized (verbatim) target
    // This would FAIL with junction 1.3, but should WORK with DK26 fork
    let junction_path = td.path().join("test_junction");
    if let Err(e) = junction::create(&canonical_target, &junction_path) {
        panic!("Junction creation with verbatim target failed (DK26 fork should fix this): {e:?}");
    }

    // Verify junction works by accessing through it
    std::fs::write(target_dir.join("test.txt"), "hello").unwrap();
    let content = std::fs::read_to_string(junction_path.join("test.txt")).unwrap();
    assert_eq!(content, "hello", "Junction should be functional");

    println!("Junction with verbatim target works correctly");
}

/// Test 4: soft-canonicalize handles junction prefix mismatch correctly.
///
/// This tests that `soft_canonicalize::anchored_canonicalize` correctly handles
/// the scenario where junction targets are returned in non-verbatim format.
#[cfg(all(windows, feature = "junctions"))]
#[test]
fn test_soft_canonicalize_handles_junction_prefix_mismatch() {
    use soft_canonicalize::anchored_canonicalize;

    let td = tempfile::tempdir().unwrap();

    // CRITICAL: Canonicalize the anchor to get verbatim path (\\?\C:\...)
    // This is the exact scenario that triggers the prefix mismatch bug:
    // - Anchor is verbatim: \\?\C:\Users\...\tmp
    // - Junction target resolves to non-verbatim: C:\Users\...\tmp\real_data
    let anchor = std::fs::canonicalize(td.path()).unwrap();
    let anchor_str = anchor.to_string_lossy();
    println!("Canonicalized anchor: {anchor_str}");
    assert!(
        anchor_str.starts_with(r"\\?\"),
        "Anchor should be verbatim for this test: {anchor_str}"
    );

    // Create structure
    std::fs::create_dir_all(anchor.join("real_data")).unwrap();

    // Create junction (junction targets are stored as non-verbatim internally by Windows)
    if let Err(e) = junction::create(anchor.join("real_data"), anchor.join("link_to_data")) {
        eprintln!("Skipping test: failed to create junction: {e:?}");
        return;
    }

    // Use soft-canonicalize's anchored_canonicalize with verbatim anchor
    // This is where the prefix mismatch would cause issues
    let result = anchored_canonicalize(&anchor, "link_to_data").unwrap();
    let result_str = result.to_string_lossy();
    println!("anchored_canonicalize result: {result_str}");

    // Should resolve to real_data, not have any duplication
    assert!(
        result_str.contains("real_data"),
        "Result should contain 'real_data': {result_str}"
    );

    // Should NOT have path duplication
    assert_eq!(
        result_str.matches("real_data").count(),
        1,
        "Result should contain 'real_data' exactly once: {result_str}"
    );

    // Result should be usable (exist on filesystem)
    assert!(result.exists(), "Resolved path should exist: {result_str}");
}

/// Test 5: VirtualPath junction handling with prefix mismatch.
///
/// Tests that VirtualPath correctly handles junctions when there's a prefix
/// mismatch between verbatim anchor and non-verbatim junction target.
#[cfg(all(windows, feature = "virtual-path", feature = "junctions"))]
#[test]
fn test_virtual_path_junction_prefix_mismatch() {
    use crate::VirtualRoot;

    let td = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::<()>::try_new_create(td.path()).unwrap();

    // Create target directory
    let target_dir = vroot.virtual_join("real_data").unwrap();
    target_dir.create_dir_all().unwrap();

    // Create a file in the target
    target_dir
        .virtual_join("secret.txt")
        .unwrap()
        .write(b"secret content")
        .unwrap();

    // Create junction: link_to_data -> real_data
    let link_path = vroot.virtual_join("link_to_data").unwrap();
    if let Err(e) = target_dir.virtual_junction(link_path.interop_path()) {
        eprintln!("Skipping test: failed to create junction: {e:?}");
        return;
    }

    // Access file through junction
    let file_through_link = vroot.virtual_join("link_to_data/secret.txt").unwrap();

    // Virtual display should show virtual path
    let virtual_display = file_through_link.virtualpath_display().to_string();
    println!("Virtual display: {virtual_display}");
    assert!(
        virtual_display.starts_with('/'),
        "Virtual display should be rooted: {virtual_display}"
    );

    // System path should be valid and not duplicated
    // Use as_unvirtual() to access StrictPath methods
    let system_str = file_through_link
        .as_unvirtual()
        .strictpath_to_string_lossy();
    println!("System path: {system_str}");
    assert_eq!(
        system_str.matches("real_data").count(),
        1,
        "System path should contain 'real_data' exactly once: {system_str}"
    );

    // File should be readable
    let content = file_through_link.read_to_string().unwrap();
    assert_eq!(content, "secret content");
}
