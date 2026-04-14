// Regression tests for soft-canonicalize issue #53:
// `symlink/../sibling` was lexically collapsed instead of following the symlink
// first. This could cause:
//   1. Security bypass: symlink pointing outside boundary + `..` = escape not detected
//   2. File confusion: symlink to nested dir + `../sibling` = wrong file resolved
//
// Fixed in soft-canonicalize v0.5.5. These tests ensure strict-path
// correctly inherits the fix and prevents future regressions.

use crate::PathBoundary;

// ---------------------------------------------------------------------------
// StrictPath: symlink pointing outside + `../sibling` MUST be rejected
// ---------------------------------------------------------------------------

/// If `link → /outside`, then `link/../secret` must not lexically collapse
/// to `boundary/secret`. Canonicalization must follow the symlink first,
/// producing `/outside/../secret` → `/secret`, which escapes the boundary.
#[cfg(unix)]
#[test]
fn strict_symlink_outside_parent_traversal_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&boundary_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Create a decoy file at boundary/secret — if the bug is present,
    // lexical normalization would resolve `link/../secret` to this file
    // instead of following the symlink.
    fs::write(boundary_dir.join("secret"), "decoy-in-boundary").unwrap();

    // Create file at outside/secret — this is where symlink-following
    // resolution would land if `..` after the symlink is resolved correctly.
    fs::write(outside_dir.join("secret"), "real-outside-file").unwrap();

    // link → /outside (absolute symlink escape)
    unix_fs::symlink(&outside_dir, boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    // `link/../secret` must be REJECTED: canonicalization follows link → outside,
    // then `..` goes above outside → base, then `secret` → base/secret.
    // In any case, the resolved path is NOT inside boundary.
    let result = restriction.strict_join("link/../secret");
    assert!(
        result.is_err(),
        "strict_join must reject symlink/../sibling when the symlink points outside. \
         Got: {:?}",
        result.unwrap().strictpath_display()
    );
}

/// Same attack but with a *relative* symlink escape: `link → ../outside`
#[cfg(unix)]
#[test]
fn strict_relative_symlink_outside_parent_traversal_is_rejected() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&boundary_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // Decoy at boundary/secret
    fs::write(boundary_dir.join("secret"), "decoy").unwrap();

    // Relative symlink: link → ../outside
    unix_fs::symlink("../outside", boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    let result = restriction.strict_join("link/../secret");
    assert!(
        result.is_err(),
        "strict_join must reject relative symlink/../sibling escape. Got: {:?}",
        result.unwrap().strictpath_display()
    );
}

// ---------------------------------------------------------------------------
// StrictPath: symlink pointing inside + `../sibling` resolves correctly
// ---------------------------------------------------------------------------

/// If `link → nested/dir` (inside boundary), then `link/../a` must resolve
/// to `nested/a` — NOT to `boundary/a` (which would be the lexical collapse).
#[cfg(unix)]
#[test]
fn strict_symlink_inside_parent_traversal_reaches_correct_sibling() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let boundary_dir = td.path();

    // boundary/
    //   nested/
    //     dir/       (real directory)
    //     a          (target file — should be reached)
    //   a            (decoy — should NOT be reached)
    //   link → nested/dir
    let nested = boundary_dir.join("nested");
    let nested_dir = nested.join("dir");
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(nested.join("a"), "correct-nested-a").unwrap();
    fs::write(boundary_dir.join("a"), "wrong-root-decoy").unwrap();

    // Relative symlink so it works on macOS (/var → /private/var)
    unix_fs::symlink("nested/dir", boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(boundary_dir).unwrap();

    // `link/../a` must follow the symlink: link → nested/dir, then ../a → nested/a
    let sp = restriction
        .strict_join("link/../a")
        .expect("link/../a should resolve inside boundary to nested/a");

    let content = sp.read_to_string().unwrap();
    assert_eq!(
        content,
        "correct-nested-a",
        "strict_join(\"link/../a\") must reach nested/a, not the root decoy. \
         Resolved to: {}",
        sp.strictpath_display()
    );
}

/// Same test ensuring the non-existing-suffix case also follows the symlink.
/// `link/../b` where `nested/b` does not exist.
#[cfg(unix)]
#[test]
fn strict_symlink_inside_parent_traversal_nonexistent_suffix() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let boundary_dir = td.path();

    // boundary/
    //   nested/
    //     dir/       (real directory)
    //   link → nested/dir
    let nested_dir = boundary_dir.join("nested").join("dir");
    fs::create_dir_all(&nested_dir).unwrap();

    unix_fs::symlink("nested/dir", boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(boundary_dir).unwrap();

    // `link/../nonexistent` — the resolved path `nested/nonexistent` doesn't exist
    // but soft-canonicalize resolves the existing prefix + appends the remainder.
    let sp = restriction
        .strict_join("link/../nonexistent")
        .expect("link/../nonexistent should resolve inside boundary");

    // The display path must be within boundary/nested/, NOT boundary/
    let display = sp.strictpath_display().to_string();
    assert!(
        display.contains("nested"),
        "Resolved path should be under nested/, got: {display}"
    );
}

// ---------------------------------------------------------------------------
// VirtualPath: symlink-based escape clamped correctly
// ---------------------------------------------------------------------------

/// VirtualPath must clamp `symlink/../escape` when the symlink points outside.
/// The clamped result must remain inside the virtual root.
#[cfg(all(unix, feature = "virtual-path"))]
#[test]
fn virtual_symlink_outside_parent_traversal_is_clamped() {
    use crate::VirtualRoot;
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&boundary_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    unix_fs::symlink(&outside_dir, boundary_dir.join("link")).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&boundary_dir).unwrap();

    let vp = vroot
        .virtual_join("link/../secret")
        .expect("VirtualPath should clamp, not error");

    // The system path must remain within the boundary
    let canonical_boundary = fs::canonicalize(&boundary_dir).unwrap();
    let system_path = vp.interop_path();
    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_boundary),
        "Virtual clamped path must stay inside boundary. Got: {system_path:?}"
    );
}

/// VirtualPath: symlink inside + `../sibling` → correct resolution
#[cfg(all(unix, feature = "virtual-path"))]
#[test]
fn virtual_symlink_inside_parent_traversal_reaches_correct_sibling() {
    use crate::VirtualRoot;
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let boundary_dir = td.path();

    let nested = boundary_dir.join("nested");
    let nested_dir = nested.join("dir");
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(nested.join("a"), "correct-nested-a").unwrap();
    fs::write(boundary_dir.join("a"), "wrong-root-decoy").unwrap();

    unix_fs::symlink("nested/dir", boundary_dir.join("link")).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(boundary_dir).unwrap();

    let vp = vroot
        .virtual_join("link/../a")
        .expect("link/../a with internal symlink should succeed");

    let content = vp.read_to_string().unwrap();
    assert_eq!(
        content,
        "correct-nested-a",
        "virtual_join(\"link/../a\") must reach nested/a. Got display: {}",
        vp.virtualpath_display()
    );

    // The virtual display must reflect the resolved path under nested/
    let display = vp.virtualpath_display().to_string();
    assert_eq!(display, "/nested/a", "Expected /nested/a, got {display}");
}

// ---------------------------------------------------------------------------
// Windows: junction + `../sibling` escape detection
// ---------------------------------------------------------------------------

/// On Windows, junctions are resolved lexically for `..` — the OS does NOT
/// follow the junction target before applying parent traversal. So
/// `jlink/../secret` → `boundary/secret` (stays inside the boundary).
/// This differs from Unix but is still safe: no escape occurs.
#[cfg(windows)]
#[test]
fn strict_junction_outside_parent_traversal_stays_inside_on_windows() {
    use std::fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    let outside_dir = base.join("outside");
    fs::create_dir_all(&boundary_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    // File inside boundary — Windows lexical resolution reaches this
    fs::write(boundary_dir.join("secret"), "inside-boundary").unwrap();

    let jlink = boundary_dir.join("jlink");
    let outside_canonical = fs::canonicalize(&outside_dir).unwrap();
    if junction::create(&outside_canonical, &jlink).is_err() {
        return;
    }

    let restriction: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    // Windows resolves lexically: jlink/../secret → boundary/secret (inside)
    let result = restriction.strict_join("jlink/../secret");
    match result {
        Ok(sp) => {
            let content = sp.read_to_string().unwrap();
            assert_eq!(
                content, "inside-boundary",
                "Windows lexical resolution should reach boundary/secret"
            );
        }
        Err(_) => {
            // Also acceptable if canonicalization detects the junction target
        }
    }
}

/// Windows: junction inside boundary + `../sibling` — Windows resolves `..`
/// lexically before following the junction, so `jlink/../a` → `boundary/a`
/// (the root-level file), NOT `nested/a`. This is safe (stays in boundary)
/// but differs from the Unix symlink-following behavior.
#[cfg(windows)]
#[test]
fn strict_junction_inside_parent_traversal_lexical_on_windows() {
    use std::fs;

    let td = tempfile::tempdir().unwrap();
    let boundary_dir = td.path();

    let nested = boundary_dir.join("nested");
    let nested_dir = nested.join("dir");
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(nested.join("a"), "correct-nested-a").unwrap();
    fs::write(boundary_dir.join("a"), "root-level-a").unwrap();

    let nested_dir_canonical = fs::canonicalize(&nested_dir).unwrap();
    let jlink = boundary_dir.join("jlink");
    if junction::create(&nested_dir_canonical, &jlink).is_err() {
        return;
    }

    let restriction: PathBoundary = PathBoundary::try_new(boundary_dir).unwrap();

    let sp = restriction
        .strict_join("jlink/../a")
        .expect("jlink/../a should resolve inside boundary");

    // Windows lexical resolution: jlink/../a → boundary/a (root-level)
    let content = sp.read_to_string().unwrap();
    assert_eq!(
        content, "root-level-a",
        "Windows resolves junction/../a lexically to boundary/a"
    );
}

// ---------------------------------------------------------------------------
// Edge cases: chained symlinks + `..`, deep nesting
// ---------------------------------------------------------------------------

/// Chain: `link1 → sub1`, `sub1/link2 → sub1/sub2`.
/// `link1/link2/../a` must resolve through both symlinks to reach `sub1/a`.
#[cfg(unix)]
#[test]
fn strict_chained_symlinks_parent_traversal() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let boundary_dir = td.path();

    // boundary/
    //   sub1/
    //     sub2/        (real dir)
    //     a            (target — should be reached)
    //     link2 → sub2
    //   a              (decoy — should NOT be reached)
    //   link1 → sub1
    let sub1 = boundary_dir.join("sub1");
    let sub2 = sub1.join("sub2");
    fs::create_dir_all(&sub2).unwrap();

    // The real target file: sub1/a
    fs::write(sub1.join("a"), "correct-sub1-a").unwrap();
    // Decoy at root
    fs::write(boundary_dir.join("a"), "wrong-root-decoy").unwrap();

    // link1 → sub1 (relative)
    unix_fs::symlink("sub1", boundary_dir.join("link1")).unwrap();
    // sub1/link2 → sub2 (relative)
    unix_fs::symlink("sub2", sub1.join("link2")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(boundary_dir).unwrap();

    // link1/link2/../a
    // Step 1: link1 → sub1
    // Step 2: sub1/link2 → sub1/sub2
    // Step 3: sub1/sub2/../a → sub1/a → "correct-sub1-a"
    // Without the fix: link1/link2/../a → lexically → boundary/link1/a (wrong!)
    let sp = restriction
        .strict_join("link1/link2/../a")
        .expect("chained symlink traversal should resolve inside boundary");

    let content = sp.read_to_string().unwrap();
    assert_eq!(
        content,
        "correct-sub1-a",
        "Chained symlink/.. must follow links, not collapse lexically. \
         Resolved to: {}",
        sp.strictpath_display()
    );
}

/// Symlink to self (boundary root): `link → .`, then `link/../<escape>`.
/// The `..` goes above boundary → must be rejected.
#[cfg(unix)]
#[test]
fn strict_symlink_to_dot_parent_traversal_escape() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    fs::create_dir_all(&boundary_dir).unwrap();

    // link → . (pointing to boundary_dir itself)
    unix_fs::symlink(".", boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    // link → boundary_dir, then ../escape → goes above boundary
    let result = restriction.strict_join("link/../../escape");
    assert!(
        result.is_err(),
        "link(→.)/../../escape must be rejected as boundary escape"
    );

    // But link/../ should resolve back to boundary itself (not escape)
    let safe = restriction.strict_join("link/..");
    // This either resolves to boundary itself (ok) or is rejected (also ok)
    if let Ok(sp) = safe {
        // Must be the boundary root itself
        let canonical_boundary = fs::canonicalize(&boundary_dir).unwrap();
        assert_eq!(
            sp.interop_path(),
            canonical_boundary.as_os_str(),
            "link/.. should resolve to boundary root"
        );
    }
}

/// Multiple `..` segments after a symlink: `link/../../..` must follow the
/// symlink before applying the traversals.
#[cfg(unix)]
#[test]
fn strict_symlink_deep_parent_traversal_escape() {
    use std::fs;
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let base = td.path();

    let boundary_dir = base.join("boundary");
    let nested = boundary_dir.join("a").join("b").join("c");
    fs::create_dir_all(&nested).unwrap();

    // link → a/b/c (deep inside boundary)
    unix_fs::symlink("a/b/c", boundary_dir.join("link")).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&boundary_dir).unwrap();

    // link/../../../escape → a/b/c/../../../escape → boundary/escape (or above)
    // a/b/c + ../../../escape → escape (at boundary level)
    // This should succeed since "escape" would be at boundary root level
    // (if the file were to exist)
    let inside = restriction.strict_join("link/../../../within");
    // This resolves to boundary/within — inside boundary, so it should succeed
    // (the file doesn't need to exist for strict_join to validate the path)
    if let Ok(sp) = &inside {
        let display = sp.strictpath_display().to_string();
        assert!(
            !display.contains(".."),
            "Resolved path must not contain raw ..: {display}"
        );
    }

    // But one more `..` escapes: link/../../../../escape
    let escaped = restriction.strict_join("link/../../../../escape");
    assert!(
        escaped.is_err(),
        "link/../../../../escape must be rejected when link points 3 levels deep"
    );
}
