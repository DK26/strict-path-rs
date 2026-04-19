//! F7 — `virtual_join` navigates to the wrong system path when a parent directory
//! contains a sanitized character in its name.
//!
//! ## Root cause
//!
//! `compute_virtual` (called inside `VirtualPath::new`) sanitizes each path
//! component and stores the *sanitized* form in `self.virtual_path`.  When
//! `virtual_join` later composes a child path it does:
//!
//! ```text
//! candidate = self.virtual_path.join("child.txt")
//! //            ^^^^^^^^^^^^^^^^ stored as "foo_bar" (sanitized)
//! //            should be       "foo\u{0085}bar" (original)
//! ```
//!
//! The candidate is then resolved relative to the boundary, so it looks for
//! `<boundary>/foo_bar/child.txt` on disk — not the real
//! `<boundary>/foo\u{0085}bar/child.txt`.  Navigation silently diverges.
//!
//! ## Fix
//!
//! Sanitization belongs at *display* time, not at *storage* time.
//! `compute_virtual` should store raw components; `VirtualPathDisplay::fmt`
//! should call `sanitize_display_component` per component before formatting.

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

// ---------------------------------------------------------------------------
// F7-A  virtual_join from a sanitized-character parent uses the wrong path
// ---------------------------------------------------------------------------

/// When a parent directory's name contains a C1 control (U+0085 NEL — sanitized
/// to '_' by the display layer), navigating into it with `virtual_join` must
/// still reach the *real* directory, not a sibling named with '_'.
#[cfg(feature = "virtual-path")]
#[test]
fn f7a_virtual_join_navigates_through_sanitized_character_dir() {
    use std::fs;
    let td = tempfile::tempdir().unwrap();

    // Create the real directory and file on disk using the original characters.
    let real_dir = td.path().join("foo\u{0085}bar");
    fs::create_dir(&real_dir).unwrap();
    fs::write(real_dir.join("child.txt"), b"hello").unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    // Navigate to the parent directory.
    let parent_vp = vroot
        .virtual_join("foo\u{0085}bar")
        .expect("virtual_join to sanitized-char dir should succeed");

    // Navigate from the parent to the child.
    let child_vp = parent_vp
        .virtual_join("child.txt")
        .expect("virtual_join('child.txt') from sanitized-char parent should succeed");

    // The underlying system path must contain the ORIGINAL directory name so
    // that filesystem I/O actually reaches the file.
    let system_display = child_vp.as_unvirtual().strictpath_display().to_string();
    assert!(
        system_display.contains("foo\u{0085}bar"),
        "virtual_join must navigate through the original (unsanitized) directory name; \
         got system path: {system_display:?}"
    );

    // And the file must actually be readable through this path.
    let content = child_vp
        .read_to_string()
        .expect("child.txt must be readable through the correct system path");
    assert_eq!(content, "hello");
}

// ---------------------------------------------------------------------------
// F7-B  virtualpath_display still sanitizes even after the fix
// ---------------------------------------------------------------------------

/// After the fix, `virtualpath_display()` for a path whose directory name
/// contains U+0085 must still show the sanitized form (no raw control chars).
/// This ensures the fix does not regress F6.
#[cfg(feature = "virtual-path")]
#[test]
fn f7b_display_still_sanitizes_after_navigation_fix() {
    use std::fs;
    let td = tempfile::tempdir().unwrap();

    let real_dir = td.path().join("foo\u{0085}bar");
    fs::create_dir(&real_dir).unwrap();
    fs::write(real_dir.join("child.txt"), b"x").unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();
    let parent_vp = vroot.virtual_join("foo\u{0085}bar").unwrap();

    let display = parent_vp.virtualpath_display().to_string();
    assert!(
        !display.contains('\u{0085}'),
        "virtualpath_display must NOT expose U+0085 NEL after the F7 fix: {display:?}"
    );
    assert!(
        display.contains("foo_bar"),
        "virtualpath_display should show sanitized 'foo_bar': {display:?}"
    );
}

// ---------------------------------------------------------------------------
// F7-C  virtualpath_parent round-trip uses the original characters
// ---------------------------------------------------------------------------

/// `virtualpath_parent()` called on a child path inside a sanitized-character
/// directory must return a VirtualPath whose system path still points to the
/// real parent directory.
#[cfg(feature = "virtual-path")]
#[test]
fn f7c_virtualpath_parent_round_trip_preserves_original_chars() {
    use std::fs;
    let td = tempfile::tempdir().unwrap();

    let real_dir = td.path().join("foo\u{0085}bar");
    fs::create_dir(&real_dir).unwrap();
    fs::write(real_dir.join("child.txt"), b"x").unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();
    let parent_vp = vroot.virtual_join("foo\u{0085}bar").unwrap();
    let child_vp = parent_vp.virtual_join("child.txt").unwrap();

    let recovered_parent = child_vp
        .virtualpath_parent()
        .expect("virtualpath_parent should succeed")
        .expect("child has a parent");

    let parent_system = recovered_parent
        .as_unvirtual()
        .strictpath_display()
        .to_string();
    assert!(
        parent_system.contains("foo\u{0085}bar"),
        "virtualpath_parent must recover the real directory name: {parent_system:?}"
    );
}
