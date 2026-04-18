//! Regression tests for the 2026-04-18 security audit findings.
//!
//! Each `#[test]` here started life as a failing proof-of-vulnerability (it
//! demonstrated the bug before a fix existed). They are preserved as green
//! regression tests so the behavior cannot silently revert.
//!
//! - F1: `strictpath_with_extension` / `virtualpath_with_extension` must
//!   return `Err` (not panic) on untrusted extensions.
//! - F2: `virtualpath_display` must scrub all C0/DEL control characters and
//!   `;`, not just `\n`.
//! - F3: `strictpath_parent()` must return `Ok(None)` at the boundary root,
//!   and root-level rename/copy/symlink must fall back to the boundary dir.
//! - F4: `FromStr` must validate, not create. Parsing an untrusted string
//!   through `PathBoundary`/`VirtualRoot` must not materialize directories.
//! - F5: Windows verbatim/device-namespace prefix stripping must cover
//!   `\\?\`, `\\.\`, and `\\?\UNC\` so junction creation works on any
//!   normalized form.

use crate::PathBoundary;
#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

// ---------------------------------------------------------------------------
// F1 — extension panic DoS
// ---------------------------------------------------------------------------

#[test]
fn f1_strictpath_with_extension_rejects_separator_without_panic() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let f = boundary.strict_join("report.txt").unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.strictpath_with_extension("/../../../etc/passwd")
    }));

    assert!(
        result.is_ok(),
        "strictpath_with_extension must not panic on attacker-controlled \
         extensions"
    );
    assert!(
        result.unwrap().is_err(),
        "separator-bearing extension must produce Err"
    );
}

#[test]
fn f1_strictpath_with_extension_rejects_backslash_on_windows() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let f = boundary.strict_join("report.txt").unwrap();

    // Backslash is a path separator on Windows. On Unix it's a legal byte in a
    // filename (and so `a.b\c` is just a weirdly-named extension), so the
    // assertion differs by platform.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.strictpath_with_extension(r"a\b")
    }))
    .expect("must not panic");

    #[cfg(windows)]
    assert!(result.is_err(), "backslash must be rejected on Windows");
    #[cfg(not(windows))]
    let _ = result; // on Unix either outcome is acceptable (still must not panic)
}

#[test]
fn f1_strictpath_with_extension_rejects_nul_byte() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let f = boundary.strict_join("report.txt").unwrap();

    // NUL inside a path is never legal on any major filesystem and often
    // truncates C string APIs silently. Reject explicitly.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.strictpath_with_extension("x\0y")
    }))
    .expect("must not panic");

    assert!(result.is_err(), "NUL byte in extension must produce Err");
}

#[cfg(feature = "virtual-path")]
#[test]
fn f1_virtualpath_with_extension_rejects_separator_without_panic() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();
    let f = vroot.virtual_join("report.txt").unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.virtualpath_with_extension("/../../../etc/passwd")
    }));

    assert!(
        result.is_ok(),
        "virtualpath_with_extension must not panic on attacker-controlled \
         extensions"
    );
    assert!(
        result.unwrap().is_err(),
        "separator-bearing extension must produce Err"
    );
}

// ---------------------------------------------------------------------------
// F2 — display sanitizer leaks control characters
// ---------------------------------------------------------------------------

#[cfg(feature = "virtual-path")]
#[test]
fn f2_virtualpath_display_scrubs_carriage_return() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    let v = vroot.virtual_join("foo\rDELETE_ME").unwrap();
    let display = v.virtualpath_display().to_string();

    assert!(
        !display.contains('\r'),
        "virtualpath_display leaks CR into user-facing output; got {:?}",
        display
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn f2_virtualpath_display_scrubs_ansi_escape() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    let v = vroot.virtual_join("foo\x1b[2Jbar").unwrap();
    let display = v.virtualpath_display().to_string();

    assert!(
        !display.contains('\x1b'),
        "virtualpath_display leaks ESC into user-facing output; got bytes {:x?}",
        display.as_bytes()
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn f2_virtualpath_display_scrubs_all_c0_controls() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    // Every C0 control we can reasonably push through virtual_join. We skip
    // NUL (forbidden by filesystem APIs on every platform) and `/`, `\` (path
    // separators); anything else soft-canonicalize accepts should round-trip
    // into display without leaking the raw byte.
    let payload = "a\x01b\x02c\x07d\x08e\x0bf\x0cg\x1ch";
    let v = vroot.virtual_join(payload).unwrap();
    let display = v.virtualpath_display().to_string();

    for ch in display.chars() {
        assert!(
            ch == '/' || ch == '_' || (ch as u32) >= 0x20,
            "virtualpath_display leaked a C0 control: {:?} (in {:?})",
            ch,
            display
        );
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn f2_virtualpath_display_scrubs_del() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    let v = vroot.virtual_join("foo\x7fbar").unwrap();
    let display = v.virtualpath_display().to_string();

    assert!(
        !display.contains('\x7f'),
        "virtualpath_display leaks DEL (0x7f); got bytes {:x?}",
        display.as_bytes()
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn f2_virtualpath_display_preserves_newline_scrub() {
    // Pre-existing guarantee (newline was the original case). Keep as a pin
    // so a future rewrite of the sanitizer can't silently drop the coverage.
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    let v = vroot.virtual_join("foo\nbar").unwrap();
    let display = v.virtualpath_display().to_string();

    assert!(!display.contains('\n'), "newline must remain scrubbed");
}

// ---------------------------------------------------------------------------
// F3 — strictpath_parent() at boundary root
// ---------------------------------------------------------------------------

#[test]
fn f3_strictpath_parent_returns_none_at_boundary_root() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let root = boundary.into_strictpath().unwrap();

    let parent = root.strictpath_parent();

    assert!(
        matches!(parent, Ok(None)),
        "strictpath_parent must be Ok(None) at the boundary root; got {:?}",
        parent
            .as_ref()
            .map(|o| o.as_ref().map(|p| p.strictpath_display().to_string()))
    );
}

#[test]
fn f3_strictpath_parent_unchanged_for_non_root_paths() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    boundary.strict_join("logs").unwrap().create_dir().unwrap();
    let child = boundary.strict_join("logs/app.log").unwrap();

    let parent = child
        .strictpath_parent()
        .unwrap()
        .expect("non-root path must have a Some(parent)");
    assert!(
        parent.strictpath_display().to_string().ends_with("logs"),
        "parent of logs/app.log should end with 'logs'"
    );
}

#[test]
fn f3_create_parent_dir_at_boundary_root_is_noop() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let root = boundary.into_strictpath().unwrap();

    // Must not error — boundary directory already exists, nothing to create.
    root.create_parent_dir().unwrap();
    root.create_parent_dir_all().unwrap();
}

#[test]
fn f3_strict_rename_at_boundary_root_does_not_emit_bogus_escape_error() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();

    // Renaming a legitimate child still works — baseline.
    boundary.strict_join("src.txt").unwrap().write("x").unwrap();
    boundary
        .strict_join("src.txt")
        .unwrap()
        .strict_rename("renamed.txt")
        .unwrap();

    // Renaming the boundary root itself will fail (the OS refuses to move a
    // directory onto an existing or in-use path), but the failure must come
    // from the OS, not from the `strictpath_parent` fallback that used to
    // bubble up `PathEscapesBoundary`.
    let root_as_sp = boundary.clone().into_strictpath().unwrap();
    if let Err(e) = root_as_sp.strict_rename("anything") {
        let msg = e.to_string();
        assert!(
            !msg.contains("escapes boundary"),
            "relative rename on boundary root must not report a bogus escape; got {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// F4 — FromStr must validate, not create
// ---------------------------------------------------------------------------

#[test]
fn f4_pathboundary_from_str_does_not_create_directory() {
    let td = tempfile::tempdir().unwrap();
    let phantom = td.path().join("never-should-be-created-by-parse");
    assert!(!phantom.exists(), "precondition: directory does not exist");

    let parsed: std::result::Result<PathBoundary, _> =
        phantom.to_string_lossy().parse();

    assert!(
        parsed.is_err(),
        "FromStr for PathBoundary must reject non-existent paths (not silently \
         create them)"
    );
    assert!(
        !phantom.exists(),
        "FromStr must not materialize a directory — this would be a filesystem \
         side effect from parsing untrusted input"
    );
}

#[cfg(feature = "virtual-path")]
#[test]
fn f4_virtualroot_from_str_does_not_create_directory() {
    let td = tempfile::tempdir().unwrap();
    let phantom = td.path().join("never-should-be-created-by-parse-vroot");
    assert!(!phantom.exists(), "precondition: directory does not exist");

    let parsed: std::result::Result<VirtualRoot, _> =
        phantom.to_string_lossy().parse();

    assert!(
        parsed.is_err(),
        "FromStr for VirtualRoot must reject non-existent paths"
    );
    assert!(
        !phantom.exists(),
        "FromStr must not materialize the sandbox — an attacker-controlled \
         string could otherwise pick any writable directory as the sandbox"
    );
}

#[test]
fn f4_pathboundary_from_str_accepts_existing_directory() {
    let td = tempfile::tempdir().unwrap();
    let parsed: PathBoundary = td
        .path()
        .to_string_lossy()
        .parse()
        .expect("existing directory should parse");
    assert!(parsed.exists());
}

// ---------------------------------------------------------------------------
// F5 — Windows verbatim/device prefix handling for junctions
// ---------------------------------------------------------------------------
// The helper being tested is `#[cfg(all(windows, feature = "junctions"))]`, so
// this whole section is compiled only on that configuration. We test the
// prefix-stripping logic observationally via `strict_junction` — the behavior
// that F5 defends is "junction creation works when the boundary was
// canonicalized to a verbatim or device-namespace path".

#[cfg(all(windows, feature = "junctions"))]
#[test]
fn f5_strict_junction_works_on_verbatim_prefixed_boundary() {
    // `soft-canonicalize` returns `\\?\`-prefixed paths on Windows. The
    // `strict_junction` method must strip that prefix before handing the path
    // to the `junction` crate, or it builds a broken junction.
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(td.path()).unwrap();
    let target = boundary.strict_join("target_dir").unwrap();
    target.create_dir().unwrap();

    let link_result = target.strict_junction("link_dir");
    // We don't require success on restricted CI runners — some environments
    // lack the privilege to create junctions. We DO require that when it does
    // run, it doesn't spuriously fail with ERROR_INVALID_NAME due to a raw
    // `\\?\` prefix reaching the junction crate.
    if let Err(e) = link_result {
        let code = e.raw_os_error().unwrap_or(0);
        assert_ne!(
            code, 123,
            "ERROR_INVALID_NAME from junction crate indicates the \\\\?\\ \
             prefix was not stripped before creation"
        );
    }
}
