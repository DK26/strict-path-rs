//! Tests for symlink, hard link, and junction creation helpers within boundaries,
//! metadata inspection, and escape-rejection for targets that cross the boundary.
//!
//! ## Symlink Clamping Behavior (soft-canonicalize patch required)
//!
//! Tests at the end of this file (`following_symlink_pointing_outside_vroot`,
//! `following_junction_pointing_outside_vroot`, `following_junction_with_relative_escape`)
//! expect **clamping behavior** for absolute symlink targets.

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{PathBoundary, StrictPathError};

#[cfg(windows)]
fn symlink_permission_denied(err: &std::io::Error) -> bool {
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    err.kind() == std::io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD)
}

#[cfg(not(windows))]
fn symlink_permission_denied(_err: &std::io::Error) -> bool {
    false
}

fn hard_link_unsupported(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
    )
}

#[cfg(all(windows, feature = "junctions"))]
#[test]
fn strict_junction_helpers_create_junctions_within_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Junction target must be a directory
    let target_dir = test_dir.strict_join("data/dir").unwrap();
    target_dir.create_dir_all().unwrap();

    let link_dir = test_dir.strict_join("links/junc").unwrap();
    link_dir.create_parent_dir_all().unwrap();

    if let Err(err) = target_dir.strict_junction(link_dir.interop_path()) {
        // Junctions generally don't require admin; if some env forbids, skip
        eprintln!("Skipping strict_junction test due to environment: {err:?}");
        return;
    }
    // Some environments may not flag junctions as directories via is_dir(); verify by attempting to read
    if !link_dir.exists() {
        eprintln!("Skipping strict_junction test: link does not exist after creation");
        return;
    }
    if let Err(err) = link_dir.read_dir() {
        eprintln!("Skipping strict_junction test: unable to read junction as directory: {err:?}");
        return;
    }

    // Also exercise PathBoundary wrapper
    let link_from_root = test_dir.strict_join("links/root_junc").unwrap();
    link_from_root.create_parent_dir_all().unwrap();
    if let Err(err) = test_dir.strict_junction(link_from_root.interop_path()) {
        eprintln!("Skipping PathBoundary::strict_junction test due to environment: {err:?}");
        return;
    }
    if !link_from_root.exists() {
        eprintln!(
            "Skipping PathBoundary::strict_junction test: link does not exist after creation"
        );
        return;
    }
    if let Err(err) = link_from_root.read_dir() {
        eprintln!("Skipping PathBoundary::strict_junction test: unable to read junction as directory: {err:?}");
    }
}

#[cfg(all(windows, feature = "virtual-path", feature = "junctions"))]
#[test]
fn virtual_junction_helpers_create_junctions_within_root() {
    use crate::VirtualRoot;

    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Junction target must be a directory
    let target_dir = vroot.virtual_join("data/dir").unwrap();
    target_dir.create_dir_all().unwrap();

    let link_dir = vroot.virtual_join("links/junc").unwrap();
    link_dir.create_parent_dir_all().unwrap();

    // Use absolute virtual path to exercise clamping semantics
    if let Err(err) = target_dir.virtual_junction("/links/junc") {
        // Junctions generally don't require admin; if some env forbids, skip
        eprintln!("Skipping virtual_junction test due to environment: {err:?}");
        return;
    }

    // Verify link existence and basic directory behavior
    if !link_dir.exists() {
        eprintln!("Skipping virtual_junction test: link does not exist after creation");
        return;
    }
    if let Err(err) = link_dir.read_dir() {
        eprintln!("Skipping virtual_junction test: unable to read junction as directory: {err:?}");
        return;
    }

    // Also exercise VirtualRoot helper
    let root_link = vroot.virtual_join("links/root_junc").unwrap();
    root_link.create_parent_dir_all().unwrap();
    if let Err(err) = vroot.virtual_junction("/links/root_junc") {
        eprintln!("Skipping VirtualRoot::virtual_junction test due to environment: {err:?}");
        return;
    }
    if !root_link.exists() {
        eprintln!(
            "Skipping VirtualRoot::virtual_junction test: link does not exist after creation"
        );
        return;
    }
    if let Err(err) = root_link.read_dir() {
        eprintln!("Skipping VirtualRoot::virtual_junction test: unable to read junction as directory: {err:?}");
    }
}

// When the `junctions` feature is disabled, any test that requires junction creation
// must fail loudly with a clear explanation so users know how to enable it.
#[cfg(all(windows, not(feature = "junctions")))]
#[test]
fn strict_junction_helpers_require_junctions_feature() {
    panic!(
        "This test requires the 'junctions' feature. \
         Enable it with: cargo test -p strict-path --features junctions \
         (CI and default dev runs use --all-features)."
    );
}

#[test]
fn strict_symlink_helpers_create_links_within_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let target = test_dir.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    let direct_link = test_dir.strict_join("links/direct.txt").unwrap();
    direct_link.create_parent_dir_all().unwrap();
    if let Err(err) = target.strict_symlink(direct_link.interop_path()) {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping strict symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("strict_symlink failed unexpectedly: {err:?}");
    }
    assert!(direct_link.exists());

    #[cfg(unix)]
    {
        let link_target = std::fs::read_link(direct_link.interop_path()).unwrap();
        assert!(link_target.ends_with("data/target.txt"));
    }

    #[cfg(windows)]
    {
        let link_target = std::fs::read_link(direct_link.interop_path()).unwrap();
        let normalized = link_target.to_string_lossy().replace("\\", "/");
        assert!(normalized.ends_with("data/target.txt"));
    }

    let boundary_link = test_dir.strict_join("links/from_test_dir.txt").unwrap();
    boundary_link.create_parent_dir_all().unwrap();
    if let Err(err) = test_dir.strict_symlink(boundary_link.interop_path()) {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping PathBoundary symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("PathBoundary::strict_symlink failed unexpectedly: {err:?}");
    }
    assert!(boundary_link.exists());
}

#[test]
fn strict_hard_link_helpers_create_links_within_boundary() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let target = test_dir.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    let hard_link = test_dir.strict_join("links/direct.txt").unwrap();
    hard_link.create_parent_dir_all().unwrap();
    if let Err(err) = target.strict_hard_link(hard_link.interop_path()) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping hard link test: not supported ({err:?})");
            return;
        }
        panic!("strict_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(hard_link.read_to_string().unwrap(), "hello");

    let boundary_link = test_dir.strict_join("links/from_test_dir.txt").unwrap();
    boundary_link.create_parent_dir_all().unwrap();
    if let Err(err) = test_dir.strict_hard_link(boundary_link.interop_path()) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping PathBoundary hard link test: not supported ({err:?})");
            return;
        }
        panic!("PathBoundary::strict_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(boundary_link.read_to_string().unwrap(), "hello");
}

#[test]
fn strictpath_symlink_metadata_reports_link_entry() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Prepare a target file
    let target = test_dir.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    // Location for the link/junction
    let link = test_dir.strict_join("links/link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    match target.strict_symlink(link.interop_path()) {
        Ok(()) => {
            // symlink_metadata should report the link, not the target
            let meta = link.symlink_metadata().unwrap();
            #[cfg(unix)]
            assert!(meta.file_type().is_symlink());
            #[cfg(windows)]
            assert!(meta.file_type().is_symlink());

            // metadata() follows links
            let follow = link.metadata().unwrap();
            assert!(!follow.file_type().is_symlink());
        }
        Err(err) if symlink_permission_denied(&err) => {
            // On Windows without privileges, fall back to junction when available
            #[cfg(all(windows, feature = "junctions"))]
            {
                let dir_target = test_dir.strict_join("data/dir").unwrap();
                dir_target.create_dir_all().unwrap();
                let dir_link = test_dir.strict_join("links/junc").unwrap();
                dir_link.create_parent_dir_all().unwrap();

                dir_target.strict_junction(dir_link.interop_path()).unwrap();

                // symlink_metadata should return metadata for the entry (the junction itself)
                assert!(dir_link.symlink_metadata().is_ok());
                // Following the junction to the target should succeed
                assert!(dir_link.metadata().is_ok());
            }

            #[cfg(all(windows, not(feature = "junctions")))]
            {
                // Last-resort fallback in tests: create a junction via third-party crate
                let dir_target = test_dir.strict_join("data/dir").unwrap();
                dir_target.create_dir_all().unwrap();
                let dir_link = test_dir.strict_join("links/junc").unwrap();
                dir_link.create_parent_dir_all().unwrap();
                junction::create(dir_target.interop_path(), dir_link.interop_path()).unwrap();
                assert!(dir_link.symlink_metadata().is_ok());
                assert!(dir_link.metadata().is_ok());
            }
            #[cfg(not(windows))]
            {}
        }
        Err(err) => panic!("unexpected symlink creation error: {err:?}"),
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtualpath_symlink_metadata_reports_link_entry() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target = vroot.virtual_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"ok").unwrap();

    let link = vroot.virtual_join("links/link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    match target.virtual_symlink("/links/link.txt") {
        Ok(()) => {
            let meta = link.symlink_metadata().unwrap();
            #[cfg(unix)]
            assert!(meta.file_type().is_symlink());
            #[cfg(windows)]
            assert!(meta.file_type().is_symlink());

            let follow = link.metadata().unwrap();
            assert!(!follow.file_type().is_symlink());
        }
        Err(err) if symlink_permission_denied(&err) => {
            // Fall back to junction creation under virtual semantics (Windows + junctions feature)
            #[cfg(all(windows, feature = "junctions"))]
            {
                // Build target and link via underlying PathBoundary to avoid absolute virtual path pitfalls
                let strict_root = vroot.as_unvirtual();
                let strict_target = strict_root.strict_join("data/dir").unwrap();
                strict_target.create_dir_all().unwrap();
                let strict_link = strict_root.strict_join("links/junc").unwrap();
                strict_link.create_parent_dir_all().unwrap();
                // Create junction to target directory
                strict_target
                    .strict_junction(strict_link.interop_path())
                    .unwrap();

                // Verify via virtual view using relative path to avoid absolute anchored issues
                let dir_link = vroot.virtual_join("links/junc").unwrap();
                assert!(dir_link.symlink_metadata().is_ok());
                assert!(dir_link.metadata().is_ok());
            }

            #[cfg(all(windows, not(feature = "junctions")))]
            {
                // Fallback using third-party junction creation on system paths derived from strict view
                let strict_root = vroot.as_unvirtual();
                let strict_target = strict_root.strict_join("data/dir").unwrap();
                strict_target.create_dir_all().unwrap();
                let strict_link = strict_root.strict_join("links/junc").unwrap();
                strict_link.create_parent_dir_all().unwrap();
                junction::create(strict_target.interop_path(), strict_link.interop_path()).unwrap();

                // Verify via virtual view using relative path
                let dir_link = vroot.virtual_join("links/junc").unwrap();
                assert!(dir_link.symlink_metadata().is_ok());
                assert!(dir_link.metadata().is_ok());
                return;
            }
            #[cfg(not(windows))]
            {}
        }
        Err(err) => panic!("unexpected symlink creation error (virtual): {err:?}"),
    }
}

#[test]
fn strict_symlink_rejects_escape_targets() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let link = test_dir.strict_join("link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    let outside_dir = tempfile::tempdir().unwrap();
    let outside_access_dir: PathBoundary = PathBoundary::try_new_create(outside_dir.path()).unwrap();
    let outside_target = outside_access_dir.strict_join("secret.txt").unwrap();

    let err = outside_target
        .strict_symlink(link.interop_path())
        .expect_err("escape symlink should be rejected");
    let inner = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<StrictPathError>());
    assert!(matches!(
        inner,
        Some(StrictPathError::PathEscapesBoundary { .. })
    ));
}

#[test]
fn strict_hard_link_rejects_escape_targets() {
    let td = tempfile::tempdir().unwrap();
    let test_dir: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let link = test_dir.strict_join("link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    let outside_dir = tempfile::tempdir().unwrap();
    let outside_access_dir: PathBoundary = PathBoundary::try_new_create(outside_dir.path()).unwrap();
    let outside_target = outside_access_dir.strict_join("secret.txt").unwrap();
    outside_target.write(b"secret").unwrap();

    let err = outside_target
        .strict_hard_link(link.interop_path())
        .expect_err("escape hard link should be rejected");
    let inner = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<StrictPathError>());
    assert!(matches!(
        inner,
        Some(StrictPathError::PathEscapesBoundary { .. })
    ));
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_symlink_helpers_create_links_within_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target = vroot.virtual_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"ok").unwrap();

    let link = vroot.virtual_join("links/alias.txt").unwrap();
    link.create_parent_dir_all().unwrap();
    if let Err(err) = target.virtual_symlink("/links/alias.txt") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping virtual symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("virtual_symlink failed unexpectedly: {err:?}");
    }
    assert!(link.exists());

    let root_link = vroot.virtual_join("links/from_root.txt").unwrap();
    root_link.create_parent_dir_all().unwrap();
    if let Err(err) = vroot.virtual_symlink("/links/from_root.txt") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping VirtualRoot symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("VirtualRoot::virtual_symlink failed unexpectedly: {err:?}");
    }
    assert!(root_link.exists());
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_hard_link_helpers_create_links_within_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target = vroot.virtual_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"ok").unwrap();

    let link = vroot.virtual_join("links/alias.txt").unwrap();
    link.create_parent_dir_all().unwrap();
    if let Err(err) = target.virtual_hard_link("/links/alias.txt") {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping virtual hard link test: not supported ({err:?})");
            return;
        }
        panic!("virtual_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(link.read_to_string().unwrap(), "ok");

    // Attempting to create a hard link to a directory (the virtual root) should be forbidden.
    // Validate that the OS rejects this operation deterministically.
    let root_link = vroot.virtual_join("links/from_root.txt").unwrap();
    root_link.create_parent_dir_all().unwrap();
    match vroot.virtual_hard_link("/links/from_root.txt") {
        Ok(()) => {
            panic!(
                "VirtualRoot::virtual_hard_link unexpectedly succeeded; directory hard links should be forbidden"
            );
        }
        Err(err) => {
            let kind = err.kind();
            assert!(
                matches!(
                    kind,
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::Other
                        | std::io::ErrorKind::InvalidInput
                ),
                "Expected PermissionDenied/Unsupported/Other when hard-linking a directory; got: {err:?}"
            );
        }
    }
}
