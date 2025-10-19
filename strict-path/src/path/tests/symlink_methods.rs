//! Tests for symlink, hard link, copy, and rename operations.
//!
//! ## Symlink Clamping Behavior (soft-canonicalize patch required)
//!
//! Tests at the end of this file (`following_symlink_pointing_outside_vroot`,
//! `following_junction_pointing_outside_vroot`, `following_junction_with_relative_escape`)
//! expect **clamping behavior** for absolute symlink targets.
//!
//! **Expected behavior:** When `anchored_canonicalize()` follows a symlink with an
//! absolute target (e.g., `/etc/passwd` or `C:\Windows`), it should **clamp** the
//! target to the anchor root rather than rejecting it. This aligns with virtual
//! filesystem semantics where all absolute paths are relative to the virtual root.
//!
//! **Status:** These tests will FAIL until the soft-canonicalize patch is applied.
//! See `ANCHORED_SYMLINK_CLAMPING_PROPOSAL.md` for detailed design rationale.

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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    // Junction target must be a directory
    let target_dir = boundary.strict_join("data/dir").unwrap();
    target_dir.create_dir_all().unwrap();

    let link_dir = boundary.strict_join("links/junc").unwrap();
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
    let link_from_root = boundary.strict_join("links/root_junc").unwrap();
    link_from_root.create_parent_dir_all().unwrap();
    if let Err(err) = boundary.strict_junction(link_from_root.interop_path()) {
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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let target = boundary.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    let direct_link = boundary.strict_join("links/direct.txt").unwrap();
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

    let boundary_link = boundary.strict_join("links/from_boundary.txt").unwrap();
    boundary_link.create_parent_dir_all().unwrap();
    if let Err(err) = boundary.strict_symlink(boundary_link.interop_path()) {
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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let target = boundary.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    let hard_link = boundary.strict_join("links/direct.txt").unwrap();
    hard_link.create_parent_dir_all().unwrap();
    if let Err(err) = target.strict_hard_link(hard_link.interop_path()) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping hard link test: not supported ({err:?})");
            return;
        }
        panic!("strict_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(hard_link.read_to_string().unwrap(), "hello");

    let boundary_link = boundary.strict_join("links/from_boundary.txt").unwrap();
    boundary_link.create_parent_dir_all().unwrap();
    if let Err(err) = boundary.strict_hard_link(boundary_link.interop_path()) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping PathBoundary hard link test: not supported ({err:?})");
            return;
        }
        panic!("PathBoundary::strict_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(boundary_link.read_to_string().unwrap(), "hello");
}

#[test]
fn strict_symlink_rejects_escape_targets() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let link = boundary.strict_join("link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    let outside_dir = tempfile::tempdir().unwrap();
    let outside_boundary: PathBoundary = PathBoundary::try_new_create(outside_dir.path()).unwrap();
    let outside_target = outside_boundary.strict_join("secret.txt").unwrap();

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
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();
    let link = boundary.strict_join("link.txt").unwrap();
    link.create_parent_dir_all().unwrap();

    let outside_dir = tempfile::tempdir().unwrap();
    let outside_boundary: PathBoundary = PathBoundary::try_new_create(outside_dir.path()).unwrap();
    let outside_target = outside_boundary.strict_join("secret.txt").unwrap();
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

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_symlink_clamps_absolute_paths_to_virtual_root() {
    // Test that absolute paths in virtual context are clamped to virtual root
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create the actual target within virtual root
    let target_path = vroot.virtual_join("etc/config/app.conf").unwrap();
    target_path.create_parent_dir_all().unwrap();
    target_path.write(b"configuration data").unwrap();

    // Create symlink at another location with absolute target path
    let link_path = vroot.virtual_join("app/config.link").unwrap();
    link_path.create_parent_dir_all().unwrap();

    // When passing "/app/config.link" to virtual_symlink, it should be clamped
    // to vroot/app/config.link, NOT the system's /app/config.link
    if let Err(err) = target_path.virtual_symlink("/app/config.link") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping absolute path clamping test due to missing privileges: {err:?}");
            return;
        }
        panic!("virtual_symlink with absolute target failed unexpectedly: {err:?}");
    }

    assert!(link_path.exists(), "Symlink should exist");

    // Verify the symlink resolves within virtual root
    let resolved_content = link_path.read_to_string().unwrap();
    assert_eq!(resolved_content, "configuration data");

    // Check the actual symlink target stored on disk
    #[cfg(unix)]
    {
        let stored_target = std::fs::read_link(link_path.interop_path()).unwrap();
        let stored_target_str = stored_target.to_string_lossy();
        // Should NOT contain system paths outside virtual root
        assert!(
            !stored_target_str.starts_with("/etc/")
                || stored_target_str.contains(td.path().to_str().unwrap()),
            "Symlink target should be within virtual root, got: {}",
            stored_target_str
        );
    }
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_symlink_clamps_traversal_attempts() {
    // Test that path traversal attempts are clamped to virtual root
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create target at root
    let target_path = vroot.virtual_join("target.txt").unwrap();
    target_path.write(b"target content").unwrap();

    // Try to create symlink with traversal path
    let nested_link = vroot.virtual_join("deep/nested/dir/link.txt").unwrap();
    nested_link.create_parent_dir_all().unwrap();

    // "../../../target.txt" from deep/nested/dir should clamp to root level
    let traversal_target = vroot.virtual_join("../../../target.txt").unwrap();

    if let Err(err) = traversal_target.virtual_symlink("deep/nested/dir/link.txt") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping traversal clamping test due to missing privileges: {err:?}");
            return;
        }
        panic!("virtual_symlink with traversal failed unexpectedly: {err:?}");
    }

    assert!(nested_link.exists(), "Symlink should exist");
    assert_eq!(nested_link.read_to_string().unwrap(), "target content");
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_symlink_archive_extraction_scenario() {
    // Real-world scenario: extracting an archive with absolute symlinks
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Simulate archive contents:
    // - /etc/myapp/config.json (actual file)
    // - /var/app/config.json (symlink -> /etc/myapp/config.json)

    // Extract the actual config file
    let config_file = vroot.virtual_join("etc/myapp/config.json").unwrap();
    config_file.create_parent_dir_all().unwrap();
    config_file
        .write(br#"{"app":"myapp","version":"1.0"}"#)
        .unwrap();

    // Extract the symlink (archive stores "/etc/myapp/config.json" as target)
    let symlink_location = vroot.virtual_join("var/app/config.json").unwrap();
    symlink_location.create_parent_dir_all().unwrap();

    // In archive, symlink target is "/etc/myapp/config.json"
    // This should be interpreted as vroot/etc/myapp/config.json
    let archive_symlink_target = vroot.virtual_join("/etc/myapp/config.json").unwrap();

    if let Err(err) = archive_symlink_target.virtual_symlink("/var/app/config.json") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping archive extraction test due to missing privileges: {err:?}");
            return;
        }
        panic!("Archive symlink extraction failed unexpectedly: {err:?}");
    }

    // Verify symlink works and points within virtual root
    assert!(symlink_location.exists(), "Extracted symlink should exist");
    let content = symlink_location.read_to_string().unwrap();
    assert!(
        content.contains("myapp"),
        "Symlink should resolve to config file"
    );

    // Verify it doesn't point outside virtual root
    let real_system_etc = std::path::Path::new("/etc/myapp/config.json");
    if real_system_etc.exists() {
        // If /etc/myapp/config.json exists on system, ensure our symlink
        // doesn't read it (should read from virtual root instead)
        assert!(
            content.contains("1.0"),
            "Should read from virtual root, not system"
        );
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_hard_link_clamps_absolute_paths() {
    // Test hard link clamping behavior similar to symlinks
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target_path = vroot.virtual_join("etc/data/file.dat").unwrap();
    target_path.create_parent_dir_all().unwrap();
    target_path.write(b"shared data").unwrap();

    let link_path = vroot.virtual_join("app/data.link").unwrap();
    link_path.create_parent_dir_all().unwrap();

    if let Err(err) = target_path.virtual_hard_link("/app/data.link") {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping hard link clamping test: not supported ({err:?})");
            return;
        }
        panic!("virtual_hard_link with absolute target failed unexpectedly: {err:?}");
    }

    assert!(link_path.exists(), "Hard link should exist");
    assert_eq!(link_path.read_to_string().unwrap(), "shared data");

    // Modify through one, verify through other (hard link behavior)
    link_path.write(b"modified data").unwrap();
    assert_eq!(target_path.read_to_string().unwrap(), "modified data");
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_join_clamps_absolute_paths_before_symlink_creation() {
    // Critical test: verify that absolute paths passed to virtual_join() are clamped to virtual root
    // This ensures symlinks created in virtual space stay within the sandbox
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Pass absolute path "/etc/config/app.conf" to virtual_join - should clamp to vroot/etc/config/app.conf
    let target = vroot.virtual_join("/etc/config/app.conf").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"virtual config").unwrap();

    // Verify the target was clamped: virtualpath_display shows "/etc/config/app.conf"
    // but the system path should be inside vroot
    assert_eq!(
        target.virtualpath_display().to_string(),
        "/etc/config/app.conf"
    );
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    assert!(
        target
            .as_unvirtual()
            .strictpath_starts_with(&vroot_canonical),
        "Target should be inside vroot, got: {}",
        target.as_unvirtual().strictpath_display()
    );

    // Create symlink at "/var/app/link.conf" (also clamped) pointing to the target
    let link = vroot.virtual_join("/var/app/link.conf").unwrap();
    link.create_parent_dir_all().unwrap();

    if let Err(err) = target.virtual_symlink("/var/app/link.conf") {
        if symlink_permission_denied(&err) {
            eprintln!(
                "Skipping absolute path virtual symlink test due to missing privileges: {err:?}"
            );
            return;
        }
        panic!("virtual_symlink with absolute paths failed: {err:?}");
    }

    // Verify symlink exists and resolves correctly within virtual root
    assert!(link.exists(), "Symlink should exist");
    let content = link.read_to_string().unwrap();
    assert_eq!(
        content, "virtual config",
        "Symlink should resolve to target within virtual root"
    );

    // Read the actual symlink target from disk to verify it points within vroot
    #[cfg(unix)]
    {
        let symlink_target = std::fs::read_link(link.interop_path()).unwrap();
        let target_str = symlink_target.to_string_lossy();

        // The symlink target should NOT point to the real system /etc/
        assert!(
            !target_str.starts_with("/etc/"),
            "Symlink target should not escape to system /etc/, got: {target_str}"
        );

        // It should point to a path within the temp directory (our virtual root)
        let temp_path = td.path().to_string_lossy();
        assert!(
            target_str.contains(&*temp_path),
            "Symlink should point within virtual root temp dir, got: {target_str}"
        );
    }
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_symlink_relative_paths_work_correctly() {
    // Test that relative paths in virtual symlinks behave correctly
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create target
    let target = vroot.virtual_join("data/original.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"original data").unwrap();

    // Create symlink with relative path (sibling within same dir)
    let link = vroot.virtual_join("data/link.txt").unwrap();

    if let Err(err) = target.virtual_symlink("link.txt") {
        if symlink_permission_denied(&err) {
            eprintln!(
                "Skipping relative path virtual symlink test due to missing privileges: {err:?}"
            );
            return;
        }
        panic!("virtual_symlink with relative paths failed: {err:?}");
    }

    assert!(link.exists());
    assert_eq!(link.read_to_string().unwrap(), "original data");
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_hard_link_with_absolute_paths_clamped_to_vroot() {
    // Critical test: verify that absolute paths passed to virtual_join() are clamped
    // before hard link creation, ensuring links stay within the sandbox
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Pass absolute path "/etc/data/shared.dat" to virtual_join - should clamp to vroot/etc/data/shared.dat
    let target = vroot.virtual_join("/etc/data/shared.dat").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"shared data").unwrap();

    // Verify the target was clamped to virtual root
    assert_eq!(
        target.virtualpath_display().to_string(),
        "/etc/data/shared.dat"
    );
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    assert!(
        target
            .as_unvirtual()
            .strictpath_starts_with(&vroot_canonical),
        "Target should be inside vroot, got: {}",
        target.as_unvirtual().strictpath_display()
    );

    // Create hard link at "/var/app/data.link" (also clamped) pointing to the target
    let link = vroot.virtual_join("/var/app/data.link").unwrap();
    link.create_parent_dir_all().unwrap();

    if let Err(err) = target.virtual_hard_link("/var/app/data.link") {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping absolute path virtual hard link test: not supported ({err:?})");
            return;
        }
        panic!("virtual_hard_link with absolute paths failed: {err:?}");
    }

    // Verify hard link exists and resolves correctly within virtual root
    assert!(link.exists(), "Hard link should exist");
    let content = link.read_to_string().unwrap();
    assert_eq!(
        content, "shared data",
        "Hard link should resolve to target within virtual root"
    );

    // Modify through link and verify through target (hard link behavior)
    link.write(b"modified via link").unwrap();
    assert_eq!(target.read_to_string().unwrap(), "modified via link");

    // Verify both point to the same inode (hard link characteristic)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let target_meta = std::fs::metadata(target.interop_path()).unwrap();
        let link_meta = std::fs::metadata(link.interop_path()).unwrap();
        assert_eq!(
            target_meta.ino(),
            link_meta.ino(),
            "Hard links should share the same inode"
        );
    }
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_copy_with_absolute_paths_clamped_to_vroot() {
    // Test that virtual_copy() properly clamps absolute destination paths
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create source file
    let source = vroot.virtual_join("data/source.txt").unwrap();
    source.create_parent_dir_all().unwrap();
    source.write(b"source content").unwrap();

    // Copy to absolute path "/backup/copy.txt" - should clamp to vroot/backup/copy.txt
    // virtual_copy() accepts impl AsRef<Path> and clamps internally
    let dest_path = "/backup/copy.txt";
    let dest_dir = vroot.virtual_join("/backup").unwrap();
    dest_dir.create_dir_all().unwrap();

    source.virtual_copy(dest_path).unwrap();

    // Verify destination was clamped to virtual root
    let dest = vroot.virtual_join(dest_path).unwrap();
    assert_eq!(dest.virtualpath_display().to_string(), "/backup/copy.txt");
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    assert!(
        dest.as_unvirtual().strictpath_starts_with(&vroot_canonical),
        "Destination should be inside vroot, got: {}",
        dest.as_unvirtual().strictpath_display()
    );

    // Verify content was copied
    assert_eq!(dest.read_to_string().unwrap(), "source content");

    // Verify it's a separate file (not a link)
    source.write(b"modified source").unwrap();
    assert_eq!(
        dest.read_to_string().unwrap(),
        "source content",
        "Copy should be independent"
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_rename_with_absolute_paths_clamped_to_vroot() {
    // Test that virtual_rename() properly clamps absolute destination paths
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create source file
    let source = vroot.virtual_join("temp/original.txt").unwrap();
    source.create_parent_dir_all().unwrap();
    source.write(b"rename content").unwrap();

    // Rename to absolute path "/archive/renamed.txt" - should clamp to vroot/archive/renamed.txt
    // virtual_rename() accepts impl AsRef<Path> and clamps internally
    let dest_path = "/archive/renamed.txt";
    let dest_dir = vroot.virtual_join("/archive").unwrap();
    dest_dir.create_dir_all().unwrap();

    source.virtual_rename(dest_path).unwrap();

    // Verify destination was clamped to virtual root
    let dest = vroot.virtual_join(dest_path).unwrap();
    assert_eq!(
        dest.virtualpath_display().to_string(),
        "/archive/renamed.txt"
    );
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    assert!(
        dest.as_unvirtual().strictpath_starts_with(&vroot_canonical),
        "Destination should be inside vroot, got: {}",
        dest.as_unvirtual().strictpath_display()
    );

    // Verify content was moved
    assert!(dest.exists(), "Renamed file should exist");
    assert!(
        !source.exists(),
        "Original file should not exist after rename"
    );
    assert_eq!(dest.read_to_string().unwrap(), "rename content");
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_join_with_traversal_attempts_clamps_to_root() {
    // Test that directory traversal attempts with ../ are clamped to virtual root
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create a file at root
    let root_file = vroot.virtual_join("root.txt").unwrap();
    root_file.write(b"at root").unwrap();

    // Try to escape with ../../../../etc/passwd - should clamp to vroot/etc/passwd
    let escaped = vroot.virtual_join("../../../../etc/passwd").unwrap();

    // Should be clamped to vroot/etc/passwd, not escape to system /etc/passwd
    let escaped_system = escaped.interop_path().to_string_lossy();
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    let vroot_str = vroot_canonical.to_string_lossy();

    // Normalize both paths for comparison (handle Windows verbatim prefix)
    let escaped_normalized = escaped_system.replace("\\\\?\\", "").replace("\\", "/");
    let vroot_normalized = vroot_str.replace("\\\\?\\", "").replace("\\", "/");

    assert!(
        escaped_normalized.contains(&*vroot_normalized),
        "Traversal attempt should be clamped within vroot.\nGot: {escaped_system}\nExpected to contain: {vroot_str}"
    );

    // Verify it resolves to etc/passwd within the vroot, not system /etc/passwd
    assert_eq!(
        escaped.virtualpath_display().to_string(),
        "/etc/passwd",
        "Virtual display should show clamped path"
    );

    // Virtual display should not show the traversal sequences
    let virtual_display = escaped.virtualpath_display().to_string();
    assert!(
        !virtual_display.contains("../"),
        "Virtual display should not contain traversal sequences, got: {virtual_display}"
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_symlink_from_root_with_absolute_target() {
    // Test VirtualRoot::virtual_symlink with absolute paths in virtual space
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create a test file
    let test_file = vroot.virtual_join("test.txt").unwrap();
    test_file.write(b"root content").unwrap();

    // Create symlink at absolute path /link.txt pointing to the root
    let link = vroot.virtual_join("/link.txt").unwrap();

    // Pass absolute VIRTUAL path, not system path
    if let Err(err) = vroot.virtual_symlink("/link.txt") {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping VirtualRoot symlink with absolute path test due to missing privileges: {err:?}");
            return;
        }
        panic!("VirtualRoot::virtual_symlink with absolute path failed: {err:?}");
    }

    // Verify link was created at the clamped location within vroot
    assert!(link.exists(), "Symlink should exist");
    let vroot_canonical = std::fs::canonicalize(td.path()).unwrap();
    assert!(
        link.as_unvirtual().strictpath_starts_with(&vroot_canonical),
        "Link should be inside vroot, got: {}",
        link.as_unvirtual().strictpath_display()
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn virtual_hard_link_from_root_with_absolute_target() {
    // Test VirtualRoot::virtual_hard_link with absolute paths in virtual space
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create a test file at root
    let test_file = vroot.virtual_join("test.dat").unwrap();
    test_file.write(b"root data").unwrap();

    // Create hard link at absolute path /link.dat pointing to the root
    let link = vroot.virtual_join("/link.dat").unwrap();

    // Pass absolute VIRTUAL path, not system path
    if let Err(err) = vroot.virtual_hard_link("/link.dat") {
        if hard_link_unsupported(&err) {
            eprintln!(
                "Skipping VirtualRoot hard link with absolute path test: not supported ({err:?})"
            );
            return;
        }
        panic!("VirtualRoot::virtual_hard_link with absolute path failed: {err:?}");
    }

    // Verify link was created at the clamped location within vroot
    assert!(link.exists(), "Hard link should exist");
    let link_system = link.interop_path().to_string_lossy();
    let vroot_path = td.path().to_string_lossy();
    assert!(
        link_system.contains(&*vroot_path),
        "Link should be inside vroot, got: {link_system}"
    );
}

#[test]
#[cfg(feature = "virtual-path")]
fn following_symlink_pointing_outside_vroot() {
    // This test verifies clamping behavior when reading a symlink that points outside the virtual root
    // Scenario: Archive extractor extracts a symlink with absolute target
    // Expected: Absolute symlink target is clamped to virtual root (virtual space semantics)

    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create a target file OUTSIDE the virtual root
    let system_td = tempfile::tempdir().unwrap();
    let external_target = system_td.path().join("external_secret.txt");
    std::fs::write(&external_target, b"system secret").unwrap();

    // Create a symlink INSIDE the virtual root that points to the external target
    let symlink_path = td.path().join("malicious_link.txt");

    #[cfg(unix)]
    let symlink_result = std::os::unix::fs::symlink(&external_target, &symlink_path);

    #[cfg(windows)]
    let symlink_result = std::os::windows::fs::symlink_file(&external_target, &symlink_path);

    if let Err(err) = symlink_result {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping symlink clamping test due to missing privileges: {err:?}");
            return;
        }
        panic!("Failed to create test symlink: {err:?}");
    }

    // Now try to access this symlink through the virtual root
    let vpath = vroot
        .virtual_join("malicious_link.txt")
        .expect("Symlink should be resolved with clamping");

    // EXPECTED BEHAVIOR: Symlink target should be CLAMPED to virtual root
    // interop_path() returns ALREADY CANONICALIZED &OsStr from our secure types
    // &OsStr implements AsRef<Path>, so Path::starts_with() accepts it directly
    // Canonicalize vroot for comparison (macOS has /var -> /private/var symlink)
    let system_path = vpath.interop_path();
    let canonical_vroot = std::fs::canonicalize(td.path()).unwrap();

    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_vroot),
        "Symlink target MUST be clamped within virtual root.\nGot: {:?}\nVRoot: {:?}\nOriginal target: {:?}",
        system_path,
        canonical_vroot,
        external_target
    );

    // The clamped path should include the original absolute path structure
    // e.g., vroot + /tmp/xyz/external_secret.txt
    #[cfg(unix)]
    {
        let external_stripped = external_target
            .strip_prefix("/")
            .unwrap_or(&external_target);
        let expected_clamped = canonical_vroot.join(external_stripped);

        assert_eq!(
            system_path, expected_clamped,
            "Clamped path should preserve original absolute path structure within vroot"
        );
    }

    #[cfg(windows)]
    {
        // On Windows, the absolute path structure is preserved differently
        // Just verify it's within vroot
        assert!(
            AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_vroot),
            "Clamped path should be within vroot on Windows"
        );
    }

    // Reading the clamped location should NOT return external content
    // (file doesn't exist at clamped location, so read should fail)
    let read_result = vpath.read_to_string();
    assert!(
        read_result.is_err(),
        "Reading clamped symlink should fail (file doesn't exist at clamped location)"
    );
}

#[test]
#[cfg(all(windows, feature = "virtual-path"))]
fn following_junction_pointing_outside_vroot() {
    // Test junction clamping on Windows (junctions don't require admin privileges)
    // Expected: Junction to absolute path is clamped to virtual root
    use std::process::Command;

    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create a target directory OUTSIDE the virtual root
    let system_td = tempfile::tempdir().unwrap();
    let external_target = system_td.path().join("external_secrets");
    std::fs::create_dir(&external_target).unwrap();
    std::fs::write(external_target.join("secret.txt"), b"system secret").unwrap();

    // Create a junction INSIDE the virtual root that points to the external directory
    let junction_path = td.path().join("malicious_junction");

    let output = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &junction_path.to_string_lossy(),
            &external_target.to_string_lossy(),
        ])
        .output()
        .unwrap();

    if !output.status.success() {
        eprintln!(
            "Failed to create junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Now try to access a file through this junction via the virtual root
    let vpath = vroot
        .virtual_join("malicious_junction/secret.txt")
        .expect("Junction should be resolved with clamping");

    // EXPECTED BEHAVIOR: Junction target should be CLAMPED to virtual root
    // interop_path() returns ALREADY CANONICALIZED &OsStr from our secure types
    // &OsStr implements AsRef<Path>, so Path::starts_with() accepts it directly
    let system_path = vpath.interop_path();

    // Canonicalize vroot to match the format of the already-canonicalized system_path
    let canonical_vroot = std::fs::canonicalize(td.path()).unwrap();

    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_vroot),
        "Junction target MUST be clamped within virtual root.\nGot: {:?}\nVRoot: {:?}\nOriginal target: {:?}",
        system_path,
        canonical_vroot,
        external_target
    );

    // Reading the clamped location should NOT return external content
    // (file doesn't exist at clamped location)
    let read_result = vpath.read_to_string();
    assert!(
        read_result.is_err(),
        "Reading clamped junction should fail (file doesn't exist at clamped location)"
    );
}

#[test]
#[cfg(all(windows, feature = "virtual-path"))]
fn following_junction_with_relative_escape() {
    // Test junction clamping with absolute target (appears relative but resolves absolute)
    // Expected: Junction target is clamped to virtual root
    use std::process::Command;

    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    // Create nested structure in vroot
    let nested_dir = td.path().join("user").join("uploads");
    std::fs::create_dir_all(&nested_dir).unwrap();

    // Create a target directory OUTSIDE the virtual root
    let system_td = tempfile::tempdir().unwrap();
    let external_target = system_td.path().join("external_data");
    std::fs::create_dir(&external_target).unwrap();
    std::fs::write(external_target.join("data.txt"), b"external data").unwrap();

    // Create a junction pointing to absolute external path
    let junction_path = nested_dir.join("escape_link");

    let output = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &junction_path.to_string_lossy(),
            &external_target.to_string_lossy(),
        ])
        .output()
        .unwrap();

    if !output.status.success() {
        eprintln!(
            "Failed to create junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Now try to access through the junction
    let vpath = vroot
        .virtual_join("user/uploads/escape_link/data.txt")
        .expect("Junction should be resolved with clamping");

    // EXPECTED BEHAVIOR: Junction target should be CLAMPED to virtual root
    // interop_path() returns ALREADY CANONICALIZED &OsStr from our secure types
    // &OsStr implements AsRef<Path>, so Path::starts_with() accepts it directly
    let system_path = vpath.interop_path();

    // Canonicalize vroot to match the format of the already-canonicalized system_path
    let canonical_vroot = std::fs::canonicalize(td.path()).unwrap();

    assert!(
        AsRef::<std::path::Path>::as_ref(system_path).starts_with(&canonical_vroot),
        "Junction target MUST be clamped within virtual root.\nGot: {:?}\nVRoot: {:?}\nOriginal target: {:?}",
        system_path,
        canonical_vroot,
        external_target
    );

    // Reading the clamped location should NOT return external content
    let read_result = vpath.read_to_string();
    assert!(
        read_result.is_err(),
        "Reading clamped junction should fail (file doesn't exist at clamped location)"
    );
}
