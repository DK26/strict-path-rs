use crate::{PathBoundary, StrictPathError, VirtualRoot};

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

#[test]
fn strict_symlink_helpers_create_links_within_boundary() {
    let td = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new_create(td.path()).unwrap();

    let target = boundary.strict_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"hello").unwrap();

    let direct_link = boundary.strict_join("links/direct.txt").unwrap();
    direct_link.create_parent_dir_all().unwrap();
    if let Err(err) = target.strict_symlink(&direct_link) {
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
    if let Err(err) = boundary.strict_symlink(&boundary_link) {
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
    if let Err(err) = target.strict_hard_link(&hard_link) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping hard link test: not supported ({err:?})");
            return;
        }
        panic!("strict_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(hard_link.read_to_string().unwrap(), "hello");

    let boundary_link = boundary.strict_join("links/from_boundary.txt").unwrap();
    boundary_link.create_parent_dir_all().unwrap();
    if let Err(err) = boundary.strict_hard_link(&boundary_link) {
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
        .strict_symlink(&link)
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
        .strict_hard_link(&link)
        .expect_err("escape hard link should be rejected");
    let inner = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<StrictPathError>());
    assert!(matches!(
        inner,
        Some(StrictPathError::PathEscapesBoundary { .. })
    ));
}

#[test]
fn virtual_symlink_helpers_create_links_within_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target = vroot.virtual_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"ok").unwrap();

    let link = vroot.virtual_join("links/alias.txt").unwrap();
    link.create_parent_dir_all().unwrap();
    if let Err(err) = target.virtual_symlink(&link) {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping virtual symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("virtual_symlink failed unexpectedly: {err:?}");
    }
    assert!(link.exists());

    let root_link = vroot.virtual_join("links/from_root.txt").unwrap();
    root_link.create_parent_dir_all().unwrap();
    if let Err(err) = vroot.virtual_symlink(&root_link) {
        if symlink_permission_denied(&err) {
            eprintln!("Skipping VirtualRoot symlink test due to missing privileges: {err:?}");
            return;
        }
        panic!("VirtualRoot::virtual_symlink failed unexpectedly: {err:?}");
    }
    assert!(root_link.exists());
}

#[test]
fn virtual_hard_link_helpers_create_links_within_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(td.path()).unwrap();

    let target = vroot.virtual_join("data/target.txt").unwrap();
    target.create_parent_dir_all().unwrap();
    target.write(b"ok").unwrap();

    let link = vroot.virtual_join("links/alias.txt").unwrap();
    link.create_parent_dir_all().unwrap();
    if let Err(err) = target.virtual_hard_link(&link) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping virtual hard link test: not supported ({err:?})");
            return;
        }
        panic!("virtual_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(link.read_to_string().unwrap(), "ok");

    let root_link = vroot.virtual_join("links/from_root.txt").unwrap();
    root_link.create_parent_dir_all().unwrap();
    if let Err(err) = vroot.virtual_hard_link(&root_link) {
        if hard_link_unsupported(&err) {
            eprintln!("Skipping VirtualRoot hard link test: not supported ({err:?})");
            return;
        }
        panic!("VirtualRoot::virtual_hard_link failed unexpectedly: {err:?}");
    }
    assert_eq!(root_link.read_to_string().unwrap(), "ok");
}
