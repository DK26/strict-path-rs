//! Tests that verify symlink/junction clamping when following links that point
//! outside the virtual root. These tests validate the clamping behavior introduced
//! in soft-canonicalize 0.4.0 for absolute symlink targets.

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

#[cfg(all(windows, feature = "virtual-path"))]
fn symlink_permission_denied(err: &std::io::Error) -> bool {
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    err.kind() == std::io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD)
}

#[cfg(all(not(windows), feature = "virtual-path"))]
fn symlink_permission_denied(_err: &std::io::Error) -> bool {
    false
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
        "Symlink target MUST be clamped within virtual root.\nGot: {system_path:?}\nVRoot: {canonical_vroot:?}\nOriginal target: {external_target:?}"
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
        "Junction target MUST be clamped within virtual root.\nGot: {system_path:?}\nVRoot: {canonical_vroot:?}\nOriginal target: {external_target:?}"
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
        "Junction target MUST be clamped within virtual root.\nGot: {system_path:?}\nVRoot: {canonical_vroot:?}\nOriginal target: {external_target:?}"
    );

    // Reading the clamped location should NOT return external content
    let read_result = vpath.read_to_string();
    assert!(
        read_result.is_err(),
        "Reading clamped junction should fail (file doesn't exist at clamped location)"
    );
}
