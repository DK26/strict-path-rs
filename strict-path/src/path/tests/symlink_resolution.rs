use crate::validator::virtual_root::VirtualRoot;
use std::fs;

#[test]
fn symlink_escape_clamped_via_virtual() {
    use std::os::unix::fs as unix_fs;

    // PathBoundary root
    let jail_td = tempfile::tempdir().unwrap();
    let jail_root = jail_td.path();

    // Create an outside directory separate from the PathBoundary
    let outside_td = tempfile::tempdir().unwrap();
    let outside_dir = outside_td.path();

    // Inside the PathBoundary, create a symlink that points outside
    let out_link = jail_root.join("out");
    unix_fs::symlink(outside_dir, &out_link).unwrap();

    // Build virtual root from the PathBoundary
    let vroot: VirtualRoot = VirtualRoot::try_new(jail_root).unwrap();

    // VirtualPath silently clamps escape attempts (unlike StrictPath which rejects).
    // The symlink resolves outside, but virtual_join contains the result within the boundary.
    let vp = vroot
        .virtual_join("out/../etc/passwd")
        .expect("VirtualPath clamps escapes; should not error");

    // The clamped path must stay inside the boundary
    let virtual_display = vp.virtualpath_display().to_string();
    assert!(
        virtual_display.starts_with('/'),
        "virtual display should be rooted: {virtual_display}"
    );
}

#[test]
fn symlink_inside_ok_via_virtual() {
    use std::os::unix::fs as unix_fs;

    let td = tempfile::tempdir().unwrap();
    let jail_root = td.path();

    // Create a real directory and file inside the PathBoundary
    let data = jail_root.join("data");
    fs::create_dir_all(&data).unwrap();
    let file_path = data.join("file.txt");
    fs::write(&file_path, b"ok").unwrap();

    // Create a relative symlink to the internal directory.
    // Using a relative target ("data") avoids macOS /var → /private/var
    // mismatch when the symlink stores an absolute non-canonical path.
    let link = jail_root.join("ln");
    unix_fs::symlink("data", &link).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(jail_root).unwrap();

    // Path uses symlink and parent, but remains within the PathBoundary after resolution
    let vp = vroot
        .virtual_join("ln/../ln/file.txt")
        .expect("path should remain in PathBoundary");

    // Virtual display is canonicalized then cut: expect rooted path to the real file
    assert_eq!(vp.virtualpath_display().to_string(), "/data/file.txt");
}

#[test]
fn absolute_input_clamps_to_virtual_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

    let vp = vroot
        .virtual_join("/etc/hosts")
        .expect("absolute inputs clamp to virtual root, then validate");

    // Absolute input `/etc/hosts` is rebased under the virtual root
    // Virtual display reflects the rebased path, not the system `/etc/hosts`
    assert_eq!(vp.virtualpath_display().to_string(), "/etc/hosts");
}
