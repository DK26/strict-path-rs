#[cfg(unix)]
mod symlink_resolution {
    use crate::validator::virtual_root::VirtualRoot;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn symlink_escape_rejected_via_virtual() {
        use std::os::unix::fs as unix_fs;

        // Jail root
        let jail_td = tempfile::tempdir().unwrap();
        let jail_root = jail_td.path();

        // Create an outside directory separate from the jail
        let outside_td = tempfile::tempdir().unwrap();
        let outside_dir = outside_td.path();

        // Inside the jail, create a symlink that points outside
        let out_link = jail_root.join("out");
        unix_fs::symlink(outside_dir, &out_link).unwrap();

        // Build virtual root from the jail
        let vroot: VirtualRoot = VirtualRoot::try_new(jail_root).unwrap();

        // Attempt to traverse using symlink then parent
        // Canonicalization resolves the symlink first, then applies `..`, which
        // would place us outside the jail; this must be rejected.
        let err = vroot
            .virtual_join("out/../etc/passwd")
            .expect_err("escape via symlink should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("boundary") || msg.contains("escape"),
            "error message should indicate boundary escape: {msg}"
        );
    }

    #[test]
    fn symlink_inside_ok_via_virtual() {
        use std::os::unix::fs as unix_fs;

        let td = tempfile::tempdir().unwrap();
        let jail_root = td.path();

        // Create a real directory and file inside the jail
        let data = jail_root.join("data");
        fs::create_dir_all(&data).unwrap();
        let file_path = data.join("file.txt");
        fs::write(&file_path, b"ok").unwrap();

        // Create a symlink to the internal directory
        let link = jail_root.join("ln");
        unix_fs::symlink(&data, &link).unwrap();

        let vroot: VirtualRoot = VirtualRoot::try_new(jail_root).unwrap();

        // Path uses symlink and parent, but remains within the jail after resolution
        let vp = vroot
            .virtual_join("ln/../ln/file.txt")
            .expect("path should remain in jail");

        // Virtual display is canonicalized then cut: expect rooted path to the real file
        assert_eq!(vp.virtualpath_to_string_lossy(), "/data/file.txt");
    }

    #[test]
    fn absolute_input_clamps_to_virtual_root() {
        let td = tempfile::tempdir().unwrap();
        let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();

        let vp = vroot
            .virtual_join("/etc/hosts")
            .expect("absolute inputs clamp to virtual root, then validate");

        // Absolute inputs clamp to the virtual root view
        assert_eq!(vp.virtualpath_to_string_lossy(), "/");
    }
}
