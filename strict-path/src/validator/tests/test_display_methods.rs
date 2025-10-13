#[cfg(test)]
mod display_methods_tests {
    use crate::PathBoundary;
    #[cfg(feature = "virtual-path")]
    use crate::VirtualRoot;

    #[test]
    fn test_restriction_path_strictpath_display() {
        let temp = tempfile::tempdir().unwrap();
        let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

        // Test strictpath_display() returns a proper Display
        let display = temp_dir.strictpath_display();
        let display_string = format!("{display}");

        // Should display the actual system path
        assert!(!display_string.is_empty());
        // On windows, temp paths typically contain "Temp"
        // On unix, they typically contain "tmp"
        #[cfg(windows)]
        assert!(display_string.to_lowercase().contains("temp") || display_string.contains("tmp"));
        #[cfg(unix)]
        assert!(display_string.contains("tmp"));
    }

    #[test]
    #[cfg(feature = "virtual-path")]
    fn test_virtual_root_display() {
        let temp = tempfile::tempdir().unwrap();
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

        // Test as_unvirtual().strictpath_display() returns the actual system path
        let restricted_display = vroot.as_unvirtual().strictpath_display();
        let restricted_display_string = format!("{restricted_display}");
        assert!(!restricted_display_string.is_empty());
        // Should display the actual system path, same as the temp_dir
        #[cfg(windows)]
        assert!(
            restricted_display_string.to_lowercase().contains("temp")
                || restricted_display_string.contains("tmp")
        );
        #[cfg(unix)]
        assert!(restricted_display_string.contains("tmp"));
    }

    #[test]
    #[cfg(feature = "virtual-path")]
    fn test_display_methods_consistency() {
        let temp = tempfile::tempdir().unwrap();
        let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();

        // The temp_dir display and std::path::Path display should be the same
        let temp_dir_display = format!("{}", temp_dir.strictpath_display());
        let path_display = format!("{}", temp.path().canonicalize().unwrap().display());
        assert_eq!(temp_dir_display, path_display);

        // The virtual root restricted display should match the temp_dir display
        let vroot_restricted_display = format!("{}", vroot.as_unvirtual().strictpath_display());
        assert_eq!(temp_dir_display, vroot_restricted_display);
    }

    #[test]
    #[cfg(feature = "virtual-path")]
    fn test_virtualroot_unvirtual() {
        let temp = tempfile::tempdir().unwrap();

        // Test as_unvirtual() for borrowing
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
        let temp_dir_ref = vroot.as_unvirtual();
        let borrowed_display = format!("{}", temp_dir_ref.strictpath_display());
        assert!(!borrowed_display.is_empty());
    }
}
