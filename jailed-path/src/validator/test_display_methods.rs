#[cfg(test)]
mod test_display_methods {
    use crate::{Jail, VirtualRoot};

    #[test]
    fn test_jail_jailedpath_display() {
        let temp = tempfile::tempdir().unwrap();
        let jail: Jail = Jail::try_new(temp.path()).unwrap();
        
        // Test jailedpath_display() returns a proper Display
        let display = jail.jailedpath_display();
        let display_string = format!("{}", display);
        
        // Should display the actual system path
        assert!(display_string.len() > 0);
        // On windows, temp paths typically contain "Temp" 
        // On unix, they typically contain "tmp"
        #[cfg(windows)]
        assert!(display_string.to_lowercase().contains("temp") || display_string.contains("tmp"));
        #[cfg(unix)]
        assert!(display_string.contains("tmp"));
    }

    #[test]
    fn test_virtual_root_virtualpath_display() {
        let temp = tempfile::tempdir().unwrap();
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
        
        // Test virtualpath_display() returns "/" for the virtual root
        let virtual_display = vroot.virtualpath_display();
        let virtual_display_string = format!("{}", virtual_display);
        assert_eq!(virtual_display_string, "/");
        
        // Test as_unvirtual().jailedpath_display() returns the actual system path
        let jailed_display = vroot.as_unvirtual().jailedpath_display();
        let jailed_display_string = format!("{}", jailed_display);
        assert!(jailed_display_string.len() > 0);
        // Should display the actual system path, same as the jail
        #[cfg(windows)]
        assert!(jailed_display_string.to_lowercase().contains("temp") || jailed_display_string.contains("tmp"));
        #[cfg(unix)]
        assert!(jailed_display_string.contains("tmp"));
    }

    #[test]
    fn test_display_methods_consistency() {
        let temp = tempfile::tempdir().unwrap();
        let jail: Jail = Jail::try_new(temp.path()).unwrap();
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
        
        // The jail display and std::path::Path display should be the same
        let jail_display = format!("{}", jail.jailedpath_display());
        let path_display = format!("{}", temp.path().canonicalize().unwrap().display());
        assert_eq!(jail_display, path_display);
        
        // The virtual root jailed display should match the jail display
        let vroot_jailed_display = format!("{}", vroot.as_unvirtual().jailedpath_display());
        assert_eq!(jail_display, vroot_jailed_display);
        
        // The virtual root virtual display should always be "/"
        let vroot_virtual_display = format!("{}", vroot.virtualpath_display());
        assert_eq!(vroot_virtual_display, "/");
    }

    #[test]
    fn test_jail_virtualize_and_vroot_unvirtual() {
        let temp = tempfile::tempdir().unwrap();
        let jail: Jail = Jail::try_new(temp.path()).unwrap();
        
        // Test Jail::virtualize() -> VirtualRoot
        let vroot = jail.virtualize();
        assert_eq!(format!("{}", vroot.virtualpath_display()), "/");
        
        // Test VirtualRoot::unvirtual() -> Jail
        let jail2 = vroot.unvirtual();
        let jail_display = format!("{}", jail2.jailedpath_display());
        
        // Should be the same path
        let expected_display = format!("{}", temp.path().canonicalize().unwrap().display());
        assert_eq!(jail_display, expected_display);
        
        // Test as_unvirtual() for borrowing
        let temp2 = tempfile::tempdir().unwrap();
        let vroot2: VirtualRoot = VirtualRoot::try_new(temp2.path()).unwrap();
        let jail_ref = vroot2.as_unvirtual();
        let borrowed_display = format!("{}", jail_ref.jailedpath_display());
        assert!(borrowed_display.len() > 0);
    }
}
