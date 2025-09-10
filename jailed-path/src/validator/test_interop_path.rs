#[cfg(test)]
mod test_interop_path {
    use crate::{Jail, VirtualRoot};
    use std::path::Path;

    #[test]
    fn test_interop_path_methods() {
        let temp = tempfile::tempdir().unwrap();
        
        // Test Jail::interop_path()
        let jail: Jail = Jail::try_new(temp.path()).unwrap();
        let interop_path_osstr = jail.interop_path();
        let path_from_interop = Path::new(interop_path_osstr);
        
        // Test VirtualRoot::interop_path()
        let vroot: VirtualRoot = VirtualRoot::try_new(temp.path()).unwrap();
        let vroot_interop_path_osstr = vroot.interop_path();
        let vroot_path_from_interop = Path::new(vroot_interop_path_osstr);
        
        // Verify they point to the same location
        assert_eq!(path_from_interop, vroot_path_from_interop);
        
        // Verify they point to the canonical jail root
    assert_eq!(path_from_interop, jail.interop_path());
    assert_eq!(vroot_path_from_interop, vroot.interop_path());
    }
}
