use jailed_path::{Jail, VirtualRoot};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    
    // Test Jail::interop_path()
    let jail = Jail::try_new(temp.path())?;
    let interop_path_osstr = jail.interop_path();
    let path_from_interop = Path::new(interop_path_osstr);
    println!("Jail interop_path works: {}", path_from_interop.display());
    
    // Test VirtualRoot::interop_path()
    let vroot = VirtualRoot::try_new(temp.path())?;
    let vroot_interop_path_osstr = vroot.interop_path();
    let vroot_path_from_interop = Path::new(vroot_interop_path_osstr);
    println!("VirtualRoot interop_path works: {}", vroot_path_from_interop.display());
    
    // Verify they point to the same location
    assert_eq!(path_from_interop, vroot_path_from_interop);
    println!("✓ Both interop_path() methods return the same result");
    
    Ok(())
}
