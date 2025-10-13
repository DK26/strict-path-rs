// One-liner VirtualPath demo
//
// Create a virtual root and immediately operate on a user-facing path.

#![cfg(feature = "virtual-path")]

use strict_path::VirtualRoot;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // True one-liner: create nested path with parents and write
    let tmp_dir = tempfile::tempdir()?;
    let vp = VirtualRoot::<()>::try_new(&tmp_dir)?.virtual_join("nested/output.txt")?;
    vp.create_parent_dir_all().and_then(|_| vp.write(b"ok\n"))?;

    // One-liner read with display
    let len = vp.read_to_string()?.len();
    let display = vp.virtualpath_display();
    println!("One-liner VirtualPath: {display} => {len} bytes");

    // Note: temp directory cleanup is automatic
    Ok(())
}
