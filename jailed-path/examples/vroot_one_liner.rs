// One-liner VirtualPath demo
//
// Create a virtual root and immediately operate on a user-facing path.

use jailed_path::{VirtualPath, VirtualRoot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Validate a virtual path and write in one chain
    let vroot: VirtualRoot = VirtualRoot::try_new_create("quick/vroot")?;
    let vp: VirtualPath = vroot.virtualpath_join("nested/output.txt")?;

    // Ensure parent exists, then write
    vp.create_parent_dir_all()?;
    vp.write_bytes(b"ok\n")?;

    let content = vp.read_to_string()?;
    println!("One-liner VirtualPath: {} => {} bytes", vp, content.len());

    // Cleanup
    std::fs::remove_dir_all("quick").ok();
    Ok(())
}
