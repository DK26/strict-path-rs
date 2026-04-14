// One-liner VirtualPath demo
//
// Create a virtual root and immediately operate on a user-facing path.
// The path segment comes from the first CLI argument (or defaults to "nested/output.txt"),
// demonstrating that virtual_join() validates and contains untrusted external input.
//
// Run with: cargo run --example vroot_one_liner --features virtual-path -- <path>

#![cfg(feature = "virtual-path")]

use strict_path::VirtualRoot;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path segment from external input (user input, form data, API request, etc.)
    let user_path: String = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nested/output.txt".to_owned());

    // True one-liner: create nested path with parents and write
    let tmp_dir = tempfile::tempdir()?;
    let vp = VirtualRoot::<()>::try_new(&tmp_dir)?.virtual_join(&user_path)?;
    vp.create_parent_dir_all().and_then(|_| vp.write(b"ok\n"))?;

    // One-liner read with display
    let len = vp.read_to_string()?.len();
    let display = vp.virtualpath_display();
    println!("One-liner VirtualPath: {display} => {len} bytes");

    // Note: temp directory cleanup is automatic
    Ok(())
}
