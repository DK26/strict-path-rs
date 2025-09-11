//! VirtualPath-Only Server Simulation
//!
//! Demonstrates serving files using only `VirtualPath` for I/O.
//! - All user input is validated via `VirtualRoot::virtual_join(..)`.
//! - Serving functions accept `&VirtualPath<_>` so the compiler enforces correct usage.

use strict_path::{VirtualPath, VirtualRoot};
use std::fs;

#[derive(Clone)]
struct Assets;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prepare a tiny assets tree
    fs::create_dir_all("vp_assets/css")?;
    fs::write("vp_assets/index.html", "<h1>Hi</h1>")?;
    fs::write("vp_assets/css/app.css", "body{color:#333}")?;

    // Create a virtual root for serving assets
    let vroot: VirtualRoot<Assets> = VirtualRoot::try_new_create("vp_assets")?;

    // Simulate requests (including an attack)
    let requests = ["/index.html", "/css/app.css", "/../../etc/passwd"];

    for req in requests {
        match vroot.virtual_join(req) {
            Ok(vp) => {
                let display = vp.virtualpath_display();
                println!("-> {display}"); // Virtual root path (user-facing)
                match serve_asset(&vp) {
                    Ok(body) => {
                        let bytes = body.len();
                        println!("  200 OK ({bytes} bytes)");
                    }
                    Err(_) => println!("  404 Not Found"),
                }
            }
            Err(e) => println!("Invalid path: {e}"),
        }
    }

    fs::remove_dir_all("vp_assets").ok();
    Ok(())
}

fn serve_asset(p: &VirtualPath<Assets>) -> std::io::Result<String> {
    if !p.is_file() {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    p.read_to_string()
}

