use anyhow::Result;
use std::fs;
use strict_path::{VirtualPath, VirtualRoot};

// Marker type for our web assets path
#[derive(Clone)]
struct WebAssets;

fn main() -> Result<()> {
    // Create a directory for our web assets and a dummy file
    fs::create_dir_all("web_root/assets")?;
    fs::write("web_root/assets/style.css", "body { color: #333; }")?;
    fs::write("web_root/index.html", "<h1>Welcome!</h1>")?;

    // --- Security Setup ---
    // Create a virtual root for the web assets.
    // This is the ONLY directory from which files can be served.
    let web_root = VirtualRoot::<WebAssets>::try_new("web_root")
        .map_err(|e| anyhow::anyhow!("VirtualRoot error: {e}"))?;

    // --- One-liner Pattern Example ---
    // Quick validation and serving in a single chain
    println!("=== One-liner example ===");
    match web_root
        .virtual_join("/index.html")
        .and_then(|vp| vp.read_to_string())
    {
        Ok(content) => {
            let chars = content.len();
            println!("One-liner served: {chars} chars");
        }
        Err(e) => println!("One-liner failed: {e}"),
    }

    // --- Simulate HTTP Requests ---
    // These would come from a web framework like Axum, Actix, etc.
    let requests = [
        "/index.html",
        "/assets/style.css",
        "/../../../../etc/passwd", // A malicious request
        "/does_not_exist.html",
    ];

    println!("--- Starting Web Server Simulation ---");
    for req_path in &requests {
        println!(
            "
Request: {req_path}"
        );
        match resolve_and_serve(&web_root, req_path) {
            Ok(content) => {
                let bytes = content.len();
                println!("  -> Served {bytes} bytes.");
                // In a real server, you'd send this as the HTTP response body.
            }
            Err(e) => {
                println!("  -> Error: {e}");
                // In a real server, you'd return a 404 or 500 error.
            }
        }
    }
    println!(
        "
--- Simulation Complete ---"
    );

    // Cleanup
    fs::remove_dir_all("web_root")?;

    Ok(())
}

/// Simulates a request handler that serves a file from a virtual root.
///
/// # Arguments
/// * `web_root` - The `VirtualRoot` that enforces the security boundary.
/// * `path` - The requested file path from the user.
///
/// # Returns
/// The file content as bytes, or an error if the file cannot be served.
fn resolve_and_serve(web_root: &VirtualRoot<WebAssets>, path: &str) -> Result<Vec<u8>> {
    println!("  Attempting to resolve: {path}");

    // 1. Validate the requested path against the virtual root.
    // This clamps the path, so `../` traversal is neutralized.
    let virtual_path = web_root
        .virtual_join(path)
        .map_err(|e| anyhow::anyhow!("VirtualRoot error: {e}"))?;

    let vdisp = virtual_path.virtualpath_display();
    let sdisp = virtual_path.as_unvirtual().strictpath_display();
    println!("  -> Virtual path: {vdisp}");
    println!("  -> System path: {sdisp}");

    // 2. Perform serving via a function that requires VirtualPath
    serve_vpath(&virtual_path)
}

fn serve_vpath(path: &VirtualPath<WebAssets>) -> Result<Vec<u8>> {
    if !path.is_file() {
        return Err(anyhow::anyhow!("File not found or is a directory."));
    }
    Ok(path.read()?)
}
