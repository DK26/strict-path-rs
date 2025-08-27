use anyhow::Result;
use jailed_path::VirtualRoot;
use std::fs;

// Marker type for our web assets jail
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
    let web_jail = VirtualRoot::<WebAssets>::try_new("web_root")
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

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
        match serve_file(&web_jail, req_path) {
            Ok(content) => {
                println!("  -> Served {} bytes.", content.len());
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
/// * `jail` - The `VirtualRoot` that enforces the security boundary.
/// * `path` - The requested file path from the user.
///
/// # Returns
/// The file content as bytes, or an `io::Error` if the file cannot be served.
fn serve_file(jail: &VirtualRoot<WebAssets>, path: &str) -> Result<Vec<u8>> {
    println!("  Attempting to resolve: {path}");

    // 1. Validate the requested path against the virtual root.
    // This clamps the path, so `../` traversal is neutralized.
    let virtual_path = jail
        .try_path_virtual(path)
        .map_err(|e| anyhow::anyhow!("Jail error: {e}"))?;

    println!("  -> Virtual path: {virtual_path}");
    println!("  -> System path: {}", virtual_path.systempath_to_string());

    // 2. Check if the resolved path actually exists and is a file.
    if !virtual_path.is_file() {
        return Err(anyhow::anyhow!("File not found or is a directory."));
    }

    // 3. Read the file content.
    // We can now safely perform the I/O operation.
    Ok(virtual_path.read_bytes()?)
}
