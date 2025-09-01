//! Static File Server Example
//!
//! This example demonstrates how to build a simple, secure static file server.
//! It uses `VirtualRoot` to create a safe environment for serving files from a
//! designated public directory. Any request attempting to access files outside
//! this directory (e.g., via `../` traversal) will be safely clamped within the jail.
//!
//! This illustrates a primary use case for `jailed-path`: handling untrusted path
//! input from an external source like an HTTP request.
//!
//! ## Usage
//!
//! 1. Run the example: `cargo run --example static_file_server`
//! 2. Open your web browser and navigate to:
//!    - `http://localhost:8080/index.html` (serves the file)
//!    - `http://localhost:8080/` (serves the file, defaults to index.html)
//!    - `http://localhost:8080/../../../../etc/passwd` (attempted attack, serves index.html instead)

use jailed_path::{VirtualPath, VirtualRoot};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;

// The public directory to serve files from.
const PUBLIC_DIR: &str = "example_public_www";

/// Handles an individual client connection.
fn handle_client(mut stream: TcpStream, vroot: &VirtualRoot) {
    let mut buffer = [0; 1024];
    if stream.read(&mut buffer).is_err() {
        return;
    }

    let request = String::from_utf8_lossy(&buffer[..]);
    let request_line = request.lines().next().unwrap_or("");

    // Extract the path from the HTTP request line "GET /path HTTP/1.1"
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .trim_start_matches('/');

    // If the path is empty (e.g., request for "/"), default to "index.html"
    let requested_path = if path.is_empty() { "index.html" } else { path };

    println!("Request for path: {requested_path}");

    // Use the virtual root to safely resolve the requested path.
    // This is the core security step. `virtualpath_join` will contain any
    // traversal attempts within the `PUBLIC_DIR`.
    let virtual_path = match vroot.virtualpath_join(requested_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Path validation error: {e}");
            let response = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Path";
            stream.write_all(response.as_bytes()).ok();
            return;
        }
    };

    println!("Safely resolved virtual path: {virtual_path}");

    let (status_line, contents) = if virtual_path.is_file() {
        match serve_vpath(&virtual_path) {
            Ok(contents) => ("HTTP/1.1 200 OK", contents),
            Err(_) => (
                "HTTP/1.1 500 Internal Server Error",
                "Could not read file.".to_string(),
            ),
        }
    } else {
        ("HTTP/1.1 404 NOT FOUND", "404: Not Found".to_string())
    };

    // Build HTTP response with correct CRLF separators and a Content-Length header
    let response = format!(
        "{}\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        contents.len(),
        contents
    );

    stream.write_all(response.as_bytes()).ok();
    stream.flush().ok();
}

fn serve_vpath(p: &VirtualPath) -> std::io::Result<String> {
    p.read_to_string()
}

/// Sets up the file system environment for the example.
fn setup_environment() -> std::io::Result<()> {
    // Create the public directory and some sample files.
    let public_path = Path::new(PUBLIC_DIR);
    if public_path.exists() {
        fs::remove_dir_all(public_path)?;
    }
    fs::create_dir_all(public_path.join("assets"))?;

    fs::write(
        public_path.join("index.html"),
        "<h1>Welcome!</h1><p>This is the main page.</p><p><a href=\"/assets/style.css\">Stylesheet</a></p>",
    )?;
    fs::write(
        public_path.join("assets/style.css"),
        "body { font-family: sans-serif; background-color: #f0f0f0; }",
    )?;

    println!("Created public directory with index.html and assets/style.css");
    Ok(())
}

fn main() -> std::io::Result<()> {
    // 1. Set up the environment (create public directory and files).
    setup_environment()?;

    // 2. Create a VirtualRoot. This defines the "jail" for our web server.
    let vroot = VirtualRoot::try_new(PUBLIC_DIR).expect("Failed to create virtual root");
    println!(
        "Jailed file server root to: {}",
        vroot.path().to_string_lossy()
    );

    // In CI or when RUN_SERVER is not set, run a quick offline simulation
    if std::env::var("RUN_SERVER").is_err() {
        for path in ["index.html", "assets/style.css", "../../etc/passwd"] {
            match vroot.virtualpath_join(path) {
                Ok(vp) => match serve_vpath(&vp) {
                    Ok(body) => println!("Offline demo: {} -> {} bytes", vp, body.len()),
                    Err(_) => println!("Offline demo: {} not found", vp),
                },
                Err(e) => println!("Offline demo: invalid path '{}': {e}", path),
            }
        }
        fs::remove_dir_all(PUBLIC_DIR).ok();
        return Ok(())
    }

    // 3. Start the TCP listener.
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Server listening on http://127.0.0.1:8080");

    // 4. Accept incoming connections and handle them in separate threads.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let vroot_clone = vroot.clone();
                thread::spawn(move || {
                    handle_client(stream, &vroot_clone);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {e}");
            }
        }
    }

    Ok(())
}



