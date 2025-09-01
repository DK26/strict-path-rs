//! A more realistic example of a server that uses multiple jails
//! to manage different security contexts:
//!
//! 1.  **Public Assets**: A jail for serving static files like CSS, JS, and images.
//!     - Marker Type: `PublicAssets`
//!     - Directory: `public/`
//!
//! 2.  **User Uploads**: A jail for handling user-specific file uploads.
//!     - Marker Type: `UserUploads`
//!     - Directory: `user_data/`
//!
//! This example demonstrates how `jailed-path`'s marker types prevent accidental
//! cross-contamination of paths at compile time, ensuring, for example, that a
//! user-generated path can't be used to access a public asset, and vice-versa.

use anyhow::Result;
use jailed_path::{VirtualPath, VirtualRoot};
use std::fs;

// --- Marker Types for Security Contexts ---

/// Marker for the public web assets jail.
struct PublicAssets;

/// Marker for the private user uploads jail.
struct UserUploads;

// --- Simulated Request Handler ---

/// A simulated user for authentication purposes.
struct User {
    id: u32,
    is_authenticated: bool,
}

/// Simulates a request to the server.
enum Request {
    GetAsset(String),
    UploadFile {
        user: User,
        filename: String,
        content: Vec<u8>,
    },
}

/// The main request handler for the server.
///
/// It dispatches requests to the appropriate handlers based on the request type
/// and ensures that the correct jail is used for each security context.
fn handle_request(
    request: Request,
    public_jail: &VirtualRoot<PublicAssets>,
    uploads_jail: &VirtualRoot<UserUploads>,
) -> Result<()> {
    match request {
        Request::GetAsset(path) => {
            println!("[Request] Get public asset: {path}");
            // This request is for a public asset, so we use the `public_jail`.
            let asset_path = public_jail.virtualpath_join(&path)?;

            // Serve via a function that accepts VirtualPath (virtual view supports I/O)
            serve_public_asset(&asset_path)?;
        }
        Request::UploadFile {
            user,
            filename,
            content,
        } => {
            println!("[Request] Upload file: {} for user {}", filename, user.id);
            if !user.is_authenticated {
                return Err(anyhow::anyhow!("User is not authenticated."));
            }

            // This request is for a user upload, so we use the `uploads_jail`.
            // We can create a user-specific subdirectory within the jail.
            let user_upload_path =
                uploads_jail.virtualpath_join(format!("user_{}/{}", user.id, filename))?;

            // Save via a function that accepts VirtualPath (type enforces correct jail)
            save_user_upload(&user_upload_path, &content)?;
        }
    }
    Ok(())
}

// --- Service Functions ---

/// Serves a file from the `PublicAssets` jail.
///
/// This function's signature guarantees that it can only ever be called with a
/// path that has been validated by the `public_jail`.
fn serve_public_asset(asset_path: &VirtualPath<PublicAssets>) -> Result<()> {
    if !asset_path.is_file() {
        return Err(anyhow::anyhow!("Asset not found."));
    }
    let content = asset_path.read_to_string()?;
    println!(
        "  -> Served asset: {}, content: \"{}\"",
        asset_path,
        content.trim()
    );
    Ok(())
}

/// Saves a file to the `UserUploads` jail.
///
/// This function's signature guarantees that it can only ever be called with a
/// path that has been validated by the `uploads_jail`.
fn save_user_upload(upload_path: &VirtualPath<UserUploads>, content: &[u8]) -> Result<()> {
    // Create the parent directory if it doesn't exist.
    upload_path.create_parent_dir_all()?;
    upload_path.write_bytes(content)?;
    println!("  -> Saved upload: {upload_path}");
    if upload_path.exists() {
        println!("  -> Verified: Upload exists on disk.");
    } else {
        println!("  -> Warning: Upload does not exist on disk immediately after writing.");
    }
    Ok(())
}

// --- Main Simulation ---

fn main() -> Result<()> {
    // --- Setup: Create directories and dummy files ---
    fs::create_dir_all("public/css")?;
    fs::write("public/css/style.css", "body { font-family: sans-serif; }")?;
    fs::write("public/index.html", "<h1>Welcome to the site!</h1>")?;
    fs::create_dir_all("user_data")?;

    // --- Security Setup: Create the jails ---
    let public_jail = VirtualRoot::<PublicAssets>::try_new("public")?;
    let uploads_jail = VirtualRoot::<UserUploads>::try_new("user_data")?;

    println!("--- Server Simulation Start ---");

    // --- Simulate a series of requests ---
    let requests = vec![
        Request::GetAsset("index.html".to_string()),
        Request::GetAsset("css/style.css".to_string()),
        Request::GetAsset("../../../etc/passwd".to_string()), // Malicious request
        Request::UploadFile {
            user: User {
                id: 101,
                is_authenticated: true,
            },
            filename: "profile.txt".to_string(),
            content: b"User 101 data".to_vec(),
        },
        Request::UploadFile {
            user: User {
                id: 102,
                is_authenticated: false,
            },
            filename: "data.bin".to_string(),
            content: b"Should not be written".to_vec(),
        },
    ];

    for request in requests {
        if let Err(e) = handle_request(request, &public_jail, &uploads_jail) {
            println!("  -> Error: {e}");
        }
        println!("--------------------");
    }

    println!("--- Simulation Complete ---");

    // --- Cleanup ---
    fs::remove_dir_all("public").ok();
    fs::remove_dir_all("user_data").ok();
    Ok(())
}



