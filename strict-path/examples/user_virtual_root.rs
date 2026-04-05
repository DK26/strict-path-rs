// Per-user VirtualRoot example
//
// Map a user_id to a VirtualRoot<UserSpace>, isolating each user under
// their own directory. All user-visible paths are virtual ("/docs/x.txt").
// I/O happens via VirtualPath methods; no shared StrictPath namespace.
//
// The second section shows validating untrusted filenames from external
// sources (HTTP requests, form fields, CLI args) through virtual_join().

#![cfg(feature = "virtual-path")]

use strict_path::{VirtualPath, VirtualRoot};

#[derive(Clone, Copy)]
struct UserSpace;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Suppose you discovered/created a per-user directory externally,
    // e.g., from config, DB, or after auth. You now create a VirtualRoot
    // anchored to that directory and mark it with UserSpace directly.
    let tmp = tempfile::tempdir()?; // demo root

    // --- Section 1: Standard virtual root usage ---

    // For a given user_id, derive their dedicated directory
    let user_id = "user_42";
    let user_dir = tmp.path().join(user_id);

    // Create a VirtualRoot anchored at user_dir
    let vroot: VirtualRoot<UserSpace> = VirtualRoot::try_new_create(&user_dir)?;

    // Write a doc in the user's virtual space
    let doc: VirtualPath<UserSpace> = vroot.virtual_join("docs/welcome.txt")?;
    doc.create_parent_dir_all()?;
    doc.write("hello, virtual user space\n")?;

    // Read it back and show the virtual path (forward-slash rooted)
    let body = doc.read_to_string()?;
    let display = doc.virtualpath_display();
    println!("user_id={user_id}, path={}, bytes={} ", display, body.len());

    // List files under a virtual directory using virtual_read_dir for auto-validated iteration
    let docs_dir: VirtualPath<UserSpace> = vroot.virtual_join("docs")?;
    if docs_dir.exists() && docs_dir.is_dir() {
        let mut names = Vec::new();
        // virtual_read_dir returns already-validated VirtualPath entries!
        for entry in docs_dir.virtual_read_dir()? {
            let child = entry?;
            // Each child is a VirtualPath - no manual re-join needed
            names.push(child.virtualpath_display().to_string());
        }
        names.sort();
        println!("docs: {}", names.join(", "));
    }

    // --- Section 2: Validating untrusted external filenames ---
    //
    // In a real SaaS app, the filename below comes from an HTTP request body,
    // a form field, or a CLI argument — never a hardcoded constant.
    println!("\nValidating untrusted upload filenames (HTTP request / form field):");

    // Filenames as received from the network. In production:
    //   let uploaded_filename = request.form_field("filename");
    let upload_requests: &[&str] = &[
        // From HTTP multipart upload, API body, or form field
        "notes/meeting.txt",
        "../../etc/shadow",         // traversal attack — must be blocked
        "../other_user/secret.txt", // escape to another user's dir — must be blocked
        "reports/2024/q4.csv",      // valid nested path
    ];

    for uploaded_filename in upload_requests {
        // uploaded_filename is untrusted — virtual_join() validates and clamps it
        match vroot.virtual_join(uploaded_filename) {
            Ok(safe_upload_path) => {
                safe_upload_path.create_parent_dir_all()?;
                safe_upload_path.write(b"file content")?;
                println!(
                    "  OK      '{}' -> {}",
                    uploaded_filename,
                    safe_upload_path.virtualpath_display()
                );
            }
            Err(e) => {
                // virtual_join clamps escapes rather than erroring in most cases,
                // but explicit errors can still arise (e.g., I/O failure).
                println!("  ERROR   '{}': {e}", uploaded_filename);
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "virtual-path"))]
fn main() {
    eprintln!("This example requires the 'virtual-path' feature.");
    eprintln!("Run with: cargo run --example user_virtual_root --features virtual-path");
}
