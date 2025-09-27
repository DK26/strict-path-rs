// Per-user VirtualRoot example
//
// Map a user_id to a VirtualRoot<UserSpace>, isolating each user under
// their own directory. All user-visible paths are virtual ("/docs/x.txt").
// I/O happens via VirtualPath methods; no shared StrictPath namespace.

use strict_path::{VirtualPath, VirtualRoot};

#[derive(Clone, Copy)]
struct UserSpace;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Suppose you discovered/created a per-user directory externally,
    // e.g., from config, DB, or after auth. You now create a VirtualRoot
    // anchored to that directory and rebrand it to UserSpace.
    let tmp = tempfile::tempdir()?; // demo root

    // For a given user_id, derive their dedicated directory
    let user_id = "user_42";
    let user_dir = tmp.path().join(user_id);

    // Create a VirtualRoot anchored at user_dir
    let vroot: VirtualRoot<UserSpace> =
        VirtualRoot::<UserSpace>::try_new_create(&user_dir)?.rebrand();

    // Write a doc in the user's virtual space
    let doc: VirtualPath<UserSpace> = vroot.virtual_join("docs/welcome.txt")?;
    doc.create_parent_dir_all()?;
    doc.write("hello, virtual user space\n")?;

    // Read it back and show the virtual path (forward-slash rooted)
    let body = doc.read_to_string()?;
    let display = doc.virtualpath_display();
    println!("user_id={user_id}, path={}, bytes={} ", display, body.len());

    // List files under a virtual directory
    let docs = vroot.virtual_join("docs")?;
    if docs.exists() && docs.is_dir() {
        let mut names = Vec::new();
        if let Ok(entries) = docs.read_dir() {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    // Re-join to keep guarantees
                    if let Ok(child) = docs.virtual_join(name) {
                        names.push(child.virtualpath_display().to_string());
                    }
                }
            }
        }
        names.sort();
        println!("docs: {}", names.join(", "));
    }

    Ok(())
}
