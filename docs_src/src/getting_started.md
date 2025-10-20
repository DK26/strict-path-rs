# Getting Started with strict-path

## What is strict-path?

Have you ever worried about users trying to access files they shouldn't? Like when someone enters `../../../etc/passwd` to try to escape from a safe directory? That's called a "directory traversal" attack, and it's surprisingly common.

**strict-path strictly enforces path boundaries to prevent directory traversal attacks.** It creates safe boundaries that paths cannot escape from. It comes in two modes: StrictPath (via PathBoundary) which detects and rejects escape attempts, and VirtualPath (via VirtualRoot) which contains and redirects escape attempts within a virtual sandbox.

## Why Should You Care?

Directory traversal vulnerabilities are everywhere:
- Web applications where users upload files
- CLI tools that accept file paths as arguments  
- Any application that processes user-provided paths
- Systems that extract archives (ZIP files, etc.)

Getting path security wrong can expose your entire filesystem to attackers. With strict-path, the Rust compiler helps ensure you can't make these mistakes.

## Your First PathBoundary

Let's start with a simple example. Say you're building a web app where users can upload and download their files, but you want to keep them contained in a specific directory:

```rust
use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a path boundary in the "user_files" directory
    // This creates the directory if it doesn't exist
    let user_files_dir = PathBoundary::try_new_create("user_files")?;

    // Now any path we validate through this path boundary will be contained
    // within the "user_files" directory

    // Simulate user input from HTTP request, CLI args, form data, etc.
    let user_input = "documents/report.txt"; // In real code: from request.form_data()
    
    // ✅ This is SAFE - validates and creates "user_files/documents/report.txt"
    let report = user_files_dir.strict_join(user_input)?;
    report.create_parent_dir_all()?;
    report.write("Quarterly report contents")?;

    // ❌ This would FAIL - can't escape the path boundary!
    let attack_input = "../../../etc/passwd"; // Attacker-controlled input
    // let _bad = user_files_dir.strict_join(attack_input)?; // Error!

    let display = report.strictpath_display();
    println!("Safe path: {display}");

    Ok(())
}
```

## What Just Happened?

1. **Created a path boundary**: `PathBoundary::try_new_create("user_files")` sets up a safe boundary
2. **Validated a path**: `path_boundary.strict_join("documents/report.txt")` checks the path is safe
3. **Got protection**: Any attempt to escape the path boundary (like `../../../etc/passwd`) fails immediately

The magic is that once you have a `StrictPath`, you *know* it's safe. The type system guarantees it.

## Working with Strict Paths

Once you have a `StrictPath`, you can use it for file operations:

```rust
use strict_path::PathBoundary;

fn save_user_file() -> Result<(), Box<dyn std::error::Error>> {
    let uploads_dir = PathBoundary::try_new_create("uploads")?;

    // User wants to save to "my-document.txt"
    let user_input = "my-document.txt"; // untrusted
    let safe_path = uploads_dir.strict_join(user_input)?;

    // Write some content safely using built-in helpers
    safe_path.write("Hello, world!")?;

    // Read it back
    let content = safe_path.read_to_string()?;
    println!("File contains: {content}");

    Ok(())
}
```

## Type Safety: The Secret Sauce

Here's where strict-path gets really clever. You can write functions that *only* accept safe paths:

```rust
use strict_path::{PathBoundary, StrictPath};

// This function can ONLY be called with safe paths
fn process_user_file(path: &StrictPath) -> std::io::Result<String> {
    // We know this path is safe - no need to validate again
    path.read_to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBoundary::try_new_create("safe_area")?;
    let user_data = data_dir.strict_join("user-data.txt")?;

    // ✅ This works - user_data is a StrictPath
    let _content = process_user_file(&user_data)?;

    // ❌ This won't compile - can't pass an unsafe path!
    // let unsafe_path = std::path::Path::new("/etc/passwd");
    // let _content = process_user_file(unsafe_path); // Compilation error!

    Ok(())
}
```

This means once you set up your path boundaries correctly, the compiler prevents you from accidentally using unsafe paths.

## Virtual Paths: User-Friendly Sandboxes

Sometimes you want to give users the illusion that they have their own private filesystem, starting from `/`. That's what `VirtualPath` is for:

```rust
use strict_path::VirtualRoot;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a virtual root that maps to "user_123_files" on disk
    let vroot = VirtualRoot::try_new_create("user_123_files")?;

    // User thinks they're working from "/"
    let vpath = vroot.virtual_join("/documents/my-file.txt")?;

    // But it actually maps to "user_123_files/documents/my-file.txt"
    let user_sees = vpath.virtualpath_display();
    let system_path = vpath.as_unvirtual().strictpath_display();
    println!("User sees: {user_sees}");
    println!("Actually stored at: {system_path}");

    Ok(())
}
```

This is perfect for multi-user applications where each user should feel like they have their own filesystem.

### The Critical Difference: Symlink Behavior

**`StrictPath`** validates paths and **rejects** anything that escapes:
- User input `"../../../etc/passwd"` → ❌ Error
- Symlink pointing to `/etc/passwd` → ❌ Error (if outside boundary)

**`VirtualPath`** implements true virtual filesystem and **clamps** absolute paths:
- User input `"../../../etc/passwd"` → ✅ Clamped to `vroot/etc/passwd`
- Symlink pointing to `/etc/passwd` → ✅ Clamped to `vroot/etc/passwd`

This makes `VirtualPath` perfect for:
- 🗜️ Archive extraction (malicious entries are safely clamped)
- 🏢 Multi-tenant systems (users can't escape their sandbox)
- 📦 Container-like environments (absolute paths stay inside)

**Rule of thumb:** Use `StrictPath` for system resources (explicit validation), use `VirtualPath` for user sandboxes (graceful containment).

## API Summary

That's really all you need to know! The core API is simple:

### Creating Safe Boundaries
- `PathBoundary::try_new(path)` - Use existing directory as path boundary (fails if not found)
- `PathBoundary::try_new_create(path)` - Create directory if needed (for setup/initialization)
- `VirtualRoot::try_new(path)` - Virtual filesystem root (expects existing directory)
- `VirtualRoot::try_new_create(path)` - Create virtual root if needed (for user storage)

### Validating Paths
- `path_boundary.strict_join(user_path)` - Returns `StrictPath` or error
- `vroot.virtual_join(user_path)` - Returns `VirtualPath` or error

### Using Safe Paths
- Both `StrictPath` and `VirtualPath` work with standard file operations
- They implement `.interop_os()` so you can pass them to `fs::read`, `fs::write`, etc.
- The type system prevents using unvalidated paths

## Common Patterns

### Web File Upload

```rust
use strict_path::{PathBoundary, StrictPath};

// Public API: callers pass untrusted filename; we validate, then call an internal helper
fn handle_file_upload(filename: &str, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let uploads_dir = PathBoundary::try_new_create("uploads")?;
    let dest = uploads_dir.strict_join(filename)?; // ✅ Validate external input
    save_uploaded(&dest, content) // Internal API enforces &StrictPath in signature
}

// Internal helper encodes guarantee in its signature
fn save_uploaded(path: &StrictPath, content: &[u8]) -> std::io::Result<()> {
    path.create_parent_dir_all()?;
    path.write(content)
}
```

### Configuration Files

```rust
use strict_path::{PathBoundary, VirtualRoot};

// Prefer signatures that encode guarantees explicitly: pass the boundary and the untrusted name
fn load_config(config_dir: &PathBoundary, config_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    config_dir.strict_join(config_name)?.read_to_string() // ✅ Validated
}

fn setup_user_storage(user_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Create a user-facing virtual root for UI flows
    let vroot = VirtualRoot::try_new_create(format!("users/{user_id}"))?;
    let docs = vroot.virtual_join("documents")?;
    docs.create_dir_all()?;
    Ok(())
}
```

## What's Next?

- **Real-World Examples**: See complete applications using strict-path
- **Understanding Type-History**: Learn how the internal security works (for contributors)
- **Choosing Canonicalized vs Lexical**: See Ergonomics → Choosing Canonicalized vs Lexical for performance vs safety trade-offs

The key rule: **always validate external paths through a path boundary before using them**. Whether it's user input, configuration files, or data from external sources - if you didn't create the path yourself, join it to a path boundary first!
