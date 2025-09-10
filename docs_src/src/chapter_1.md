# Getting Started with jailed-path

## What is jailed-path?

Have you ever worried about users trying to access files they shouldn't? Like when someone enters `../../../etc/passwd` to try to escape from a safe directory? That's called a "directory traversal" attack, and it's surprisingly common.

**jailed-path** solves this problem by creating "jails" - safe boundaries that paths cannot escape from. Think of it like a sandbox for file paths.

## Why Should You Care?

Directory traversal vulnerabilities are everywhere:
- Web applications where users upload files
- CLI tools that accept file paths as arguments  
- Any application that processes user-provided paths
- Systems that extract archives (ZIP files, etc.)

Getting path security wrong can expose your entire filesystem to attackers. With jailed-path, the Rust compiler helps ensure you can't make these mistakes.

## Your First Jail

Let's start with a simple example. Say you're building a web app where users can upload and download their files, but you want to keep them contained in a specific directory:

```rust
use jailed_path::Jail;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a jail in the "user_files" directory
    // This creates the directory if it doesn't exist
    let jail = Jail::try_new_create("user_files")?;
    
    // Now any path we validate through this jail will be contained
    // within the "user_files" directory
    
    // This is SAFE - creates "user_files/documents/report.txt"
    let safe_path = jail.jailed_join("documents/report.txt")?;
    
    // This would FAIL - can't escape the jail!
    // let bad_path = jail.jailed_join("../../../etc/passwd")?; // Error!
    
    println!("Safe path: {}", safe_path.as_path().display());
    
    Ok(())
}
```

## What Just Happened?

1. **Created a jail**: `Jail::try_new_create("user_files")` sets up a safe boundary
2. **Validated a path**: `jail.jailed_join("documents/report.txt")` checks the path is safe
3. **Got protection**: Any attempt to escape the jail (like `../../../etc/passwd`) fails immediately

The magic is that once you have a `JailedPath`, you *know* it's safe. The type system guarantees it.

## Working with Jailed Paths

Once you have a `JailedPath`, you can use it for file operations:

```rust
use jailed_path::Jail;
use std::fs;

fn save_user_file() -> Result<(), Box<dyn std::error::Error>> {
    let jail = Jail::try_new_create("uploads")?;
    
    // User wants to save to "my-document.txt"
    let user_input = "my-document.txt";
    let safe_path = jail.jailed_join(user_input)?;
    
    // Write some content safely
    fs::write(&safe_path, "Hello, world!")?;
    
    // Read it back
    let content = fs::read_to_string(&safe_path)?;
    println!("File contains: {}", content);
    
    Ok(())
}
```

## Type Safety: The Secret Sauce

Here's where jailed-path gets really clever. You can write functions that *only* accept safe paths:

```rust
use jailed_path::JailedPath;
use std::fs;

// This function can ONLY be called with safe paths
fn process_user_file(path: &JailedPath) -> Result<String, std::io::Error> {
    // We know this path is safe - no need to validate again
    fs::read_to_string(path)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jail = Jail::try_new_create("safe_area")?;
    let safe_path = jail.jailed_join("user-data.txt")?;
    
    // This works - safe_path is a JailedPath
    let content = process_user_file(&safe_path)?;
    
    // This won't compile - can't pass an unsafe path!
    // let unsafe_path = std::path::Path::new("/etc/passwd");
    // let content = process_user_file(unsafe_path); // Compilation error!
    
    Ok(())
}
```

This means once you set up your jails correctly, the compiler prevents you from accidentally using unsafe paths.

## Virtual Paths: User-Friendly Sandboxes

Sometimes you want to give users the illusion that they have their own private filesystem, starting from `/`. That's what `VirtualPath` is for:

```rust
use jailed_path::VirtualRoot;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a virtual root that maps to "user_123_files" on disk
    let vroot = VirtualRoot::try_new_create("user_123_files")?;
    
    // User thinks they're working from "/"
    let user_path = vroot.virtual_join("/documents/my-file.txt")?;
    
    // But it actually maps to "user_123_files/documents/my-file.txt"
    println!("User sees: /documents/my-file.txt");
    println!("Actually stored at: {}", user_path.as_path().display());
    
    Ok(())
}
```

This is perfect for multi-user applications where each user should feel like they have their own filesystem.

## API Summary

That's really all you need to know! The core API is simple:

### Creating Safe Boundaries
- `Jail::try_new(path)` - Use existing directory as jail (fails if not found)
- `Jail::try_new_create(path)` - Create directory if needed (for setup/initialization)
- `VirtualRoot::try_new(path)` - Virtual filesystem root (expects existing directory)
- `VirtualRoot::try_new_create(path)` - Create virtual root if needed (for user storage)

### Validating Paths
- `jail.jailed_join(user_path)` - Returns `JailedPath` or error
- `vroot.virtual_join(user_path)` - Returns `VirtualPath` or error

### Using Safe Paths
- Both `JailedPath` and `VirtualPath` work with standard file operations
- They implement `AsRef<Path>` so you can pass them to `fs::read`, `fs::write`, etc.
- The type system prevents using unvalidated paths

## Common Patterns

### Web File Upload

```rust
use jailed_path::Jail;

fn handle_file_upload(filename: &str, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let uploads_jail = Jail::try_new_create("uploads")?;
    let safe_path = uploads_jail.jailed_join(filename)?;
    std::fs::write(&safe_path, content)?;
    Ok(())
}
```

### Configuration Files

```rust
use jailed_path::Jail;

fn load_config(config_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let config_jail = Jail::try_new("config")?;  // Expect config dir to exist
    let config_path = config_jail.jailed_join(config_name)?;
    let content = std::fs::read_to_string(&config_path)?;
    Ok(content)
}

fn setup_user_storage(user_id: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Create user directory structure if it doesn't exist
    let user_jail = Jail::try_new_create(&format!("users/{}", user_id))?;
    let documents = user_jail.jailed_join("documents")?;
    std::fs::create_dir_all(&documents)?;
    Ok(())
}
```

## What's Next?

- **Real-World Examples**: See complete applications using jailed-path
- **Understanding Type-History**: Learn how the internal security works (for contributors)

The key rule: **always validate external paths through a jail before using them**. Whether it's user input, configuration files, or data from external sources - if you didn't create the path yourself, put it in jail first!