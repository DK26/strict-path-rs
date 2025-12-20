# Common Mistakes to Avoid

Here are the most common mistakes developers make with strict-path, and how to fix them.

## The Big Picture: Don't Defeat Your Own Security

Most anti-patterns come down to one thing: **treating strict-path types like regular paths**. When you convert back to `Path` or `String`, you're throwing away the safety you worked to create.

The core principle is: **make functions safe by design**. Instead of accepting raw strings and validating inside every function, accept safe types that guarantee the validation already happened.

## Security Theater: Only Validating Constants

**❌ What not to do:**
```rust
let config_dir = PathBoundary::try_new("./config")?;
let settings = config_dir.strict_join("settings.toml")?;  // Only literals!
let cache = config_dir.strict_join("cache")?;            // No user input validated
```

**Why it's wrong:** You're using strict-path but never validating untrusted input. This provides no security value—it's just security theater that looks safe but protects nothing.

**✅ Do this instead:**
```rust
let config_dir = PathBoundary::try_new("./config")?;
// Actually validate untrusted input from users, HTTP, databases, archives, etc.
let user_file = config_dir.strict_join(&user_provided_filename)?;
let archive_entry = config_dir.strict_join(&entry_name_from_zip)?;
let db_path = config_dir.strict_join(&path_from_database)?;
```


## Hidden Policy Decisions in Functions

**❌ What not to do:**
```rust
fn load_user_data(filename: &str) -> Result<String, Error> {
    // Policy hidden inside the function!
    let data_dir = PathBoundary::try_new("./userdata")?;
    let file = data_dir.strict_join(filename)?;
    file.read_to_string()
}
```

**Why it's wrong:** Callers can't see or control the security policy. What if they want a different directory? What if different users need different boundaries? The function makes security decisions that should be visible.

**✅ Do this instead:**
```rust
fn load_user_data(user_dir: &PathBoundary, filename: &str) -> std::io::Result<String> {
    let file = user_dir.strict_join(filename)?;
    file.read_to_string()
}

// OR even better - accept the validated path directly:
fn load_user_data(file_path: &StrictPath) -> std::io::Result<String> {
    file_path.read_to_string()
}
```

## Converting Back to Unsafe Types

**❌ What not to do:**
```rust
let safe_path = uploads_dir.strict_join("photo.jpg")?;
// WHY are you converting back to the unsafe Path type?!
if Path::new(safe_path.interop_path()).exists() {
    std::fs::copy(
        Path::new(safe_path.interop_path()), 
        "./backup/photo.jpg"
    )?;
}
```

## Leaking Real Paths to End-Users (Security Critical)

**❌ What not to do:**
```rust
// Cloud storage API - user requests file info
fn get_file_info(user_root: &VirtualRoot, filename: &str) -> FileInfo {
    let vpath = user_root.virtual_join(filename)?;
    FileInfo {
        name: filename.to_string(),
        // ❌ SECURITY HOLE: Exposes real host path to cloud client!
        path: vpath.interop_path().to_string_lossy().to_string(),
        size: vpath.metadata()?.len(),
    }
}
// User sees: "path": "/var/app/cloud-storage/tenant-42/docs/report.pdf"
// They now know your server structure!
```

**Why it's dangerous:** `interop_path()` returns the **real filesystem path on your host**. In multi-tenant systems, cloud services, or any scenario where users shouldn't know the actual server structure, exposing this path is an **information leakage vulnerability**:

- Reveals internal directory structure to attackers
- Exposes tenant IDs, usernames, or internal identifiers in paths
- Breaks the isolation abstraction that VirtualPath provides
- May expose sensitive infrastructure details (mount points, container paths, etc.)

**✅ Do this instead:**
```rust
fn get_file_info(user_root: &VirtualRoot, filename: &str) -> FileInfo {
    let vpath = user_root.virtual_join(filename)?;
    FileInfo {
        name: filename.to_string(),
        // ✅ CORRECT: Show virtual path, hide real host structure
        path: vpath.virtualpath_display().to_string(),
        size: vpath.metadata()?.len(),
    }
}
// User sees: "path": "/docs/report.pdf"
// Clean virtual view - no host structure exposed!
```

**The rule:** `interop_path()` is **only** for passing to OS/library calls that need the real path to function. It should **never** appear in:
- API responses to clients
- User-facing error messages
- Logs that users can access
- Any data serialized and sent to end-users

**Why it's wrong:** `StrictPath` already has `.exists()`, `.read()`, `.write()`, and other methods. You're defeating the entire point by converting back to `Path`, which ignores all security restrictions.

**✅ Do this instead:**
```rust
let safe_path = uploads_dir.strict_join("photo.jpg")?;
if safe_path.exists() {
    let backup_dir = PathBoundary::try_new("./backup")?;
    let backup_path = backup_dir.strict_join("photo.jpg")?;
    safe_path.strict_copy(backup_path.interop_path())?;
}
```

> **✅ Exception:** Passing `interop_path()` to strict-path's own methods like `strict_copy()`, `strict_rename()`, or `strict_symlink()` is correct—they **re-validate** the destination path against the boundary before performing the operation. This is intentional API design, not a security hole.

## Using std Path Operations on Leaked Values

**❌ What not to do:**
```rust
let uploads_dir = PathBoundary::try_new("./uploads")?;
let leaked = Path::new(uploads_dir.interop_path());
let dangerous = leaked.join("../../../etc/passwd");  // Can escape!
```

**Why it's wrong:** `Path::join()` is the #1 cause of path traversal vulnerabilities. It completely replaces the base path when you pass an absolute path, ignoring all security restrictions.

**✅ Do this instead:**
```rust
let uploads_dir = PathBoundary::try_new("./uploads")?;
// This will return an error instead of escaping:
let safe_result = uploads_dir.strict_join("../../../etc/passwd");
match safe_result {
    Ok(path) => println!("Safe path: {}", path.strictpath_display()),
    Err(e) => println!("Rejected dangerous path: {}", e),
}
```

## Wrong Display Method

**❌ What not to do:**
```rust
println!("Processing: {}", file.interop_path().to_string_lossy());
```

**Why it's wrong:** `interop_path()` is for passing to external APIs that need `AsRef<Path>`, like `std::fs::File::open()`. For displaying to users, it's the wrong tool and can lose information.

**✅ Do this instead:**
```rust
println!("Processing: {}", file.strictpath_display());

// For VirtualPath:
println!("Virtual path: {}", vpath.virtualpath_display());

// For VirtualRoot:
println!("Root: {}", vroot.as_unvirtual().strictpath_display());
```

## Terrible Variable Names

**❌ What not to do:**
```rust
let boundary = PathBoundary::try_new("./uploads")?;
let restriction = PathBoundary::try_new("./config")?;
let jail = VirtualRoot::try_new("./user_data")?;
```

**Why it's wrong:** These names tell you the type but nothing about what the directories are for. When you see `boundary.strict_join("photo.jpg")`, you have no idea what boundary you're joining to.

**✅ Do this instead:**
```rust
let uploads_dir = PathBoundary::try_new("./uploads")?;
let config_dir = PathBoundary::try_new("./config")?;
let user_id = "alice";
let user_data = VirtualRoot::try_new(format!("./user_data/{user_id}"))?;
```

Now `uploads_dir.strict_join("photo.jpg")` reads naturally as "uploads directory join photo.jpg".

## Functions That Accept Dangerous Inputs

**❌ What not to do:**
```rust
fn save_file(filename: &str, data: &[u8]) -> std::io::Result<()> {
    // Every function has to validate - error prone!
    let uploads = PathBoundary::try_new("./uploads")?;
    let safe_path = uploads.strict_join(filename)?;
    safe_path.write(data)
}
```

**Why it's wrong:** Every caller has to trust that this function validates correctly. Someone could call `save_file("../../../etc/passwd", data)` and you're relying on runtime validation instead of the type system.

**✅ Do this instead:**
```rust
fn save_file(safe_path: &StrictPath, data: &[u8]) -> std::io::Result<()> {
    safe_path.write(data)  // Already guaranteed safe!
}
```

Now it's **impossible** to call this function unsafely. The validation happens once when creating the `StrictPath`, and the type system prevents all misuse.

## Multi-User Data with Single Boundary

**❌ What not to do:**
```rust
// Global boundary for all users - dangerous!
static UPLOADS: PathBoundary = /* ... */;

fn save_user_file(user_id: u64, filename: &str, data: &[u8]) {
    // All users share the same directory - data mixing risk!
    let path = UPLOADS.strict_join(&format!("{}/{}", user_id, filename))?;
    path.write(data)?;
}
```

**Why it's wrong:** All users share the same boundary, making it easy to accidentally access another user's files or create insecure paths.

**✅ Do this instead:**
```rust
fn get_user_root(user_id: u64) -> Result<VirtualRoot<UserData>, Error> {
    let user_dir = format!("./users/{}", user_id);
    VirtualRoot::try_new(user_dir)
}

fn save_user_file(user_root: &VirtualRoot<UserData>, filename: &str, data: &[u8]) -> Result<(), Error> {
    let safe_path = user_root.virtual_join(filename)?.as_unvirtual();
    safe_path.write(data)?;
    Ok(())
}
```

## Redundant Method Chaining

**❌ What not to do:**
```rust
// Redundant .as_ref() call
external_api(path.interop_path().as_ref());

// Redundant unvirtualization 
vroot.as_unvirtual().interop_path();  // VirtualRoot already has interop_path()!
```

**✅ Do this instead:**
```rust
// interop_path() already implements AsRef<Path>
external_api(path.interop_path());

// VirtualRoot and VirtualPath have interop_path() directly
vroot.interop_path();
vpath.interop_path();
```

## Quick Reference: Bad → Good

| ❌ Bad Pattern                                           | ✅ Good Pattern                                  |
| ------------------------------------------------------- | ----------------------------------------------- |
| `Path::new(secure_path.interop_path()).exists()`        | `secure_path.exists()`                          |
| `println!("{}", path.interop_path().to_string_lossy())` | `println!("{}", path.strictpath_display())`     |
| `fn process(path: &str)`                                | `fn process(path: &StrictPath<_>)`              |
| `let boundary = PathBoundary::try_new(...)?`            | `let uploads_dir = PathBoundary::try_new(...)?` |
| `leaked_path.join("child")`                             | `secure_path.strict_join("child")?`             |
| `vroot.as_unvirtual().interop_path()`                   | `vroot.interop_path()`                          |
| `path.interop_path().as_ref()`                          | `path.interop_path()`                           |

## The Golden Rules

1. **Never convert secure types back to `Path`/`PathBuf`** - use their native methods instead
2. **Make functions accept safe types** - don't validate inside every function
3. **Name variables by purpose, not type** - `config_dir` not `boundary`
4. **Use the right method for the job** - `strictpath_display()` for display, `interop_path()` for external APIs
5. **Let callers control security policy** - don't hide `PathBoundary` creation inside helpers
6. **Actually validate untrusted input** - don't just validate constants

Remember: The whole point of strict-path is to make path operations safe by design. If you find yourself converting back to regular paths or validating inside every function, you're probably doing it wrong!
