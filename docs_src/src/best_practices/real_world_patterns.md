# Real-World Patterns

> *Production-ready examples showing how to use strict-path in common scenarios.*

This chapter provides complete, copy-pasteable examples for typical use cases. Each pattern includes error handling, best practices, and explanations.

---

## LLM Agent File Manager

**Challenge**: LLM-generated paths are untrusted by definition—they could suggest anything from legitimate filenames to sophisticated traversal attacks.

**Solution**: Use `StrictPath` to detect and reject escape attempts explicitly.

```rust
use strict_path::PathBoundary;

// Encode guarantees in signature: pass workspace directory boundary and untrusted request
async fn llm_file_operation(
    workspace_dir: &PathBoundary,
    request: &LlmRequest
) -> Result<String, Box<dyn std::error::Error>> {
    // LLM could suggest anything: "../../../etc/passwd", "C:/Windows/System32", etc.
    let safe_path = workspace_dir.strict_join(&request.filename)?; // ✅ Attack = Error

    match request.operation.as_str() {
        "write" => {
            safe_path.create_parent_dir_all()?;
            safe_path.write(&request.content)?;
        },
        "read" => {
            return Ok(safe_path.read_to_string()?);
        },
        "delete" => {
            safe_path.remove_file()?;
        },
        _ => return Err("Invalid operation".into()),
    }
    Ok(format!("File {} processed safely", safe_path.strictpath_display()))
}

// Stub types
struct LlmRequest {
    filename: String,
    operation: String,
    content: Vec<u8>,
}
```

**Key points:**
- Pass `&PathBoundary` into the helper—boundary choice is policy
- Reject escape attempts explicitly with `?` operator
- Use `strictpath_display()` for system-facing output
- Create parent directories explicitly when needed

---

## Archive Extraction: Detect vs. Contain

**Critical distinction**: Choose the right tool based on whether escapes are attacks or expected behavior.

### Pattern 1: Detect Malicious Archives (Production)

**When to use**: Production archive extraction where malicious paths indicate a compromised archive.

**Solution**: Use `StrictPath` to detect and reject compromised archives:

```rust
use strict_path::PathBoundary;

fn extract_zip_strict(
    zip_entries: impl IntoIterator<Item = (String, Vec<u8>)>
) -> Result<(), Box<dyn std::error::Error>> {
    let extract_dir = PathBoundary::try_new_create("./extracted")?;
    
    for (name, data) in zip_entries {
        // Malicious names like "../../../etc/passwd" return Error
        match extract_dir.strict_join(&name) {
            Ok(safe_path) => {
                safe_path.create_parent_dir_all()?;
                safe_path.write(&data)?;
            },
            Err(e) => {
                eprintln!("🚨 Malicious path detected: {name}");
                eprintln!("Error: {e}");
                return Err(format!("Archive contains malicious path: {name}").into());
            }
        }
    }
    Ok(())
}
```

**Benefits:**
- Detects compromised archives immediately
- Allows logging and alerting on attacks
- Fails fast—doesn't partially extract malicious content
- Users know their archive was rejected

### Pattern 2: Sandbox Suspicious Archives (Research/Analysis)

**When to use**: Malware analysis, security research, or safely inspecting untrusted archives.

**Solution**: Use `VirtualPath` to contain escape attempts while observing behavior:

```rust,no_run
#[cfg(feature = "virtual-path")]
use strict_path::VirtualPath;

#[cfg(feature = "virtual-path")]
fn extract_zip_sandbox(
    zip_entries: impl IntoIterator<Item = (String, Vec<u8>)>
) -> std::io::Result<()> {
    let extract_root = VirtualPath::with_root_create("./sandbox")?;
    
    for (name, data) in zip_entries {
        // Hostile names like "../../../etc/passwd" → "/etc/passwd" (safely clamped)
        let vpath = extract_root.virtual_join(&name)?;
        
        println!("Entry: {name}");
        println!("  Virtual path: {}", vpath.virtualpath_display());
        println!("  System path: {}", vpath.as_unvirtual().strictpath_display());
        
        vpath.create_parent_dir_all()?;
        vpath.write(&data)?;
    }
    Ok(())
}
```

**Benefits:**
- Escapes are contained—observe malicious behavior safely
- See what paths the archive *tried* to write
- Perfect for forensic analysis
- No partial extraction issues

### When to Use Which

| Scenario                  | Use Pattern 1 (StrictPath)  | Use Pattern 2 (VirtualPath) |
| ------------------------- | --------------------------- | --------------------------- |
| **Production extraction** | ✅ Detect attacks            | ❌ Hides attacks             |
| **File uploads**          | ✅ Reject at boundary        | ❌ Hides attacks             |
| **Malware analysis**      | ❌ Can't observe behavior    | ✅ Safe observation          |
| **Security research**     | ❌ Escapes prevent analysis  | ✅ Contained escapes         |
| **User-facing services**  | ✅ Users know it's malicious | ❌ Silently "fixes" it       |

**Rule of thumb**: Use `StrictPath` (detect) for production; use `VirtualPath` (contain) for research/analysis.

---

## Web File Server

**Challenge**: Prevent directory traversal attacks while serving static files, and ensure user uploads can't be served as static assets.

**Solution**: Use marker types to enforce domain separation at compile time.

```rust,no_run
use strict_path::{PathBoundary, StrictPath};

struct StaticFiles;    // CSS, JS, images
struct UserUploads;    // User documents

async fn serve_static(
    static_dir: &PathBoundary<StaticFiles>,
    path: &str
) -> Result<Response, Box<dyn std::error::Error>> {
    let safe_path = static_dir.strict_join(path)?; // ✅ "../../../" → Error
    Ok(Response::new(safe_path.read()?))
}

// Function signature prevents bypass - no validation needed inside!
async fn serve_file(safe_path: &StrictPath<StaticFiles>) -> Response {
    Response::new(safe_path.read().unwrap_or_default())
}

// This function CANNOT accept UserUploads paths - compile error!
fn handle_request(
    static_files_dir: &PathBoundary<StaticFiles>,
    user_uploads_dir: &PathBoundary<UserUploads>,
    request_path: &str
) -> Result<Response, Box<dyn std::error::Error>> {
    let static_file = static_files_dir.strict_join(request_path)?;
    let _response = serve_file(&static_file); // ✅ Works
    
    let user_file = user_uploads_dir.strict_join(request_path)?;
    // serve_file(&user_file); // ❌ Compile error: wrong domain!
    
    Ok(Response::new(Vec::new()))
}

// Stub types
struct Response { data: Vec<u8> }
impl Response {
    fn new(data: Vec<u8>) -> Self { Response { data } }
}
```

**Key benefits:**
- Marker types prevent cross-domain mix-ups at compile time
- Function signatures encode security requirements
- No runtime validation needed when types guarantee safety
- Refactoring changes propagate through type system

---

## Configuration Manager

**Challenge**: Load configuration files safely when the filename comes from user input or external sources.

**Solution**: Validate config file paths before loading; encode validation state in function signatures.

```rust,no_run
use strict_path::{PathBoundary, StrictPath};

struct UserConfigs;

fn load_user_config(
    config_dir: &PathBoundary<UserConfigs>,
    config_name: &str
) -> Result<Config, Box<dyn std::error::Error>> {
    let config_file = config_dir.strict_join(config_name)?;
    
    // Use built-in I/O helpers
    let content = config_file.read_to_string()?;
    Ok(serde_json::from_str(&content)?)
}

fn save_user_config(
    config_file: &StrictPath<UserConfigs>,
    config: &Config
) -> Result<(), Box<dyn std::error::Error>> {
    // Function signature guarantees path is already validated
    let json = serde_json::to_string_pretty(config)?;
    config_file.write(json.as_bytes())?;
    Ok(())
}

// Stub types
struct Config { setting: String }
```

**Pattern notes:**
- Pass `&PathBoundary` when validation is needed in the helper
- Pass `&StrictPath` when validation already happened at call site
- Use built-in I/O methods to avoid `.interop_path()` calls
- Marker types document which config directory is being accessed

---

## Multi-Tenant Cloud Storage

**Challenge**: Each user needs isolated storage where they can't access other users' files, and paths should look clean (no system paths exposed).

**Solution**: Use `VirtualPath` to create per-user isolated filesystems with clean rooted paths.

```rust,no_run
#[cfg(feature = "virtual-path")]
use strict_path::{VirtualRoot, VirtualPath};

#[cfg(feature = "virtual-path")]
async fn handle_upload(
    user_root: &VirtualRoot,
    filename: &str,
    bytes: &[u8]
) -> std::io::Result<()> {
    // User can request ANY path - always safely contained
    let vpath = user_root.virtual_join(filename)?;
    
    vpath.create_parent_dir_all()?;
    vpath.write(bytes)?;
    
    // Show user-friendly path
    println!("Saved: {}", vpath.virtualpath_display());
    // Output: "Saved: /documents/report.pdf"
    // (Real path: storage/user_42/documents/report.pdf)
    
    Ok(())
}

#[cfg(feature = "virtual-path")]
async fn handle_download(
    user_root: &VirtualRoot,
    filename: &str
) -> std::io::Result<Vec<u8>> {
    let vpath = user_root.virtual_join(filename)?;
    
    // Share strict helper logic by borrowing
    vpath.as_unvirtual().read()
}

#[cfg(feature = "virtual-path")]
fn setup_user_storage(user_id: u64) -> Result<VirtualRoot, Box<dyn std::error::Error>> {
    let user_root = VirtualRoot::try_new_create(format!("storage/user_{user_id}"))?;
    Ok(user_root)
}
```

**Isolation benefits:**
- Users see clean paths like `/documents/report.pdf`
- Real path hidden: `storage/user_42/documents/report.pdf`
- Escape attempts silently contained within user's boundary
- Each user's `/` is their own root—complete isolation
- Share strict helpers with `as_unvirtual()` borrowing

---

## Common Quick Patterns

### Validate + Write

```rust
use strict_path::PathBoundary;

fn write_file(boundary: &PathBoundary, name: &str, data: &[u8]) -> std::io::Result<()> {
    let safe_path = boundary.strict_join(name)?;
    safe_path.create_parent_dir_all()?;
    safe_path.write(data)
}
```

### Validate + Read

```rust
use strict_path::PathBoundary;

fn read_file(boundary: &PathBoundary, name: &str) -> std::io::Result<String> {
    boundary.strict_join(name)?.read_to_string()
}
```

### Directory Walking with Validation

```rust
use strict_path::{PathBoundary, StrictPath};

fn process_directory(base_dir: &PathBoundary) -> std::io::Result<Vec<StrictPath>> {
    let mut paths = Vec::new();
    
    // Walk the directory
    for entry in base_dir.read_dir()? {
        let entry = entry?;
        let name = entry.file_name();
        
        // Re-validate each discovered name before use
        let safe_path = base_dir.strict_join(&name.to_string_lossy())?;
        paths.push(safe_path);
    }
    
    Ok(paths)
}
```

### Error Handling with Security Logging

```rust
use strict_path::{PathBoundary, StrictPathError};

fn robust_file_access(
    boundary: &PathBoundary,
    filename: &str
) -> Result<String, Box<dyn std::error::Error>> {
    match boundary.strict_join(filename) {
        Ok(safe_path) => {
            match safe_path.read_to_string() {
                Ok(content) => Ok(content),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File doesn't exist - create default
                    safe_path.write(b"default content")?;
                    Ok("default content".to_string())
                },
                Err(e) => Err(e.into()),
            }
        },
        Err(StrictPathError::PathEscapesBoundary { .. }) => {
            // Log security incident
            eprintln!("🚨 Path escape attempt: {filename}");
            Err("Invalid path".into())
        },
        Err(e) => Err(e.into()),
    }
}
```

---

## Learn More

- **[Best Practices Overview →](../best_practices.md)** - Core guidelines and decision matrices
- **[Common Operations →](./common_operations.md)** - Complete operation examples (joins, rename, delete, etc.)
- **[Policy & Reuse →](./policy_and_reuse.md)** - When and why to use VirtualRoot/PathBoundary
- **[Authorization Patterns →](./authorization_architecture.md)** - Compile-time authorization with markers

