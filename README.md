# jailed-path

[![Crates.io](https://img.shields.io/crates/v/jailed-path.svg)](https://crates.io/crates/jailed-path)
[![Documentation](https://docs.rs/jailed-path/badge.svg)](https://docs.rs/jailed-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![CI](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

**Prevent directory traversal with type-safe virtual path jails and safe symlinks**

> *Putting your paths in jail by the Type-State Police Department*
> *because your LLM can't be trusted with security*

Never worry about `../../../etc/passwd` again. Jailed-path provides compile-time guarantees that external paths stay exactly where you want them.

## ⚡ **Installation & Quick Start**

```toml
[dependencies]
jailed-path = "0.0.4"
```

```rust
use jailed_path::Jail;

// 1. Create a jail
let jail = Jail::try_new_create("safe_directory")?;  // Creates dir if needed

// 2. Validate any external path
let safe_path = jail.try_path("user/input/file.txt")?;

// 3. Use normal file operations - guaranteed safe
safe_path.read_to_string()?;
safe_path.write_string("content")?;
safe_path.create_dir_all()?;
```



## 🛡️ **Security Features**

- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the jail
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **Windows Security**: Handles DOS 8.3 short names (`PROGRA~1`) as potential attack vectors
- **Symlink Safe**: Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) for proper resolution
- **Zero Allocation Interop**: `systempath_as_os_str()` for external APIs without performance cost
- **Misuse Resistant**: API design makes it hard to accidentally bypass security

**Core Security Principle: Jail Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a `JailedPath` before I/O.

## 🚀 **Simple Examples**

### Basic Usage
```rust
use jailed_path::Jail;

// Any external input - HTTP requests, CLI args, config files, LLM output...
let user_input = "../../../etc/passwd";  // 🚨 This would be a security disaster

let jail = Jail::try_new("uploads")?;
let safe_path = jail.try_path(user_input)?;  // ✅ Attack neutralized!

safe_path.write_bytes(b"data")?;  // Guaranteed safe within ./uploads/
assert!(safe_path.starts_with_systempath(jail.path()));  // Mathematical proof
```

### The Old Way vs. The New Way
```rust
// 🚨 DANGEROUS - Every external path is a potential vulnerability
std::fs::read(format!("./uploads/{}", user_path))  // One day this kills your server

// ✅ SECURE - Function signature makes bypass impossible
fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
    safe_path.read_bytes()  // Cannot be called with unsafe paths
}
```

### Virtual Paths: User-Friendly + Secure
```rust
use jailed_path::VirtualRoot;

// Each user gets their own secure sandbox
let storage = VirtualRoot::try_new(format!("/srv/users/{user_id}"))?;

// User requests any path - we clamp it safely
let user_request = "photos/vacation/beach.jpg";  // or "../../../secrets" (blocked!)
let vpath = storage.try_path_virtual(user_request)?;

println!("User sees: {}", vpath);           // "/photos/vacation/beach.jpg"
vpath.write_bytes(image_data)?;              // Stored safely in their sandbox
```

## 🚨 **What External Paths Need Jailing**

**RULE: Each path from an uncontrolled environment should be jailed.**

- HTTP request parameters and form data
- Command-line arguments
- Configuration file contents
- Database-stored paths
- File upload names
- External API responses
- LLM/AI-generated paths
- Archive entry names (ZIP, TAR, etc.)
- Inter-service message payloads
- Any user input whatsoever

If it comes from outside your program's direct control, jail it.

## 🎯 **When to Use Each Type**

| Source                  | Typical Input                  | Use VirtualPath For                                      | Use JailedPath For        | Notes                                                       |
| ----------------------- | ------------------------------ | -------------------------------------------------------- | ------------------------- | ----------------------------------------------------------- |
| 🌐 HTTP requests         | URL path segments, file names  | Display/logging, safe virtual joins (`join_virtualpath`) | System-facing interop/I/O | Always clamp user paths via `VirtualRoot::try_path_virtual` |
| 🌍 Web forms             | Form file fields, route params | User-facing display; UI navigation                       | System-facing interop/I/O | Treat all form inputs as untrusted                          |
| ⚙️ Configuration files   | Paths in config                | Optional UI display of config paths                      | System-facing interop/I/O | Validate each path before I/O                               |
| 💾 Database content      | Stored file paths              | Rendering paths in UI dashboards                         | System-facing interop/I/O | Storage does not imply safety; validate on use              |
| 📂 CLI arguments         | Command-line path args         | Optional pretty printing                                 | System-facing interop/I/O | Validate args before touching the FS                        |
| 🔌 External APIs         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs                          | System-facing interop/I/O | Never trust external systems                                |
| 🤖 LLM/AI output         | Generated file names/paths     | Display suggestions safely                               | System-facing interop/I/O | LLM output is untrusted by default                          |
| 📨 Inter-service msgs    | Queue/event payloads           | Observability output                                     | System-facing interop/I/O | Validate on the consumer side                               |
| 📱 Apps (desktop/mobile) | Drag-and-drop, file pickers    | Show picked paths in UI                                  | System-facing interop/I/O | Validate selected paths before I/O                          |
| 📦 Archive contents      | Entry names from ZIP/TAR       | Progress UI, virtual joins                               | System-facing interop/I/O | Validate each entry to block zip-slip                       |
| 🔧 File format internals | Embedded path strings          | Diagnostics                                              | System-facing interop/I/O | Never dereference without validation                        |

**Rule of thumb**: Use `VirtualPath` for user-facing operations and display. Use `JailedPath` for actual I/O and system integration.

## 🌟 **Advanced Examples**

### Multi-Jail Type Safety (The Coolest Feature!)

Prevent accidentally mixing different storage contexts at compile time:

```rust
use jailed_path::{Jail, JailedPath, VirtualRoot, VirtualPath};

struct WebAssets;    // CSS, JS, images
struct UserFiles;    // Uploaded documents

// Functions with type-safe security contracts
fn serve_asset(path: &JailedPath<WebAssets>) { /* ... read_bytes/write_bytes ... */ }
fn process_upload(path: &JailedPath<UserFiles>) { /* ... */ }

// Ingest untrusted paths as VirtualPath per jail
let assets_vroot: VirtualRoot<WebAssets> = VirtualRoot::try_new("public")?;
let uploads_vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("user_data")?;

let css: VirtualPath<WebAssets> = assets_vroot.try_path_virtual("style.css")?;
let doc: VirtualPath<UserFiles> = uploads_vroot.try_path_virtual("report.pdf")?;

// Convert to the system-facing type only where the function requires it
serve_asset(&css.unvirtual());         // ✅ Correct context
// serve_asset(&doc.unvirtual());      // ❌ Compile error - prevents mixing!
```

Your IDE and compiler become security guards.

### Web Server File Serving
```rust
async fn serve_static_file(path: String) -> Result<Response> {
    let public_jail = Jail::try_new("./static")?;
    let safe_path = public_jail.try_path(&path)?;  // Blocks all traversal attacks
    Ok(Response::new(safe_path.read_bytes()?))
}
```

### Archive Extraction (Zip Slip Prevention)
```rust
let extract_jail = Jail::try_new("./extracted")?;
for entry in zip_archive.entries() {
    let safe_path = extract_jail.try_path(entry.path())?;  // Neutralizes zip slip
    safe_path.write_bytes(entry.data())?;
}
```

### Cloud Storage API
```rust
// User chooses any path - always safe
let user_storage = VirtualRoot::try_new(format!("/cloud/user_{id}"))?;
let file_path = user_storage.try_path_virtual(&user_requested_path)?;
file_path.write_bytes(upload_data)?;
```

### Configuration Files
```rust
fn load_config(config_name: &str) -> Result<String> {
    let config_jail = Jail::try_new("./config")?;
    let safe_path = config_jail.try_path(config_name)?;
    safe_path.read_to_string()
}
```

### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_jail = Jail::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_jail.try_path(ai_suggested_path)?; // Guaranteed safe
safe_ai_path.write_string(&ai_generated_content)?;
```

```rust
use jailed_path::Jail;

// 1. Create a jail
let jail = Jail::try_new_create("safe_directory")?;  // Creates dir if needed

// 2. Validate any external path
let safe_path = jail.try_path("user/input/file.txt")?;

// 3. Use normal file operations - guaranteed safe
safe_path.read_to_string()?;
safe_path.write_string("content")?;
safe_path.create_dir_all()?;
```

## 📚 **Core API At a Glance**

### System-Facing Paths (JailedPath)
```rust
let jail = Jail::try_new("directory")?;
let path = jail.try_path("file.txt")?;

// File I/O
path.read_bytes()?;
path.write_string("data")?;
path.exists();

// Safe path operations
path.join_systempath("subdir")?;
path.systempath_parent()?;

// External API interop
external_function(path.systempath_as_os_str());  // No allocation
```

### User-Facing Virtual Paths (VirtualPath)
```rust
let vroot = VirtualRoot::try_new("directory")?;
let vpath = vroot.try_path_virtual("file.txt")?;

println!("{}", vpath);  // "/file.txt" (rooted view)

// Virtual operations
vpath.join_virtualpath("subdir")?;
vpath.virtualpath_parent()?;

// Convert to system path for I/O
vpath.unvirtual().read_bytes()?;
```

## 📖 **Advanced Usage**

For complete API reference, see our [API_REFERENCE.md](API_REFERENCE.md).

For underlying path resolution without jailing, see [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize).

## 📄 **License**

MIT OR Apache-2.0
