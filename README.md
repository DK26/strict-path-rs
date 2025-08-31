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

// 3. Prefer encoding guarantees in function signatures
fn store_report(path: &jailed_path::JailedPath) -> std::io::Result<()> {
    // Implement your logic; `path` is proven inside the jail
    path.write_string("content")
}

store_report(&safe_path)?; // Type system enforces correct usage
```



## 🛡️ **Security Features**

- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the jail
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **Windows Security**: Handles DOS 8.3 short names (`PROGRA~1`) as potential attack vectors
- **Symlink Safe**: Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) for proper resolution
- **Zero Allocation Interop**: `systempath_as_os_str()` for external APIs without performance cost
- **Misuse Resistant**: API design makes it hard to accidentally bypass security

**Core Security Principle: Jail Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a jail‑enforced type (`JailedPath` or `VirtualPath`) before I/O.

## ⚠️ **Security Limitations**

This library operates at the **path level**, not the operating system level. While it provides strong protection against path traversal attacks using symlinks and standard directory navigation, it **cannot protect against** certain privileged operations:

- **Hard Links**: If a file is hard-linked outside the jailed path, accessing it through the jail will still reach the original file data. Hard links create multiple filesystem entries pointing to the same inode.
- **Mount Points**: If a filesystem mount is introduced (by a system administrator or attacker with sufficient privileges) that redirects a path within the jail to an external location, this library cannot detect or prevent access through that mount.

**Important**: These attack vectors require **high system privileges** (typically root/administrator access) to execute. If an attacker has such privileges on your system, they can bypass most application-level security measures anyway. This library effectively protects against the much more common and practical symlink-based traversal attacks that don't require special privileges.

Our symlink resolution via [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) handles the most accessible attack vectors that malicious users can create without elevated system access.

## 🚀 **Simple Examples**

### Basic Usage
```rust
use jailed_path::Jail;

// Any external input - HTTP requests, CLI args, config files, LLM output...
let user_input = "../../../etc/passwd";  // 🚨 This would be a security disaster

let jail = Jail::try_new("uploads")?;
let safe_path = jail.try_path(user_input)?;  // ✅ Attack neutralized!

safe_path.write_bytes(b"data")?;  // Guaranteed safe within ./uploads/
assert!(safe_path.systempath_starts_with(jail.path()));  // Mathematical proof
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
let vpath = storage.try_virtual_path(user_request)?;

// Recommended pattern: accept `VirtualPath` in function signatures
fn save_image(path: &jailed_path::VirtualPath) -> std::io::Result<()> {
    path.write_bytes(b"...image bytes...")
}

save_image(&vpath)?;            // Type system guarantees correctness
println!("User sees: {}", vpath); // Virtual root path
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

| Source                  | Typical Input                  | Use VirtualPath For                                          | Use JailedPath For                      | Notes                                                       |
| ----------------------- | ------------------------------ | ------------------------------------------------------------ | --------------------------------------- | ----------------------------------------------------------- |
| 🌐 HTTP requests         | URL path segments, file names  | Display/logging, safe virtual joins, and I/O within the jail | System-facing interop/I/O (alternative) | Always clamp user paths via `VirtualRoot::try_virtual_path` |
| 🌍 Web forms             | Form file fields, route params | User-facing display; UI navigation; I/O within the jail      | System-facing interop/I/O (alternative) | Treat all form inputs as untrusted                          |
| ⚙️ Configuration files   | Paths in config                | UI display and I/O within the jail                           | System-facing interop/I/O (alternative) | Validate each path before I/O                               |
| 💾 Database content      | Stored file paths              | Rendering paths in UI dashboards; I/O within the jail        | System-facing interop/I/O (alternative) | Storage does not imply safety; validate on use              |
| 📂 CLI arguments         | Command-line path args         | Pretty printing; I/O within the jail                         | System-facing interop/I/O (alternative) | Validate args before touching the FS                        |
| 🔌 External APIs         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs; I/O within the jail         | System-facing interop/I/O (alternative) | Never trust external systems                                |
| 🤖 LLM/AI output         | Generated file names/paths     | Display suggestions; I/O within the jail                     | System-facing interop/I/O (alternative) | LLM output is untrusted by default                          |
| 📨 Inter-service msgs    | Queue/event payloads           | Observability output; I/O within the jail                    | System-facing interop/I/O (alternative) | Validate on the consumer side                               |
| 📱 Apps (desktop/mobile) | Drag-and-drop, file pickers    | Show picked paths in UI; I/O within the jail                 | System-facing interop/I/O (alternative) | Validate selected paths before I/O                          |
| 📦 Archive contents      | Entry names from ZIP/TAR       | Progress UI, virtual joins, and I/O within the jail          | System-facing interop/I/O (alternative) | Validate each entry to block zip-slip                       |
| 🔧 File format internals | Embedded path strings          | Diagnostics and I/O within the jail                          | System-facing interop/I/O (alternative) | Never dereference without validation                        |

Note: This is not “JailedPath vs VirtualPath.” `VirtualPath` conceptually extends `JailedPath` with a virtual-root view and restricted, jail-aware operations. Both support I/O; choose based on whether you need virtual, user-facing semantics or raw system-facing semantics.

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

let css: VirtualPath<WebAssets> = assets_vroot.try_virtual_path("style.css")?;
let doc: VirtualPath<UserFiles> = uploads_vroot.try_virtual_path("report.pdf")?;

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
let file_path = user_storage.try_virtual_path(&user_requested_path)?;
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

// Prefer signatures that require `JailedPath`
fn read_file(p: &jailed_path::JailedPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
fn write_file(p: &jailed_path::JailedPath, s: &str) -> std::io::Result<()> { p.write_string(s) }
let _ = read_file(&path)?; write_file(&path, "data")?;

// Safe path operations
path.systempath_join("subdir")?;
path.systempath_parent()?;

// External API interop
external_function(path.systempath_as_os_str());  // No allocation
```

### Concept Comparison

| Feature              | `Path`/`PathBuf`          | `JailedPath`                                 | `VirtualPath`                                     |
| -------------------- | ------------------------- | -------------------------------------------- | ------------------------------------------------- |
| Join behavior        | `Path::join` (can escape) | `systempath_join` (validated)                | `virtualpath_join` (clamped)                      |
| Display behavior     | OS path                   | OS path                                      | Virtual root path                                 |
| Boundary guarantee   | None                      | Jailed (cannot escape)                       | Jailed (virtual view)                             |
| Input permissiveness | Any path (no checks)      | Only paths inside the jail                   | Any input; always clamped to the jail             |
| Typical use          | Low-level, unvalidated    | Anything you'd do with `Path`, but jail‑safe | User‑facing paths and the same I/O (virtual view) |

### User-Facing Virtual Paths (VirtualPath)
```rust
let vroot = VirtualRoot::try_new("directory")?;
let vpath = vroot.try_virtual_path("file.txt")?;

println!("{}", vpath);  // "/file.txt" (rooted view)

// Prefer signatures that require `VirtualPath`
fn serve(p: &jailed_path::VirtualPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
let _ = serve(&vpath)?;

// Explicit names make intent obvious even without types in scope:
// p.join(..)              -> unsafe std join (can escape the jail) — avoid on untrusted inputs
// path.systempath_join(..)-> safe system-path join (validated not to escape)
// vpath.virtualpath_join(..)-> safe virtual join (clamped to the virtual root)
// The same naming applies to other ops: parent/with_file_name/with_extension/starts_with/ends_with.
```

### Switching Views: Upgrade or Downgrade
- Stay in one dimension for most flows:
  - Virtual dimension: `VirtualPath` + `virtualpath_*` operations and direct I/O
  - System dimension: `JailedPath` + `systempath_*` operations and direct I/O
- Edge cases: switch views explicitly
  - Upgrade: `JailedPath::virtualize()` to get virtual-root behavior for display/joins
  - Downgrade: `VirtualPath::unvirtual()` to get a system-facing value for interop
- Debug vs Display
  - `Display` for `VirtualPath` shows a rooted path like "/a/b.txt" (user-facing)
  - `Debug` for `VirtualPath` is verbose and developer-facing (shows system path, virtual view, jail context, and marker type)
  - `Debug` for `Jail` and `VirtualRoot` shows the root path and marker type (developer-facing); `Display` shows the real root path


## 📖 **Advanced Usage**

For complete API reference, see our [API_REFERENCE.md](API_REFERENCE.md).

For underlying path resolution without jailing, see [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize).

## 🔌 Integrations

- Serde (feature `serde`):
  - `JailedPath` and `VirtualPath` implement `Serialize`.
  - Deserialize into a `String`, then validate with a jail/virtual root:
    - `#[derive(serde::Deserialize)] struct Payload { file: String }`
    - `let p: Payload = serde_json::from_str(body)?;`
    - `let jp = jail.try_path(&p.file)?;` or `let vp = vroot.try_virtual_path(&p.file)?;`
  - Or use context helpers for deserialization: `serde_ext::WithJail(&jail)` / `serde_ext::WithVirtualRoot(&vroot)` with a serde Deserializer when you deserialize single values with context.

- Axum AppState + Extractors:
  - Store `VirtualRoot<Marker>` in state; validate `Path<String>` to `VirtualPath` per request.
  - Handlers and helpers accept `&VirtualPath<Marker>` or `&JailedPath<Marker>` so types enforce correctness.
  - See `examples/src/bin/web/axum_static_server.rs` for a minimal custom extractor and a JSON route.

- app-path (config dirs):
  - Use `app_path::app_path!("config", env = "APP_CONFIG_DIR")` to locate a config directory relative to the executable with an env override.
  - Create a jail there: `let cfg = Jail::try_new_create(cfg_dir)?;` and operate via `JailedPath`.

## 🧭 Markers (Type Inference)

- Default marker: `Marker = ()` for all types; inference usually works once a value is bound.
- If inference needs help, annotate the `let` or use an empty turbofish.
- Keep it readable: avoid turbofish unless it clarifies intent or is required.

```rust
// Inferred default marker
let vroot: VirtualRoot = VirtualRoot::try_new("user_data")?;
let vpath: VirtualPath = vroot.try_virtual_path("a.txt")?;

// When inference needs help
let vroot = VirtualRoot::<()>::try_new("user_data")?; // or: let vroot: VirtualRoot<()> = ...

// Custom marker
struct UserFiles;
let uploads: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;
```

## 📄 **License**

MIT OR Apache-2.0
