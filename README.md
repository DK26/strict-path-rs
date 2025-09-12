# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![CI](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/jailed-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)**

**Prevent directory traversal with type-safe path restriction and safe symlinks.**

> *The Type-State Police have set up PathBoundary checkpoints*  
> *keeping your unruly paths in line, because your LLM is running wild*

## 🚨 **One Line of Code Away from Disaster**

```rust
// ❌ This single line can destroy your server
std::fs::write(user_input, data)?;  // user_input = "../../../etc/passwd"

// ✅ This single line makes it mathematically impossible  
PathBoundary::try_new("uploads")?.strict_join(user_input)?.write_bytes(data)?;
```

**The Reality**: Every web server, LLM agent, and file processor faces the same vulnerability. One unvalidated path from user input, config files, or AI responses can grant attackers full filesystem access.

**The Solution**: Comprehensive path security with mathematical guarantees. No more hoping you "got it right."

## 🛡️ **How We Solve The Entire Problem Class**

**strict-path isn't just validation—it's a complete solution to path security:**

1. **🔧 [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation**: Heavily tested against 19+ globally known path-related CVEs
2. **🚫 Hacky string rejection**: Advanced pattern detection blocks encoding tricks and malformed inputs  
3. **📐 Mathematical correctness**: Rust's type system provides compile-time proof of path boundaries
4. **👁️ Explicit operations**: Method names like `strict_join()` make security violations visible in code review
5. **🤖 LLM-aware design**: Built specifically for untrusted AI-generated paths and modern threat models
6. **🔗 Symlink resolution**: Safe handling of symbolic links with cycle detection and boundary enforcement
7. **⚡ Dual protection modes**: Choose **Strict** (validate & reject) or **Virtual** (clamp & contain) based on your use case
8. **🏗️ Battle-tested architecture**: Prototyped and refined across real-world production systems
9. **🎯 Zero-allocation interop**: Seamless integration with existing `std::path` ecosystems

### **Recently Addressed CVEs**
- **CVE-2025-8088** (WinRAR ADS): NTFS Alternate Data Stream traversal prevention
- **CVE-2022-21658** (TOCTOU): Race condition protection during path resolution  
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793**: Windows 8.3 short name vulnerabilities

**Your security audit becomes**: *"We use strict-path for comprehensive path security."* ✅

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1.0-alpha.1"
```

```rust
use strict_path::PathBoundary;

// 1. Create a boundary (your security perimeter)
let uploads = PathBoundary::try_new_create("uploads")?;

// 2. ANY external input becomes safe 
let safe_path = uploads.strict_join(dangerous_user_input)?;  // Attack = Error

// 3. Use normal file operations - guaranteed secure
safe_path.write_bytes(file_data)?;
safe_path.read_to_string()?;
```

**That's it.** No complex validation logic. No CVE research. No security expertise required.

## 🛡️ **Security Features**

- **CVE-Aware Protection**: Built on 19+ real-world vulnerabilities - we've done the security research so you don't have to
- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the restriction  
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **LLM-Ready**: Designed specifically for untrusted AI-generated paths and modern threat models
- **Platform Security**: Handles Windows 8.3 short names, symlinks, and other OS-specific attack vectors
- **Zero-Allocation Interop**: `.interop_path()` for seamless integration with existing `std::path` code
- **Misuse Resistant**: API design makes security violations visible in code review

## 🎯 **When to Use Each Type**

| Your Input Source                           | Use This       | Why                                                 |
| ------------------------------------------- | -------------- | --------------------------------------------------- |
| **HTTP requests, LLM output, config files** | `StrictPath`   | Reject attacks explicitly - perfect for validation  |
| **User uploads, archive extraction**        | `VirtualPath`  | Clamp hostile paths safely - perfect for sandboxing |
| **Your own hardcoded paths**                | `Path/PathBuf` | You control it, no validation needed                |

**Think of it this way:**
- `StrictPath` = **Security Filter** — validates and rejects unsafe paths
- `VirtualPath` = **Complete Sandbox** — clamps any input to stay safe

## 🛡️ **Core Security Foundation**

At the heart of this crate is **`StrictPath`** - the fundamental security primitive that provides our ironclad guarantee: **every `StrictPath` is mathematically proven to be within its boundary**. 

Everything in this crate builds upon `StrictPath`:
- `PathBoundary` creates and validates `StrictPath` instances
- `VirtualPath` extends `StrictPath` with user-friendly virtual root semantics  
- `VirtualRoot` provides a root context for creating `VirtualPath` instances

**The core promise:** If you have a `StrictPath<Marker>`, it is impossible for it to reference anything outside its designated boundary. This isn't just validation - it's a type-level guarantee backed by cryptographic-grade path canonicalization.


**Core Security Principle: Secure Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a boundary‑enforced type (`StrictPath` or `VirtualPath`) before I/O.

## 🎯 **Choose Your Weapon: When to Use What**

### 🌐 **VirtualPath** - User Sandboxes & Cloud Storage
*"Give users their own private universe"*

```rust
use strict_path::VirtualRoot;

// Archive extraction - hostile names get clamped, not rejected
let extract_dir = VirtualRoot::try_new("./extracted")?;
for entry_name in malicious_zip_entries {
    let safe_path = extract_dir.virtual_join(entry_name)?; // "../../../etc" → "/etc"  
    safe_path.write_bytes(entry.data())?; // Always safe
}

// User cloud storage - users see friendly paths
let user_space = VirtualRoot::try_new(format!("users/{user_id}"))?;
let doc = user_space.virtual_join("My Documents/report.pdf")?;
println!("Saved to: {}", doc.virtualpath_display()); // Shows "/My Documents/report.pdf"
```

### ⚔️ **StrictPath** - LLM Agents & System Boundaries  
*"Validate everything, trust nothing"*

```rust
use strict_path::PathBoundary;

// LLM Agent file operations
let ai_workspace = PathBoundary::try_new("ai_sandbox")?;
let ai_request = llm.generate_path(); // Could be anything malicious
let safe_path = ai_workspace.strict_join(ai_request)?; // Attack → Explicit Error
safe_path.write_string(&ai_generated_content)?;

// Limited system access with clear boundaries
struct ConfigFiles; 
let config_dir = PathBoundary::<ConfigFiles>::try_new("./config")?;
let user_config = config_dir.strict_join(user_selected_config)?; // Validated
```

### 🔓 **Path/PathBuf** - Controlled Access
*"When you control the source"*

```rust
use std::path::PathBuf;

// ✅ You control the input - no validation needed
let log_file = PathBuf::from(format!("logs/{}.log", timestamp));
let app_config = Path::new("config/app.toml"); // Hardcoded = safe

// ❌ NEVER with external input
let user_file = Path::new(user_input); // 🚨 SECURITY DISASTER
```

## 🎖️ **The Golden Rule**

> **If you didn't create the path yourself, secure it first.**

| Input Source                              | Use This       | Why                        |
| ----------------------------------------- | -------------- | -------------------------- |
| **HTTP requests, CLI args, config files** | `StrictPath`   | Reject attacks explicitly  |
| **LLM/AI output, database records**       | `StrictPath`   | Validate before execution  |
| **Archive contents, user uploads**        | `VirtualPath`  | Clamp hostile paths safely |
| **Your own code, hardcoded paths**        | `Path/PathBuf` | You control it             |

## 🚀 **Real-World Examples**

### LLM Agent File Manager
```rust
use strict_path::PathBoundary;

// Encode guarantees in signature: pass workspace boundary and untrusted request
async fn llm_file_operation(workspace: &PathBoundary, request: &LlmRequest) -> Result<String> {
    // LLM could suggest anything: "../../../etc/passwd", "C:/Windows/System32", etc.
    let safe_path = workspace.strict_join(&request.filename)?; // Attack = Error

    match request.operation.as_str() {
        "write" => safe_path.write_string(&request.content)?,
        "read" => return Ok(safe_path.read_to_string()?),
        _ => return Err("Invalid operation".into()),
    }
    Ok(format!("File {} processed safely", safe_path.strictpath_display()))
}
```

### Zip Extraction (Zip Slip Prevention)
```rust
use strict_path::VirtualRoot;

// Encode guarantees in signature: pass the extract root and untrusted entry names
fn extract_zip(zip_entries: impl IntoIterator<Item=(String, Vec<u8>)>, extract_root: &VirtualRoot) -> std::io::Result<()> {
    for (name, data) in zip_entries {
        // Hostile names like "../../../etc/passwd" get clamped to "/etc/passwd"
        let vpath = extract_root.virtual_join(&name)?;
        vpath.create_parent_dir_all()?;
        vpath.write_bytes(&data)?;
    }
    Ok(())
}
```

### Web File Server
```rust
use strict_path::PathBoundary;

struct StaticFiles;

async fn serve_static(static_dir: &PathBoundary<StaticFiles>, path: &str) -> Result<Response> {
    let safe_path = static_dir.strict_join(path)?; // "../../../" → Error
    Ok(Response::new(safe_path.read_bytes()?))
}

// Function signature prevents bypass - no validation needed inside!
async fn serve_file(safe_path: &strict_path::StrictPath<StaticFiles>) -> Response {
    Response::new(safe_path.read_bytes().unwrap_or_default())
}
```

### Configuration Manager
```rust
use strict_path::PathBoundary;

struct UserConfigs;

fn load_user_config(config_dir: &PathBoundary<UserConfigs>, config_name: &str) -> Result<Config> {
    let config_file = config_dir.strict_join(config_name)?;
    Ok(serde_json::from_str(&config_file.read_to_string()?)?)
}
```

## ⚠️ **Security Scope**

**What this protects against (99% of attacks):**
- Path traversal (`../../../etc/passwd`)  
- Symlink escapes and directory bombs
- Archive extraction attacks (zip slip)
- Unicode/encoding bypass attempts
- Windows-specific attacks (8.3 names, UNC paths)
- Race conditions during path resolution

**What requires system-level privileges (rare):**
- **Hard links**: Multiple filesystem entries to same file data
- **Mount points**: Admin/root can redirect paths via filesystem mounts

**Bottom line**: If attackers have root/admin access, they've already won. This library stops the 99% of practical attacks that don't require special privileges.

## 📋 **Input Source Decision Matrix**

| Source                      | Typical Input                  | Use VirtualPath For                       | Use StrictPath For        | Notes                                                   |
| --------------------------- | ------------------------------ | ----------------------------------------- | ------------------------- | ------------------------------------------------------- |
| 🌐 **HTTP requests**         | URL path segments, file names  | Display/logging, safe virtual joins       | System-facing interop/I/O | Always clamp user paths via `VirtualRoot::virtual_join` |
| 🌍 **Web forms**             | Form file fields, route params | User-facing display, UI navigation        | System-facing interop/I/O | Treat all form inputs as untrusted                      |
| ⚙️ **Configuration files**   | Paths in config                | UI display and I/O within boundary        | System-facing interop/I/O | Validate each path before I/O                           |
| 💾 **Database content**      | Stored file paths              | Rendering paths in UI dashboards          | System-facing interop/I/O | Storage does not imply safety; validate on use          |
| 📂 **CLI arguments**         | Command-line path args         | Pretty printing, I/O within boundary      | System-facing interop/I/O | Validate args before touching filesystem                |
| 🔌 **External APIs**         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs           | System-facing interop/I/O | Never trust external systems                            |
| 🤖 **LLM/AI output**         | Generated file names/paths     | Display suggestions, I/O within boundary  | System-facing interop/I/O | LLM output is untrusted by default                      |
| 📨 **Inter-service msgs**    | Queue/event payloads           | Observability output, I/O within boundary | System-facing interop/I/O | Validate on the consumer side                           |
| 📱 **Apps (desktop/mobile)** | Drag-and-drop, file pickers    | Show picked paths in UI                   | System-facing interop/I/O | Validate selected paths before I/O                      |
| 📦 **Archive contents**      | Entry names from ZIP/TAR       | Progress UI, virtual joins                | System-facing interop/I/O | Validate each entry to block zip-slip                   |
| 🔧 **File format internals** | Embedded path strings          | Diagnostics, I/O within boundary          | System-facing interop/I/O | Never dereference without validation                    |

Note: This is not “StrictPath vs VirtualPath.” `VirtualPath` conceptually extends `StrictPath` with a virtual-root view and restricted, path boundary-aware operations. Both support I/O and interop; choose based on whether you need virtual, user-facing path semantics or raw system-facing semantics.

**Think of it this way:**
- `StrictPath` = **Security Filter** — validates and rejects unsafe paths
- `VirtualPath` = **Complete Sandbox** — clamps any input to stay safe

**Unified Signatures (When Appropriate)**: Prefer marker-specific `&StrictPath<Marker>` for stronger guarantees. Use a generic `&StrictPath<_>` only when the function is intentionally shared across contexts; call with `vpath.as_unvirtual()` when starting from a `VirtualPath`.

```rust
use strict_path::{PathBoundary, VirtualRoot};

fn process_file<M>(path: &strict_path::StrictPath<M>) -> std::io::Result<Vec<u8>> {
  path.read_bytes()
}

// Call with either type
let boundary = PathBoundary::try_new("directory")?;
let spath = boundary.strict_join("file.txt")?;
process_file(&spath)?;

let vroot = VirtualRoot::try_new("directory")?;
let vpath = vroot.virtual_join("file.txt")?;
process_file(vpath.as_unvirtual())?;
```

## 🔐 **Advanced: Type-Safe Context Separation**

Use markers to prevent mixing different storage contexts at compile time:

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

struct WebAssets;    // CSS, JS, images  
struct UserFiles;    // Uploaded documents

// Functions enforce context via type system
fn serve_asset(path: &StrictPath<WebAssets>) -> Response { /* ... */ }
fn process_upload(path: &StrictPath<UserFiles>) -> Result<()> { /* ... */ }

// Create context-specific boundaries
let assets_root: VirtualRoot<WebAssets> = VirtualRoot::try_new("public")?;
let uploads_root: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;

let css: VirtualPath<WebAssets> = assets_root.virtual_join("app.css")?;
let doc: VirtualPath<UserFiles> = uploads_root.virtual_join("report.pdf")?;

// Type system prevents context mixing
serve_asset(&css.unvirtual());         // ✅ Correct context
// serve_asset(&doc.unvirtual());      // ❌ Compile error!
```

**Your IDE and compiler become security guards.**

**App Configuration with `app_path`:**
```rust
// ❌ Vulnerable - app dirs + user paths
use app_path::AppPath;
let app_dir = AppPath::new("MyApp").get_app_dir();
let config_file = app_dir.join(user_config_name); // 🚨 Potential escape
fs::write(config_file, settings)?;

// ✅ Protected - bounded app directories  
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new_create(AppPath::new("MyApp").get_app_dir())?;
let safe_config = boundary.strict_join(user_config_name)?; // ✅ Validated
safe_config.write_string(&settings)?;
```

## ⚠️ Anti-Patterns (Tell‑offs and Fixes)

### DON'T Mix Interop with Display

```rust
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new("uploads")?;

// ❌ ANTI-PATTERN: Wrong method for display
println!("Path: {}", boundary.interop_path().to_string_lossy());

// ✅ CORRECT: Use proper display methods
println!("Path: {}", boundary.strictpath_display());

// For VirtualRoot, access the underlying StrictPath:
use strict_path::VirtualRoot;
let vroot = VirtualRoot::try_new("uploads")?;
println!("Path: {}", vroot.as_unvirtual().strictpath_display());
```

**Why this matters:**
- `interop_path()` is designed for external API interop (`AsRef<Path>`)
- `*_display()` methods are designed for human-readable output
- Mixing concerns makes code harder to understand and maintain

### Web Server File Serving
```rust
struct StaticFiles; // Marker for static assets

async fn serve_static_file(safe_path: &StrictPath<StaticFiles>) -> Result<Response> {
    // Function signature enforces safety - no validation needed inside!
    Ok(Response::new(safe_path.read_bytes()?))
}

// Caller handles validation once:
let static_files_dir = PathBoundary::<StaticFiles>::try_new("./static")?;
let safe_path = static_files_dir.strict_join(&user_requested_path)?;
serve_static_file(&safe_path).await?;
```

### Archive Extraction (Zip Slip Prevention)
```rust
let extract_root = VirtualRoot::try_new("./extracted")?;
for (name, data) in zip_entries {
    let vpath = extract_root.virtual_join(&name)?;  // Neutralizes zip slip (clamps hostile)
    vpath.create_parent_dir_all()?;
    vpath.write_bytes(&data)?;
}
```



```

### Cloud Storage API
```rust
// User chooses any path - always safe
let user_storage = VirtualRoot::try_new(format!("/cloud/user_{id}"))?;
let file_path = user_storage.virtual_join(&user_requested_path)?;
file_path.write_bytes(upload_data)?;
```

### Configuration Files
```rust
use strict_path::PathBoundary;

// Encode guarantees via the signature: pass the boundary and an untrusted name
fn load_config(config_dir: &PathBoundary, name: &str) -> Result<String> {
    config_dir.strict_join(name)?.read_to_string()
}
```




- Constructing boundaries/roots inside helpers
  - Helpers shouldn’t decide policy. Take a `&PathBoundary`/`&VirtualRoot` and a name, or accept a `&StrictPath`/`&VirtualPath`.
- Wrapping secure types in std paths
  - Don’t wrap `interop_path()` in `Path::new`/`PathBuf::from`; pass `interop_path()` directly to `AsRef<Path>` APIs.




### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_workspace = PathBoundary::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_workspace.strict_join(ai_suggested_path)?; // Guaranteed safe
safe_ai_path.write_string(&ai_generated_content)?;
```



## 📚 **API Quick Reference**

| Feature            | `Path`/`PathBuf`                            | `StrictPath`                        | `VirtualPath`                                      |
| ------------------ | ------------------------------------------- | ----------------------------------- | -------------------------------------------------- |
| **Security**       | None 💥                                      | Validates & rejects ✅               | Clamps any input ✅                                 |
| **Join safety**    | Unsafe (can escape)                         | Boundary-checked                    | Boundary-clamped                                   |
| **Example attack** | `"../../../etc/passwd"` → **System breach** | `"../../../etc/passwd"` → **Error** | `"../../../etc/passwd"` → **`/etc/passwd`** (safe) |
| **Best for**       | Known-safe paths                            | System boundaries                   | User interfaces                                    |

```rust
// StrictPath - validate and reject
let boundary = PathBoundary::try_new("uploads")?;
let path = boundary.strict_join("file.txt")?; // Error if unsafe

// VirtualPath - clamp any input safely  
let vroot = VirtualRoot::try_new("userspace")?;
let vpath = vroot.virtual_join("any/path/here")?; // Always works

// Both support the same I/O operations
path.write_bytes(data)?;
vpath.read_to_string()?;
```

## 📚 **Documentation & Resources**

- **📖 [Complete API Reference](https://docs.rs/strict-path)** - Comprehensive API documentation
- **📚 [User Guide & Examples](https://dk26.github.io/jailed-path-rs/)** - In-depth tutorials and patterns  
- **🔧 [API_REFERENCE.md](API_REFERENCE.md)** - Quick reference for all methods
- **🛠️ [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - The underlying path resolution engine

## 🔌 **Integrations**

- **🗂️ OS Directories** (`dirs` feature): `PathBoundary::try_new_os_config()`, `try_new_os_downloads()`, etc.
- **📄 Serde** (`serde` feature): Safe serialization/deserialization of path types
- **🌐 Axum**: Custom extractors for web servers (see `demos/` for examples)

## 📄 **License**

MIT OR Apache-2.0
