# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![CI](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/jailed-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)**

**Prevent directory traversal with type-safe path boundaries and safe symlinks**

> *The Type-State Police have set up PathBoundary checkpoints*  
> *keeping your unruly paths in line, because your LLM is running wild*

Never worry about `../../../etc/passwd` again. Strict-path provides compile-time guarantees that external paths stay exactly where you want them.

## 🔓 **Why Path Security Is Hard**

Directory traversal vulnerabilities are **everywhere**. Getting path validation right yourself means:

- Understanding platform-specific canonicalization quirks (Windows 8.3 names, case sensitivity, path separators)
- Handling symlinks safely without race conditions
- Staying current with new attack vectors and CVEs
- Carrying complex validation logic to every new project
- Convincing security auditors you got it right (again)

**We solve this once, correctly, so you don't have to.**

## 🛡️ **Automatic Protection Against Known Vulnerabilities**

This crate inherits protection against documented CVEs and attack patterns through our [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation:

### **Recently Addressed CVEs**
- **CVE-2025-8088** (WinRAR-style ADS Attacks): NTFS Alternate Data Stream path traversal prevention
- **CVE-2022-21658** (Race Conditions): TOCTOU attack protection during path resolution
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793** and others: Windows 8.3 short name vulnerabilities

### **Core Attack Vector Protection**
- **Path Traversal** (`../`, `..\\`, URL-encoded variants, Unicode bypasses)
- **Symlink Attacks** (symlink bombs, jail breaks, resolution edge cases)
- **Windows-Specific** (8.3 short names like `PROGRA~1`, UNC paths, NTFS ADS)
- **Unicode Normalization** (encoding bypasses, zero-width characters, mixed separators)
- **Race Conditions** (TOCTOU in path resolution, atomic filesystem changes)
- **Archive Extraction** (zip slip, tar slip vulnerabilities, malicious entry names)

Your next security audit becomes: *"We use strict-path."* ✅

## ⚡ **Installation & Quick Start**

```toml
[dependencies]
strict-path = "0.1.0-alpha.1"
```

```rust
use strict_path::PathBoundary;

// 1. Create a path boundary
let safe_dir = PathBoundary::try_new_create("safe_directory")?;  // Creates dir if needed

// 2. Validate any external path
let safe_path = safe_dir.strict_join("user/input/file.txt")?;

// 3. Prefer encoding guarantees in function signatures
fn store_report(path: &strict_path::StrictPath) -> std::io::Result<()> {
    // Implement your logic; `path` is proven inside the boundary
    path.write_string("content")
}

store_report(&safe_path)?; // Type system enforces correct usage
```



## 🛡️ **Security Features**

- **Beyond Simple Path Comparison**: This isn't just string matching - paths are fully resolved to their absolute, canonical form and rigorously boundary-checked against known attack patterns
- **CVE-Aware Protection**: Our validation algorithms are informed by real-world CVEs and directory traversal vulnerabilities across multiple programming languages and platforms
- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the boundary
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **Windows Security**: Handles DOS 8.3 short names (`PROGRA~1`) as potential attack vectors
- **Symlink Safe**: Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) for proper resolution
- **Zero Allocation Interop**: `.interop_path()` for external APIs that expect `AsRef<Path>`
- **Misuse Resistant**: API design makes it hard to accidentally bypass security

## 🛡️ **Core Security Foundation**

At the heart of this crate is **`StrictPath`** - the fundamental security primitive that provides our ironclad guarantee: **every `StrictPath` is mathematically proven to be within its boundary**. 

Everything in this crate builds upon `StrictPath`:
- `PathBoundary` creates and validates `StrictPath` instances
- `VirtualPath` extends `StrictPath` with user-friendly virtual root semantics  
- `VirtualRoot` provides a root context for creating `VirtualPath` instances

**The core promise:** If you have a `StrictPath<Marker>`, it is impossible for it to reference anything outside its designated boundary. This isn't just validation - it's a type-level guarantee backed by cryptographic-grade path canonicalization.


**Core Security Principle: Secure Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a boundary‑enforced type (`StrictPath` or `VirtualPath`) before I/O.

## 🤔 **Which Type Should I Use?**

| **Your Use Case**                              | **Recommended Type**   | **Why**                                                 |
| ---------------------------------------------- | ---------------------- | ------------------------------------------------------- |
| **Per-user storage, isolated workspaces**      | `VirtualPath`          | Each user gets their own sandbox with apparent "/" root |
| **Shared config, templates, common resources** | `StrictPath`           | Multiple users access same protected boundary           |
| **User uploads with personalized spaces**      | `VirtualPath`          | Users feel they own their space (`/docs/report.pdf`)    |
| **System configs that users can customize**    | `StrictPath`           | Shared area with validated boundaries                   |
| **Any external/untrusted path input**          | Either (both are safe) | `VirtualPath` clamps, `StrictPath` validates            |
| **Need compile-time type separation**          | Both with markers      | `VirtualPath<UserSpace>` vs `StrictPath<Config>`        |
| **No security constraints needed**             | `std::path::Path`      | When you truly need unrestricted access                 |

**Quick Decision:**
- **User Sandboxes** → `VirtualPath` 
- **Shared Boundaries** → `StrictPath`
- **Unrestricted** → `std::path::Path`

## 🔑 **CRITICAL: StrictPath vs Path/PathBuf**

**The fundamental security question is: "Do I control this path's source?"**

```rust
// ❌ DANGEROUS: External paths bypass all security
fn handle_user_upload(filename: &str) {
    let path = Path::new(filename);  // Could be "../../../etc/passwd"
    std::fs::write(path, data)?;     // Directory traversal attack!
}

// ✅ SECURE: External paths validated first  
fn handle_user_upload(filename: &str) -> Result<(), Box<dyn Error>> {
    let boundary = PathBoundary::try_new("uploads")?;
    let safe_path = boundary.strict_join(filename)?;  // Attack blocked!
    safe_path.write_bytes(data)?;  // Guaranteed safe
    Ok(())
}

// ✅ OK: Internal paths you generate yourself
fn create_temp_file(id: u32) -> PathBuf {
    PathBuf::from(format!("temp/file_{}.tmp", id))  // You control this
}
```

**Decision Matrix:**

| **Path Source**         | **Use This**   | **Example**                                 |
| ----------------------- | -------------- | ------------------------------------------- |
| HTTP request            | `StrictPath`   | `POST /api/files {"path": "docs/file"}`     |
| CLI arguments           | `StrictPath`   | `--output-dir /tmp/user_data`               |
| Configuration files     | `StrictPath`   | `output_directory = "user_uploads"`         |
| Database records        | `StrictPath`   | `SELECT file_path FROM user_files`          |
| LLM/AI responses        | `StrictPath`   | `"Save this to: important_docs/secret"`     |
| Archive entries         | `StrictPath`   | ZIP/TAR file entries from untrusted sources |
| **Your own generation** | `Path/PathBuf` | `format!("logs/{}.log", timestamp)`         |
| **Hardcoded literals**  | `Path/PathBuf` | `Path::new("config/app.toml")`              |

**Remember**: If you didn't generate the path yourself, treat it as potentially malicious.

## ⚠️ **Security Limitations**

This library operates at the **path level**, not the operating system level. While it provides strong protection against path traversal attacks using symlinks and standard directory navigation, it **cannot protect against** certain privileged operations:

- **Hard Links**: If a file is hard-linked outside the bounded path, accessing it through the boundary will still reach the original file data. Hard links create multiple filesystem entries pointing to the same inode.
- **Mount Points**: If a filesystem mount is introduced (by a system administrator or attacker with sufficient privileges) that redirects a path within the boundary to an external location, this library cannot detect or prevent access through that mount.

**Important**: These attack vectors require **high system privileges** (typically root/administrator access) to execute. If an attacker has such privileges on your system, they can bypass most application-level security measures anyway. This library effectively protects against the much more common and practical symlink-based traversal attacks that don't require special privileges.

Our symlink resolution via [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) handles the most accessible attack vectors that malicious users can create without elevated system access.

## 🚀 **Simple Examples**

### Basic Usage
```rust
use strict_path::PathBoundary;

// Any external input - HTTP requests, CLI args, config files, LLM output...
let user_input = "../../../etc/passwd";  // 🚨 This would be a security disaster

let boundary = PathBoundary::try_new("uploads")?;
let safe_path = boundary.strict_join(user_input)?;  // ✅ Attack neutralized!

safe_path.write_bytes(b"data")?;  // Guaranteed safe within ./uploads/
assert!(safe_path.strictpath_starts_with(boundary.path()));  // Mathematical proof
```

### One-Liner Patterns
```rust
use strict_path::{PathBoundary, VirtualRoot};

// Quick file operations in a single chain
let tmp_dir = tempfile::tempdir()?;
PathBoundary::<()>::try_new(&tmp_dir)?.strict_join("file.txt")?.write_string("data")?;

// Virtual path with nested directories
let tmp_dir = tempfile::tempdir()?;
let vp = VirtualRoot::<()>::try_new(&tmp_dir)?.virtual_join("docs/report.pdf")?;
vp.create_parent_dir_all().and_then(|_| vp.write_bytes(pdf_data))?;

// Validation + operation in one expression  
let tmp_dir = tempfile::tempdir()?;
let size = PathBoundary::<()>::try_new(&tmp_dir)?.strict_join("data.txt")?.read_bytes()?.len();
```

### The Old Way vs. The New Way
```rust
// 🚨 DANGEROUS - Every external path is a potential vulnerability
std::fs::read(format!("./uploads/{}", user_path))  // One day this kills your server

// ✅ SECURE - Function signature makes bypass impossible
fn serve_file<M>(safe_path: &strict_path::StrictPath<M>) -> std::io::Result<Vec<u8>> {
  safe_path.read_bytes()
}
```

### Virtual Paths: User-Friendly + Secure
```rust
use strict_path::VirtualRoot;

// Each user gets their own secure sandbox
let storage = VirtualRoot::try_new(format!("/srv/users/{user_id}"))?;

// User requests any path - we clamp it safely
let user_request = "photos/vacation/beach.jpg";  // or "../../../secrets" (blocked!)
let vpath = storage.virtual_join(user_request)?;

// Recommended pattern: accept `VirtualPath` in function signatures
fn save_image(path: &strict_path::VirtualPath) -> std::io::Result<()> {
    path.write_bytes(b"...image bytes...")
}

save_image(&vpath)?;            // Type system guarantees correctness
let display = vpath.virtualpath_display();
println!("User sees: {display}"); // Virtual root path
```

## 🚨 **What External Paths Need Securing**

**RULE: Each path from an uncontrolled environment should be secured.**

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

If it comes from outside your program's direct control, secure it.

## 🎯 **When to Use Each Type**

| Source                  | Typical Input                  | Use VirtualPath For                                              | Use StrictPath For                      | Notes                                                   |
| ----------------------- | ------------------------------ | ---------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------- |
| 🌐 HTTP requests         | URL path segments, file names  | Display/logging, safe virtual joins, and I/O within the boundary | System-facing interop/I/O (alternative) | Always clamp user paths via `VirtualRoot::virtual_join` |
| 🌍 Web forms             | Form file fields, route params | User-facing display; UI navigation; I/O within the boundary      | System-facing interop/I/O (alternative) | Treat all form inputs as untrusted                      |
| ⚙️ Configuration files   | Paths in config                | UI display and I/O within the boundary                           | System-facing interop/I/O (alternative) | Validate each path before I/O                           |
| 💾 Database content      | Stored file paths              | Rendering paths in UI dashboards; I/O within the boundary        | System-facing interop/I/O (alternative) | Storage does not imply safety; validate on use          |
| 📂 CLI arguments         | Command-line path args         | Pretty printing; I/O within the boundary                         | System-facing interop/I/O (alternative) | Validate args before touching the FS                    |
| 🔌 External APIs         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs; I/O within the boundary         | System-facing interop/I/O (alternative) | Never trust external systems                            |
| 🤖 LLM/AI output         | Generated file names/paths     | Display suggestions; I/O within the boundary                     | System-facing interop/I/O (alternative) | LLM output is untrusted by default                      |
| 📨 Inter-service msgs    | Queue/event payloads           | Observability output; I/O within the boundary                    | System-facing interop/I/O (alternative) | Validate on the consumer side                           |
| 📱 Apps (desktop/mobile) | Drag-and-drop, file pickers    | Show picked paths in UI; I/O within the boundary                 | System-facing interop/I/O (alternative) | Validate selected paths before I/O                      |
| 📦 Archive contents      | Entry names from ZIP/TAR       | Progress UI, virtual joins, and I/O within the boundary          | System-facing interop/I/O (alternative) | Validate each entry to block zip-slip                   |
| 🔧 File format internals | Embedded path strings          | Diagnostics and I/O within the boundary                          | System-facing interop/I/O (alternative) | Never dereference without validation                    |

Note: This is not “StrictPath vs VirtualPath.” `VirtualPath` conceptually extends `StrictPath` with a virtual-root view and restricted, path boundary-aware operations. Both support I/O and interop; choose based on whether you need virtual, user-facing path semantics or raw system-facing semantics.

**Think of it this way:**
- `StrictPath` = **Security Filter** — validates that a path is safe and rejects unsafe paths, then lets you work with the proven-safe path for I/O operations
- `VirtualPath` = **Complete Sandbox** — contains the filter AND creates a virtualized environment where users can specify any path they want, and it gets automatically clamped to stay safe rather than rejected

**Unified Signatures (When Appropriate)**: Prefer marker-specific `&StrictPath<Marker>` for stronger guarantees. Use a generic `&StrictPath<_>` only when the function is intentionally shared across contexts; call with `vpath.as_unvirtual()` when starting from a `VirtualPath`.

```rust
fn process_file<M>(path: &strict_path::StrictPath<M>) -> std::io::Result<Vec<u8>> {
  path.read_bytes()
}

// Call with either type
process_file(&strict_path)?;
process_file(virtual_path.as_unvirtual())?;
```

## 🌟 **Advanced Examples**

### Multi-Boundary Type Safety (The Coolest Feature!)

Prevent accidentally mixing different storage contexts at compile time:

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

struct WebAssets;    // CSS, JS, images
struct UserFiles;    // Uploaded documents

// Functions with type-safe security contracts
fn serve_asset(path: &StrictPath<WebAssets>) { /* ... read_bytes/write_bytes ... */ }
fn process_upload(path: &StrictPath<UserFiles>) { /* ... */ }

// Ingest untrusted paths as VirtualPath per boundary
let assets_vroot: VirtualRoot<WebAssets> = VirtualRoot::try_new("public")?;
let uploads_vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("user_data")?;

let css: VirtualPath<WebAssets> = assets_vroot.virtual_join("style.css")?;
let doc: VirtualPath<UserFiles> = uploads_vroot.virtual_join("report.pdf")?;

// Convert to `StrictPath` only where the function requires it
serve_asset(&css.unvirtual());         // ✅ Correct context
// serve_asset(&doc.unvirtual());      // ❌ Compile error - prevents mixing!
```

Your IDE and compiler become security guards.

### Drop-In Replacement Patterns

Transform vulnerable code with minimal changes:

**File Operations:**
```rust
// ❌ Vulnerable - direct user input to filesystem
use std::fs;
let user_path = get_user_input(); // Could be "../../../etc/passwd"
fs::write(user_path, data)?; // 🚨 Security disaster

// ✅ Protected - automatic validation
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new_create("uploads")?;
let safe_path = boundary.strict_join(get_user_input())?; // Attack blocked
safe_path.write_bytes(data)?; // ✅ Guaranteed safe
```

**Working with `tempfile`:**
```rust
// ❌ Vulnerable - temp directory + user paths
use tempfile::tempdir;
let temp = tempdir()?;
let user_file = temp.path().join(user_input); // 🚨 Can escape tempdir
fs::write(user_file, data)?;

// ✅ Protected - bounded temp operations
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new(tempdir()?.path())?;
let safe_file = boundary.strict_join(user_input)?; // ✅ Cannot escape
safe_file.write_bytes(data)?;
```

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
let extract_dir = PathBoundary::try_new("./extracted")?;
for entry in zip_archive.entries() {
    let safe_path = extract_dir.strict_join(entry.path())?;  // Neutralizes zip slip
    safe_path.write_bytes(entry.data())?;
}
```

### Using With Archive Extractors (Recommended Pattern)
When processing untrusted archive entries (ZIP/TAR), prefer VirtualRoot so hostile names are clamped rather than failing the whole extraction:

```rust
use strict_path::VirtualRoot;

fn extract_all(dest: &std::path::Path, entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
  let vroot: VirtualRoot<()> = VirtualRoot::try_new_create(dest)?;
  for (name, data) in entries {
    // Map entry name to a safe path inside the path boundary
    let vpath = match vroot.virtual_join(&name) {
      Ok(v) => v,
      Err(_) => continue, // reject bad entry, but keep extracting others
    };
    vpath.create_parent_dir_all()?;
    vpath.write_bytes(&data)?;
  }
  Ok(())
}
```

Best practices:
- Always join entry names through VirtualRoot/PathBoundary; never concatenate strings
- Accept absolute, UNC, or drive-relative names — virtual_join clamps them safely
- On Windows, ADS like `file.txt:stream` stays inside the path boundary or is rejected by the OS
- Validate symlink/junction behavior at runtime; our resolution rejects boundary escapes
- See docs: Using with Archive Extractors

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

### Other tell‑offs and the right way

- Validating only constants
  - If no untrusted segment ever flows through `strict_join`/`virtual_join`, the crate adds no value. Use `boundary.interop_path()` for discovery; validate actual external names (HTTP/DB/manifest/archive entries).
- Constructing boundaries/roots inside helpers
  - Helpers shouldn’t decide policy. Take a `&PathBoundary`/`&VirtualRoot` and a name, or accept a `&StrictPath`/`&VirtualPath`.
- Wrapping secure types in std paths
  - Don’t wrap `interop_path()` in `Path::new`/`PathBuf::from`; pass `interop_path()` directly to `AsRef<Path>` APIs.
- `interop_path().as_ref()` or `as_unvirtual().interop_path()`
  - `interop_path()` already implements `AsRef<Path>`; both `VirtualRoot` and `VirtualPath` expose it.
- Using std path ops on leaked values
  - Use `strict_join`/`virtual_join` and `strictpath_parent`/`virtualpath_parent`.
- Raw path parameters for safe helpers
  - Prefer `&StrictPath<_>`/`&VirtualPath<_>` (or boundary/root + segment) to encode guarantees.

### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_workspace = PathBoundary::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_workspace.strict_join(ai_suggested_path)?; // Guaranteed safe
safe_ai_path.write_string(&ai_generated_content)?;
```

```rust
use strict_path::PathBoundary;

// 1. Create a path boundary (aka jail)
let safe_directory_boundary = PathBoundary::try_new_create("safe_directory")?;  // Creates dir if needed

// 2. Validate any external path
let safe_new_path = safe_directory_boundary.strict_join("user/input/file.txt")?;

// 3. Use normal file operations - guaranteed safe
safe_path.read_to_string()?;
safe_path.write_string("content")?;
safe_path.create_dir_all()?;
```

## 📚 **Core API At a Glance**

### System-Facing Paths (StrictPath)
```rust
let boundary = PathBoundary::try_new("directory")?;
let path = boundary.strict_join("file.txt")?;

// Prefer signatures that require `StrictPath`
fn read_file(p: &strict_path::StrictPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
fn write_file(p: &strict_path::StrictPath, s: &str) -> std::io::Result<()> { p.write_string(s) }
let _ = read_file(&path)?; write_file(&path, "data")?;

// Safe path operations
path.strict_join("subdir")?;
path.strictpath_parent()?;

// External API interop
external_function(path.interop_path());  // No allocation
```

### Concept Comparison

| Feature                   | `Path`/`PathBuf`                    | `StrictPath`                              | `VirtualPath`                                                                   |
| ------------------------- | ----------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------- |
| **Absolute join safety**  | Unsafe (replaces path) 💥            | Secure (validates boundaries) ✅           | Secure (clamps to root) ✅                                                       |
| **Relative join safety**  | Unsafe (can escape) 💥               | Secure (validates boundaries) ✅           | Secure (clamps to root) ✅                                                       |
| **Boundary guarantee**    | None                                | Jailed (cannot escape)                    | Jailed (virtual view)                                                           |
| **Input permissiveness**  | Any path (no validation)            | Only safe paths                           | Any input (auto-clamped)                                                        |
| **Display format**        | OS path                             | OS path                                   | Virtual root path                                                               |
| **Example: good input**   | `"file.txt"` → `"file.txt"`         | `"file.txt"` → `"path boundary/file.txt"` | `"file.txt"` → `"/file.txt"`                                                    |
| **Example: attack input** | `"/etc/passwd"` → `"/etc/passwd"` 💥 | `"/etc/passwd"` → Error ❌                 | `"/etc/passwd"` → virtual `/etc/passwd` (maps to `<virtual_root>/etc/passwd`) ✅ |
| **Typical use case**      | Low-level, unvalidated              | System operations (boundary-safe)         | User-facing paths (UI/UX)                                                       |

### Equality, Ordering, and Hashing

- `VirtualPath` Eq/Ord/Hash are based on the underlying system-facing path (same as `StrictPath`).
- Cross-type comparisons are supported: a `VirtualPath<Marker>` equals a `StrictPath<Marker>` if they refer to the same system-facing path within the same boundary.
- This ensures consistent behavior in sets/maps. For lookups in maps keyed by `StrictPath`, call with `vpath.as_unvirtual()`.

**Security Critical:** `std::path::Path::join` with absolute paths completely replaces the base path → **#1 cause of path traversal vulnerabilities**.

### User-Facing Virtual Paths (VirtualPath)
```rust
let vroot = VirtualRoot::try_new("directory")?;
let vpath = vroot.virtual_join("file.txt")?;

let display = vpath.virtualpath_display();
println!("{display}");  // "/file.txt" (rooted view)

// Prefer signatures that require `VirtualPath`
fn serve(p: &strict_path::VirtualPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
let _ = serve(&vpath)?;

// Explicit names make intent obvious even without types in scope:
// p.join(..)              -> unsafe std join (can escape the path boundary) — avoid on untrusted inputs
// path.strict_join(..)-> safe strict join (validated not to escape)
// vpath.virtual_join(..)-> safe virtual join (virtual-absolute, clamped to VirtualRoot)
// The same naming applies to other ops: parent/with_file_name/with_extension/starts_with/ends_with.
```

### Creating Parent Directories
```rust
let vroot = VirtualRoot::try_new("data")?;
let report = vroot.virtual_join("reports/2025/q3/summary.txt")?;

// Create the full parent chain using virtual semantics
report.create_parent_dir_all()?;
report.write_string("contents")?;
```

### Switching Views: Upgrade or Downgrade
- Stay in one dimension for most flows:
  - Virtual user-facing dimension: `VirtualPath` + `virtualpath_*` operations and direct I/O
  - Bounded system-facing dimension: `StrictPath` + `strictpath_*` operations and direct I/O
- Edge cases: switch views explicitly
  - Upgrade: `StrictPath::virtualize()` to get virtual-root behavior for display/joins
  - Downgrade: `VirtualPath::unvirtual()` or `VirtualPath::as_unvirtual()` to get bounded system-facing operations like `strict_join()`


## 📖 **Advanced Usage**

For complete API reference, see our [API_REFERENCE.md](API_REFERENCE.md).

For underlying path resolution without jailing, see [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize).

## 🔌 Integrations

- **OS Standard Directories** (feature `dirs`):
  - Cross-platform access to standard directories following XDG Base Directory (Linux), Known Folder API (Windows), and Apple Standard Directories (macOS).
  - Application directories: `PathBoundary::try_new_os_config("MyApp")`, `try_new_os_data("MyApp")`, `try_new_os_cache("MyApp")`
  - User directories: `PathBoundary::try_new_os_documents()`, `try_new_os_downloads()`, `try_new_os_pictures()`, `try_new_os_audio()`, `try_new_os_videos()`
  - System directories: `try_new_os_home()`, `try_new_os_desktop()`, plus Unix-specific `try_new_os_executables()`, `try_new_os_runtime()`
  - Built on the [`dirs`](https://crates.io/crates/dirs) crate v6.0.0; see [OS Directories documentation](https://docs.rs/strict-path/) for complete platform compatibility

- **Serde** (feature `serde`):
  - `StrictPath` and `VirtualPath` implement `Serialize`.
  - Deserialize into a `String`, then validate with a path boundary/virtual root:
    - `#[derive(serde::Deserialize)] struct Payload { file: String }`
    - `let p: Payload = serde_json::from_str(body)?;`
    - `let jp = path_boundary.strict_join(&p.file)?;` or `let vp = vroot.virtual_join(&p.file)?;`
  - Or use context helpers for deserialization: `serde_ext::WithBoundary(&path_boundary)` / `serde_ext::WithVirtualRoot(&vroot)` with a serde Deserializer when you deserialize single values with context.

- **Axum** AppState + Extractors:
  - Store `VirtualRoot<Marker>` in state; validate `Path<String>` to `VirtualPath` per request.
  - Handlers and helpers accept `&VirtualPath<Marker>` or `&StrictPath<Marker>` so types enforce correctness.
  - See `demos/src/bin/web/axum_static_server.rs` for a minimal custom extractor and a JSON route.

- **app-path** (config dirs):
  - Use `app_path::app_path!("config", env = "APP_CONFIG_DIR")` to locate a config directory relative to the executable with an env override.
  - Create a jail there: `let cfg = Jail::try_new_create(cfg_dir)?;` and operate via `StrictPath`.

## 🧭 Markers (Type Inference)

- Default marker: `Marker = ()` for all types; inference usually works once a value is bound.
- If inference needs help, annotate the `let` or use an empty turbofish.
- Keep it readable: avoid turbofish unless it clarifies intent or is required.

```rust
// Inferred default marker
let vroot: VirtualRoot = VirtualRoot::try_new("user_data")?;
let vpath: VirtualPath = vroot.virtual_join("a.txt")?;

// When inference needs help
let vroot = VirtualRoot::<()>::try_new("user_data")?; // or: let vroot: VirtualRoot<()> = ...

// Custom marker
struct UserFiles;
let uploads: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;
let uploads = VirtualRoot::try_new::<UserFiles>("uploads")?;
```

## 📄 **License**

MIT OR Apache-2.0
