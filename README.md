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

Your next security audit becomes: *"We use jailed-path."* ✅

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
let safe_path = jail.jailed_join("user/input/file.txt")?;

// 3. Prefer encoding guarantees in function signatures
fn store_report(path: &jailed_path::JailedPath) -> std::io::Result<()> {
    // Implement your logic; `path` is proven inside the jail
    path.write_string("content")
}

store_report(&safe_path)?; // Type system enforces correct usage
```



## 🛡️ **Security Features**

- **Beyond Simple Path Comparison**: This isn't just string matching - paths are fully resolved to their absolute, canonical form and rigorously boundary-checked against known attack patterns
- **CVE-Aware Protection**: Our validation algorithms are informed by real-world CVEs and directory traversal vulnerabilities across multiple programming languages and platforms
- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the jail
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **Windows Security**: Handles DOS 8.3 short names (`PROGRA~1`) as potential attack vectors
- **Symlink Safe**: Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) for proper resolution
- **Zero Allocation Interop**: `.interop_path()` for external APIs that expect `AsRef<Path>`
- **Misuse Resistant**: API design makes it hard to accidentally bypass security

**Core Security Principle: Jail Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a jail‑enforced type (`JailedPath` or `VirtualPath`) before I/O.

## 🤔 **Which Type Should I Use?**

| **Your Use Case**                              | **Recommended Type**   | **Why**                                                 |
| ---------------------------------------------- | ---------------------- | ------------------------------------------------------- |
| **Per-user storage, isolated workspaces**      | `VirtualPath`          | Each user gets their own sandbox with apparent "/" root |
| **Shared config, templates, common resources** | `JailedPath`           | Multiple users access same protected boundary           |
| **User uploads with personalized spaces**      | `VirtualPath`          | Users feel they own their space (`/docs/report.pdf`)    |
| **System configs that users can customize**    | `JailedPath`           | Shared area with validated boundaries                   |
| **Any external/untrusted path input**          | Either (both are safe) | `VirtualPath` clamps, `JailedPath` validates            |
| **Need compile-time type separation**          | Both with markers      | `VirtualPath<UserSpace>` vs `JailedPath<Config>`        |
| **No security constraints needed**             | `std::path::Path`      | When you truly need unrestricted access                 |

**Quick Decision:**
- **User Sandboxes** → `VirtualPath` 
- **Shared Boundaries** → `JailedPath`
- **Unrestricted** → `std::path::Path`

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
let safe_path = jail.jailed_join(user_input)?;  // ✅ Attack neutralized!

safe_path.write_bytes(b"data")?;  // Guaranteed safe within ./uploads/
assert!(safe_path.jailedpath_starts_with(jail.path()));  // Mathematical proof
```

### One-Liner Patterns
```rust
use jailed_path::{Jail, VirtualRoot};

// Quick file operations in a single chain
let content = Jail::<()>::try_new_create("safe_dir")?.jailed_join("file.txt")?.write_string("data")?;

// Virtual path with nested directories
VirtualRoot::<()>::try_new_create("user_space")?
    .virtual_join("docs/report.pdf")?
    .create_parent_dir_all().and_then(|vp| vp.write_bytes(pdf_data))?;

// Validation + operation in one expression
let size = jail.jailed_join("data.txt")?.read_bytes()?.len();
```

### The Old Way vs. The New Way
```rust
// 🚨 DANGEROUS - Every external path is a potential vulnerability
std::fs::read(format!("./uploads/{}", user_path))  // One day this kills your server

// ✅ SECURE - Function signature makes bypass impossible
fn serve_file<M>(safe_path: &jailed_path::JailedPath<M>) -> std::io::Result<Vec<u8>> {
  safe_path.read_bytes()
}
```

### Virtual Paths: User-Friendly + Secure
```rust
use jailed_path::VirtualRoot;

// Each user gets their own secure sandbox
let storage = VirtualRoot::try_new(format!("/srv/users/{user_id}"))?;

// User requests any path - we clamp it safely
let user_request = "photos/vacation/beach.jpg";  // or "../../../secrets" (blocked!)
let vpath = storage.virtual_join(user_request)?;

// Recommended pattern: accept `VirtualPath` in function signatures
fn save_image(path: &jailed_path::VirtualPath) -> std::io::Result<()> {
    path.write_bytes(b"...image bytes...")
}

save_image(&vpath)?;            // Type system guarantees correctness
let display = vpath.virtualpath_display();
println!("User sees: {display}"); // Virtual root path
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

| Source                  | Typical Input                  | Use VirtualPath For                                          | Use JailedPath For                      | Notes                                                   |
| ----------------------- | ------------------------------ | ------------------------------------------------------------ | --------------------------------------- | ------------------------------------------------------- |
| 🌐 HTTP requests         | URL path segments, file names  | Display/logging, safe virtual joins, and I/O within the jail | System-facing interop/I/O (alternative) | Always clamp user paths via `VirtualRoot::virtual_join` |
| 🌍 Web forms             | Form file fields, route params | User-facing display; UI navigation; I/O within the jail      | System-facing interop/I/O (alternative) | Treat all form inputs as untrusted                      |
| ⚙️ Configuration files   | Paths in config                | UI display and I/O within the jail                           | System-facing interop/I/O (alternative) | Validate each path before I/O                           |
| 💾 Database content      | Stored file paths              | Rendering paths in UI dashboards; I/O within the jail        | System-facing interop/I/O (alternative) | Storage does not imply safety; validate on use          |
| 📂 CLI arguments         | Command-line path args         | Pretty printing; I/O within the jail                         | System-facing interop/I/O (alternative) | Validate args before touching the FS                    |
| 🔌 External APIs         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs; I/O within the jail         | System-facing interop/I/O (alternative) | Never trust external systems                            |
| 🤖 LLM/AI output         | Generated file names/paths     | Display suggestions; I/O within the jail                     | System-facing interop/I/O (alternative) | LLM output is untrusted by default                      |
| 📨 Inter-service msgs    | Queue/event payloads           | Observability output; I/O within the jail                    | System-facing interop/I/O (alternative) | Validate on the consumer side                           |
| 📱 Apps (desktop/mobile) | Drag-and-drop, file pickers    | Show picked paths in UI; I/O within the jail                 | System-facing interop/I/O (alternative) | Validate selected paths before I/O                      |
| 📦 Archive contents      | Entry names from ZIP/TAR       | Progress UI, virtual joins, and I/O within the jail          | System-facing interop/I/O (alternative) | Validate each entry to block zip-slip                   |
| 🔧 File format internals | Embedded path strings          | Diagnostics and I/O within the jail                          | System-facing interop/I/O (alternative) | Never dereference without validation                    |

Note: This is not “JailedPath vs VirtualPath.” `VirtualPath` conceptually extends `JailedPath` with a virtual-root view and restricted, jail-aware operations. Both support I/O and interop; choose based on whether you need virtual, user-facing path semantics or raw system-facing semantics.

**Think of it this way:**
- `JailedPath` = **Security Filter** — validates that a path is safe and rejects unsafe paths, then lets you work with the proven-safe path for I/O operations
- `VirtualPath` = **Complete Sandbox** — contains the filter AND creates a virtualized environment where users can specify any path they want, and it gets automatically clamped to stay safe rather than rejected

**Unified Signatures (When Appropriate)**: Prefer marker-specific `&JailedPath<Marker>` for stronger guarantees. Use a generic `&JailedPath<_>` only when the function is intentionally shared across contexts; call with `vpath.as_unvirtual()` when starting from a `VirtualPath`.

```rust
fn process_file<M>(path: &jailed_path::JailedPath<M>) -> std::io::Result<Vec<u8>> {
  path.read_bytes()
}

// Call with either type
process_file(&jailed_path)?;
process_file(virtual_path.as_unvirtual())?;
```

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

let css: VirtualPath<WebAssets> = assets_vroot.virtual_join("style.css")?;
let doc: VirtualPath<UserFiles> = uploads_vroot.virtual_join("report.pdf")?;

// Convert to `JailedPath` only where the function requires it
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
use jailed_path::Jail;
let jail = Jail::try_new_create("uploads")?;
let safe_path = jail.jailed_join(get_user_input())?; // Attack blocked
safe_path.write_bytes(data)?; // ✅ Guaranteed safe
```

**Working with `tempfile`:**
```rust
// ❌ Vulnerable - temp directory + user paths
use tempfile::tempdir;
let temp = tempdir()?;
let user_file = temp.path().join(user_input); // 🚨 Can escape tempdir
fs::write(user_file, data)?;

// ✅ Protected - jailed temp operations
use jailed_path::Jail;
let jail = Jail::try_new(tempdir()?.path())?;
let safe_file = jail.jailed_join(user_input)?; // ✅ Cannot escape
safe_file.write_bytes(data)?;
```

**App Configuration with `app_path`:**
```rust
// ❌ Vulnerable - app dirs + user paths
use app_path::AppPath;
let app_dir = AppPath::new("MyApp").get_app_dir();
let config_file = app_dir.join(user_config_name); // 🚨 Potential escape
fs::write(config_file, settings)?;

// ✅ Protected - jailed app directories  
use jailed_path::Jail;
let jail = Jail::try_new_create(AppPath::new("MyApp").get_app_dir())?;
let safe_config = jail.jailed_join(user_config_name)?; // ✅ Validated
safe_config.write_string(&settings)?;
```

### Web Server File Serving
```rust
async fn serve_static_file(path: String) -> Result<Response> {
    let public_jail = Jail::try_new("./static")?;
    let safe_path = public_jail.jailed_join(&path)?;  // Blocks all traversal attacks
    Ok(Response::new(safe_path.read_bytes()?))
}
```

### Archive Extraction (Zip Slip Prevention)
```rust
let extract_jail = Jail::try_new("./extracted")?;
for entry in zip_archive.entries() {
    let safe_path = extract_jail.jailed_join(entry.path())?;  // Neutralizes zip slip
    safe_path.write_bytes(entry.data())?;
}
```

### Using With Archive Extractors (Recommended Pattern)
When processing untrusted archive entries (ZIP/TAR), prefer VirtualRoot so hostile names are clamped rather than failing the whole extraction:

```rust
use jailed_path::VirtualRoot;

fn extract_all(dest: &std::path::Path, entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
  let vroot: VirtualRoot<()> = VirtualRoot::try_new_create(dest)?;
  for (name, data) in entries {
    // Map entry name to a safe path inside the jail
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
- Always join entry names through VirtualRoot/Jail; never concatenate strings
- Accept absolute, UNC, or drive-relative names — virtual_join clamps them safely
- On Windows, ADS like `file.txt:stream` stays inside the jail or is rejected by the OS
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
fn load_config(config_name: &str) -> Result<String> {
    let config_jail = Jail::try_new("./config")?;
    let safe_path = config_jail.jailed_join(config_name)?;
    safe_path.read_to_string()
}
```

### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_jail = Jail::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_jail.jailed_join(ai_suggested_path)?; // Guaranteed safe
safe_ai_path.write_string(&ai_generated_content)?;
```

```rust
use jailed_path::Jail;

// 1. Create a jail
let jail = Jail::try_new_create("safe_directory")?;  // Creates dir if needed

// 2. Validate any external path
let safe_path = jail.jailed_join("user/input/file.txt")?;

// 3. Use normal file operations - guaranteed safe
safe_path.read_to_string()?;
safe_path.write_string("content")?;
safe_path.create_dir_all()?;
```

## 📚 **Core API At a Glance**

### System-Facing Paths (JailedPath)
```rust
let jail = Jail::try_new("directory")?;
let path = jail.jailed_join("file.txt")?;

// Prefer signatures that require `JailedPath`
fn read_file(p: &jailed_path::JailedPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
fn write_file(p: &jailed_path::JailedPath, s: &str) -> std::io::Result<()> { p.write_string(s) }
let _ = read_file(&path)?; write_file(&path, "data")?;

// Safe path operations
path.jailed_join("subdir")?;
path.jailedpath_parent()?;

// External API interop
external_function(path.interop_path());  // No allocation
```

### Concept Comparison

| Feature                   | `Path`/`PathBuf`                    | `JailedPath`                     | `VirtualPath`                                                                   |
| ------------------------- | ----------------------------------- | -------------------------------- | ------------------------------------------------------------------------------- |
| **Absolute join safety**  | Unsafe (replaces path) 💥            | Secure (validates boundaries) ✅  | Secure (clamps to root) ✅                                                       |
| **Relative join safety**  | Unsafe (can escape) 💥               | Secure (validates boundaries) ✅  | Secure (clamps to root) ✅                                                       |
| **Boundary guarantee**    | None                                | Jailed (cannot escape)           | Jailed (virtual view)                                                           |
| **Input permissiveness**  | Any path (no validation)            | Only safe paths                  | Any input (auto-clamped)                                                        |
| **Display format**        | OS path                             | OS path                          | Virtual root path                                                               |
| **Example: good input**   | `"file.txt"` → `"file.txt"`         | `"file.txt"` → `"jail/file.txt"` | `"file.txt"` → `"/file.txt"`                                                    |
| **Example: attack input** | `"/etc/passwd"` → `"/etc/passwd"` 💥 | `"/etc/passwd"` → Error ❌        | `"/etc/passwd"` → virtual `/etc/passwd` (maps to `<virtual_root>/etc/passwd`) ✅ |
| **Typical use case**      | Low-level, unvalidated              | System operations (jail-safe)    | User-facing paths (UI/UX)                                                       |

### Equality, Ordering, and Hashing

- `VirtualPath` Eq/Ord/Hash are based on the underlying system-facing path (same as `JailedPath`).
- Cross-type comparisons are supported: a `VirtualPath<Marker>` equals a `JailedPath<Marker>` if they refer to the same system-facing path within the same jail.
- This ensures consistent behavior in sets/maps. For lookups in maps keyed by `JailedPath`, call with `vpath.as_unvirtual()`.

**Security Critical:** `std::path::Path::join` with absolute paths completely replaces the base path → **#1 cause of path traversal vulnerabilities**.

### User-Facing Virtual Paths (VirtualPath)
```rust
let vroot = VirtualRoot::try_new("directory")?;
let vpath = vroot.virtual_join("file.txt")?;

let display = vpath.virtualpath_display();
println!("{display}");  // "/file.txt" (rooted view)

// Prefer signatures that require `VirtualPath`
fn serve(p: &jailed_path::VirtualPath) -> std::io::Result<Vec<u8>> { p.read_bytes() }
let _ = serve(&vpath)?;

// Explicit names make intent obvious even without types in scope:
// p.join(..)              -> unsafe std join (can escape the jail) — avoid on untrusted inputs
// path.jailed_join(..)-> safe jailed join (validated not to escape)
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
  - Jailed system-facing dimension: `JailedPath` + `jailedpath_*` operations and direct I/O
- Edge cases: switch views explicitly
  - Upgrade: `JailedPath::virtualize()` to get virtual-root behavior for display/joins
  - Downgrade: `VirtualPath::unvirtual()` or `VirtualPath::as_unvirtual()` to get jailed system-facing operations like `jailed_join()`


## 📖 **Advanced Usage**

For complete API reference, see our [API_REFERENCE.md](API_REFERENCE.md).

For underlying path resolution without jailing, see [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize).

## 🔌 Integrations

- Serde (feature `serde`):
  - `JailedPath` and `VirtualPath` implement `Serialize`.
  - Deserialize into a `String`, then validate with a jail/virtual root:
    - `#[derive(serde::Deserialize)] struct Payload { file: String }`
    - `let p: Payload = serde_json::from_str(body)?;`
    - `let jp = jail.jailed_join(&p.file)?;` or `let vp = vroot.virtual_join(&p.file)?;`
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
