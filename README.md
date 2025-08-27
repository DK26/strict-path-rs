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
>

## 🎯 **Core Security Principle: Jail Every External Path**

**RULE: Each path that comes from an uncontrolled environment should be jailed.**

### About This Crate: JailedPath and VirtualPath

`JailedPath` is a system‑facing filesystem path type, mathematically proven (via canonicalization, boundary checks, and type‑state) to remain inside a configured jail directory. `VirtualPath` wraps a `JailedPath` and therefore guarantees everything a `JailedPath` guarantees — plus a rooted, forward‑slashed virtual view (treating the jail as "/") and safe virtual operations (joins/parents/file‑name/ext) that preserve clamping. Construct them with `Jail::try_new(jail_path)` and `VirtualRoot::try_new(virtual_root_path)`. Ingest untrusted paths as `VirtualPath` for UI/UX and safe joins; convert to `JailedPath` only where you perform actual I/O.

### Which Type To Use (By Source)

| Source                  | Typical input                  | Use `VirtualPath` for…                                   | Use `JailedPath` for…               | Notes                                                       |
| ----------------------- | ------------------------------ | -------------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------- |
| 📡 HTTP requests         | URL path segments, file names  | Display/logging, safe virtual joins (`join_virtualpath`) | Actual file I/O after `unvirtual()` | Always clamp user paths via `VirtualRoot::try_path_virtual` |
| 🌐 Web forms             | Form file fields, route params | User‑facing display; UI navigation                       | I/O (reads/writes)                  | Treat all form inputs as untrusted                          |
| ⚙️ Configuration files   | Paths in config                | Optional UI display of config paths                      | Validated access to config files    | Validate each path before I/O                               |
| 💾 Database content      | Stored file paths              | Rendering paths in UI dashboards                         | Reads/writes on stored paths        | Storage does not imply safety; validate on use              |
| 📂 CLI arguments         | Command‑line path args         | Optional pretty printing                                 | I/O in tools/CLIs                   | Validate args before touching the FS                        |
| 🔌 External APIs         | Webhooks, 3rd‑party payloads   | Present sanitized paths to logs                          | I/O after validation                | Never trust external systems                                |
| 🤖 LLM/AI output         | Generated file names/paths     | Display suggestions safely                               | I/O only after validation           | LLM output is untrusted by default                          |
| 📨 Inter‑service msgs    | Queue/event payloads           | Observability output                                     | Any file operations                 | Validate on the consumer side                               |
| 📱 Apps (desktop/mobile) | Drag‑and‑drop, file pickers    | Show picked paths in UI                                  | Open/save operations                | Validate selected paths before I/O                          |
| 📦 Archive contents      | Entry names from ZIP/TAR       | Progress UI, virtual joins                               | Extract/write entries               | Validate each entry to block zip‑slip                       |
| 🔧 File format internals | Embedded path strings          | Diagnostics                                              | Any dereference of embedded paths   | Never dereference without validation                        |

Rule of thumb
- Use `VirtualRoot::try_path_virtual(..)` to accept untrusted input and get a `VirtualPath` for UI and safe path manipulation.
- Convert to `JailedPath` via `vp.unvirtual()` only where you perform I/O or pass to APIs requiring a system path.
- For AsRef<Path> interop, pass `jailed_path.systempath_as_os_str()` (no allocation).

---

 


## The Problem

Every external path is a potential security vulnerability:

```rust
// 🚨 DANGEROUS - Directory traversal attack
std::fs::read(format!("./uploads/{}", user_path))  // user_path = "../../../etc/passwd"
```

## Simple API Usage

```rust
use jailed_path::Jail;

// External path from HTTP request, CLI arg, config file, etc.
let user_provided_path = "documents/invoice-2024.pdf";  // From external source
let malicious_input = "../../../etc/passwd";  // Attacker input

let jail = Jail::try_new("customer_uploads")?;
let safe_path = jail.try_path(user_provided_path)?;  // Validates external input
let attack_path = jail.try_path(malicious_input)?;   // Attack neutralized!

safe_path.write_bytes(b"data")?;  // Safe within ./customer_uploads
assert!(attack_path.starts_with_systempath(jail.path()));  // Proof: contained
```

## Mathematical Security: Functions Require Validation

```rust
use jailed_path::JailedPath;

// ✅ SECURE - Function signature makes bypass impossible
fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
    safe_path.read_bytes()  // No way to call this with unsafe path
}

// serve_file("/etc/passwd");           // ❌ Compile error - needs JailedPath
// serve_file(&std::path::Path::new("../../../etc/passwd")); // ❌ Compile error
```

## Multi-Jail Type Safety (The Coolest Feature!)

```rust
struct WebAssets;
struct UserUploads;

// Functions with type-safe security contracts
fn serve_public_asset(asset: &JailedPath<WebAssets>) -> Result<Vec<u8>, std::io::Error> {
    asset.read_bytes()  // ✅ ONLY accepts WebAssets paths
}

fn process_user_upload(upload: &JailedPath<UserUploads>) -> Result<(), std::io::Error> {
    upload.write_string("processed")  // ✅ ONLY accepts UserUploads paths  
}

let assets_jail: Jail<WebAssets> = Jail::try_new("assets")?;
let uploads_jail: Jail<UserUploads> = Jail::try_new("uploads")?;

// External paths from different sources
let css_request = "style.css";        // From HTTP request for assets
let upload_filename = "avatar.jpg";   // From file upload form

let css_file: JailedPath<WebAssets> = assets_jail.try_path(css_request)?;
let user_file: JailedPath<UserUploads> = uploads_jail.try_path(upload_filename)?;

serve_public_asset(&css_file)?;   // ✅ Correct type - compiles
process_user_upload(&user_file)?; // ✅ Correct type - compiles

// serve_public_asset(&user_file)?;   // ❌ COMPILE ERROR: wrong context!
// process_user_upload(&css_file)?;   // ❌ COMPILE ERROR: prevents mixing!
```

## Real-World Examples

### Archive Extraction (Zip Slip Prevention)
```rust
// Safe archive extraction
let extract_jail = Jail::try_new("./extracted")?;
for entry in archive.entries() {
    let safe_path = extract_jail.try_path(entry.path())?;  // Contains "../../../etc/passwd"
    safe_path.write_bytes(entry.data())?;  // Safe within ./extracted
}
```

### Web Server
```rust
async fn serve_file(path: String) -> Result<Response> {
    let public_jail = Jail::try_new("./public")?;
    let safe_path = public_jail.try_path(&path)?;  // Blocks traversal attacks
    Ok(Response::new(safe_path.read_bytes()?))
}
```

### Configuration Processing
```rust
fn load_config_file(config_path: &str) -> Result<String> {
    let config_jail = Jail::try_new("./config")?;
    let safe_path = config_jail.try_path(config_path)?;  // Validates external config paths
    safe_path.read_to_string()
}
```

## API Overview

```rust
use jailed_path::{Jail, VirtualRoot};

// Create jail and validate paths (system-facing)
let jail = Jail::try_new("./safe_dir")?;                    // or try_new_create() to create dir
let jp = jail.try_path("user/file.txt")?;                   // JailedPath<M>

// Built-in safe operations on JailedPath (I/O)
jp.read_bytes()?;                                            // File I/O
jp.write_string("content")?;
jp.create_dir_all()?;                                        // Directory ops
assert!(jp.exists());

// Display and real system path accessors (system-facing)
println!("{}", jp);                                          // System path: "<abs>/safe_dir/user/file.txt"
let s = jp.systempath_to_string();                           // Real system path string

// Safe system-path manipulation on JailedPath
let parent = jp.systempath_parent()?;                        // Result<Option<JailedPath>>
let joined = jp.join_systempath("subfile.txt")?;            // Result<JailedPath>

// Create virtual root and virtual path (user-facing)
let vroot = VirtualRoot::try_new("./safe_dir")?;
let vp = vroot.try_path_virtual("user/file.txt")?;          // VirtualPath<M>
println!("{}", vp);                                          // Virtual path: "/user/file.txt"

// Virtual path manipulation on VirtualPath
let vparent = vp.virtualpath_parent()?;                      // Result<Option<VirtualPath>>
let vsibling = vp.join_virtualpath("subfile.txt")?;         // Result<VirtualPath>

// Convert between virtual and system-facing
let back_to_jp = vp.unvirtual();                             // VirtualPath -> JailedPath
let vp2 = back_to_jp.virtualize();                           // JailedPath -> VirtualPath
```

## Windows Security

Handles DOS 8.3 short names (`PROGRA~1`) with early detection and dedicated error handling for security-conscious applications.

## Advanced Usage

For low-level control of canonicalized paths that may not exist, consider using our dependency [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) directly. The `jailed-path` crate is built on this foundation for path resolution.

## Installation

```toml
[dependencies]
jailed-path = "0.0.4"
```

## License

MIT OR Apache-2.0
