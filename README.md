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

**Sources requiring `JailedPath` validation:**

- 📡 **HTTP requests** - User file uploads, API endpoints, URL parameters
- 🌐 **Web forms** - File paths in form submissions, route parameters  
- ⚙️ **Configuration files** - User-editable config, external config sources
- 💾 **Database content** - File paths stored in user data, content management
- 📂 **CLI arguments** - Command-line file paths, script parameters
- 🔌 **External APIs** - Third-party services, webhook payloads
- 🤖 **LLM/AI output** - Generated file paths, autonomous agent decisions
- 📨 **Inter-service communication** - Microservice requests, message queues
- 📱 **Mobile/Desktop apps** - User document selection, drag-and-drop paths
- 📦 **Archive contents** - ZIP/RAR/TAR file entries, embedded path strings in binary files
- 🔧 **File format internals** - Any file that contains path strings as data

**The Rule**: **If the path comes from outside your direct code control → jail it with `JailedPath`.**

---

`JailedPath` is a filesystem path type **mathematically proven** to stay within directory boundaries. Unlike libraries that hope validation works, we mathematically prove it at compile time using Rust's type system. Create `JailedPath` instances by building a jail with `Jail::try_new()` and validating paths via `jail.try_path()`. This guarantees containment—even malicious input like `../../../etc/passwd` gets safely clamped.


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
assert!(attack_path.starts_with_real(jail.path()));  // Proof: contained
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
// Create jail and validate paths
let jail = Jail::try_new("./safe_dir")?;                    // or try_new_create() to create dir
let safe_path = jail.try_path("user/file.txt")?;            // Validates and contains path

// Built-in safe operations
safe_path.read_bytes()?;                                     // File I/O
safe_path.write_string("content")?;
safe_path.create_dir_all()?;                                 // Directory ops
safe_path.exists();

// Path display
println!("{}", safe_path);                                   // Virtual: "/user/file.txt"
safe_path.realpath_to_string();                                  // Real: "./safe_dir/user/file.txt"

// Safe path manipulation
safe_path.parent();                                          // Returns Option<JailedPath>
safe_path.join("subfile.txt");                               // Returns Option<JailedPath>
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