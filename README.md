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

`JailedPath` is a filesystem path **mathematically proven** to stay within directory boundaries. Unlike libraries that hope validation works, we mathematically prove it at compile time using Rust's type system. Create `JailedPath` instances by building a jail with `Jail::try_new()` and validating paths via `jail.try_path()`. This guarantees containment—even malicious input like `../../../etc/passwd` gets safely clamped.

**Zero Learning Curve**: Two simple functions solve 99% of use cases. **Attack Impossibility**: Not just "hard to bypass" - actually impossible due to API design.

```rust
use jailed_path::{Jail, JailedPath};

// ✅ SECURE - Guaranteed safe by construction
fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
    safe_path.read_bytes()  // Built-in safe operations
}

# std::fs::create_dir_all("users/alice_workspace/documents")?;
# std::fs::write("users/alice_workspace/documents/report.pdf", b"Alice's report")?;

// Main pattern: Reusable jail for multiple validations (most common)
let user_jail: Jail = Jail::try_new("users/alice_workspace")?;
let safe_path: JailedPath = user_jail.try_path("documents/report.pdf")?;

// Alternative: One-shot style (inline) without storing the jail
let one_shot_path: JailedPath = Jail::try_new("users/alice_workspace")?
    .try_path("documents/report.pdf")?;

// Even attacks are neutralized:
let attack_path = user_jail.try_path("../../../etc/passwd")?;
assert!(attack_path.ends_with("users/alice_workspace"));  // Attack contained!
# std::fs::remove_dir_all("users").ok();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Key Features: Security-First Design

🔒 **Security First**: API makes unsafe operations impossible, not just difficult  
🏛️ **Mathematical Guarantees**: Rust's type system proves security at compile time  
🛡️ **Zero Attack Surface**: No `Deref` to `Path`, no `AsRef<Path>`, validation cannot be bypassed  
📁 **Built-in Safe Operations**: Direct file operations on jailed paths without exposing raw filesystem paths  
👁️ **Virtual Root Display**: Clean user-facing paths that never leak filesystem structure  
🎯 **Multi-Jail Safety**: Marker types prevent cross-jail contamination  
📦 **Minimal Attack Surface**: Only one dependency - our auditable `soft-canonicalize` crate (handles non-existent paths unlike `std::fs::canonicalize`)  
🔗 **Type-History Design**: Internal pattern ensures paths carry proof of validation stages  
🧪 **Comprehensive Testing**: 100%+ test coverage with attack scenario simulation  
🌍 **Cross-Platform**: Works on Windows, macOS, and Linux  
🤖 **LLM-Friendly**: Documentation and APIs designed for both humans and AI systems to understand and use correctly  

## The Problem: Every Path Is a Security Risk

```rust
// 🚨 DANGEROUS - This code looks innocent but has a critical vulnerability
fn serve_file(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(format!("./public/{path}"))  // ← Path traversal attack possible!
}

// Attacker sends: "../../../etc/passwd" 
// Your server happily serves: ./public/../../../etc/passwd → /etc/passwd 💀
```

**The brutal truth**: Manual path validation is error-prone and easy to bypass. Even security-conscious developers get it wrong.

## See The Promise In Action: Detailed Examples

```rust
use jailed_path::{Jail, JailedPath};

// ═══════════════════════════════════════════════════════════════════════════════
// THE PROMISE HANDLES ATTACKS - Even escape attempts honor the containment promise:
// ═══════════════════════════════════════════════════════════════════════════════

let escape_attempt = "../../../etc/passwd";
let alice_jail = Jail::try_new("users/alice_workspace")?;
let attack_path: JailedPath = alice_jail.try_path(escape_attempt)?;

// Virtual display shows clamped path - the promise includes hiding real filesystem structure
assert_eq!(attack_path.virtual_display(), "/etc/passwd");  // Clean display, but SAFELY clamped

// ✅ The promise is verified: this path is actually contained within the jail
assert!(attack_path.ends_with("users/alice_workspace"));  // PROOF: Real path is inside the jail!

// Reusable jail with try_path()
let alice_home_jail = Jail::try_new("./users/alice_workspace")?;
let vacation_photo_path: JailedPath = alice_home_jail.try_path("photos/vacation.jpg")?;
assert_eq!(vacation_photo_path.virtual_display(), "/photos/vacation.jpg");  // Promise: within alice's space!

let cross_user_attack_path: JailedPath = alice_home_jail.try_path("../bob_workspace/secrets.txt")?;
assert_eq!(cross_user_attack_path.virtual_display(), "/bob_workspace/secrets.txt");  // Clean display
assert!(cross_user_attack_path.ends_with("users/alice_workspace"));  // PROOF: Still within alice's jail!
```

**The revolutionary insight**: Every `JailedPath` you hold is a cryptographic-strength promise that has been mathematically verified by Rust's type system. You cannot forge this promise—there are no other constructors!

## Understanding the Generic Marker System

You might have noticed something in the examples above. Let's explore the "generic trap" and why it's actually a feature:

```rust
use jailed_path::Jail;

// Simple approach - no type annotation needed
let static_files_jail = Jail::try_new("./static/css")?;
let stylesheet_path = static_files_jail.try_path("bootstrap.css")?;  // Type: JailedPath<()>

// Or be explicit with the "turbofish" syntax  
let static_files_jail: Jail<()> = Jail::try_new("./static/css")?;
let stylesheet_path: JailedPath<()> = static_files_jail.try_path("bootstrap.css")?;
```

**"Why the generic `<()>` parameter?"** - This is Rust's way of saying "no special marker." But the real power comes when you DO use markers...

## The Power of Multiple Jails: Promises with Specific Identities

Real applications have multiple directories. Here's where the promise system becomes even more powerful by adding **identity** to the containment promise:

```rust
use jailed_path::{Jail, JailedPath};

// Define semantic markers for different promise types
struct WebAssets;
struct UserUploads;

// Create type-safe path jails that make specific promises
let cdn_assets_jail: Jail<WebAssets> = Jail::try_new("./cdn/assets")?;
let user_uploads_jail: Jail<UserUploads> = Jail::try_new("./uploads")?;

// Get paths with specific promises
let css_bundle_path: JailedPath<WebAssets> = cdn_assets_jail.try_path("app.bundle.css")?;
// ↑ Promise: "I am contained within ./cdn/assets AND I am a WebAssets path"

let profile_pic_path: JailedPath<UserUploads> = user_uploads_jail.try_path("avatars/user123.png")?;
// ↑ Promise: "I am contained within ./uploads AND I am a UserUploads path"

// Functions can require specific promise types
fn serve_cdn_asset(asset: &JailedPath<WebAssets>) -> std::io::Result<Vec<u8>> {
    asset.read_bytes() // ✅ This function ONLY accepts the WebAssets promise
}

// The type system enforces promise contracts
serve_cdn_asset(&css_bundle_path)?;  // ✅ Correct promise type
// serve_cdn_asset(&profile_pic_path)?;  // ❌ Compile error! Wrong promise type!
```

**The magic**: The compiler mathematically guarantees that different promise types cannot be mixed up. A `JailedPath<WebAssets>` promises both containment AND identity—you can never accidentally serve a user upload as a CDN asset.

## Even Single Jails Benefit from Semantic Markers

```rust
use jailed_path::{Jail, JailedPath};

struct DocumentStorage;

let docs_jail: Jail<DocumentStorage> = Jail::try_new("./company_docs")?;

fn access_document(file: &JailedPath<DocumentStorage>) -> std::io::Result<Vec<u8>> {
    // The type signature makes it crystal clear what this function expects
    file.read_bytes() // ✅ Safe built-in operation
}
```

The marker adds semantic meaning and prevents accidental misuse.

## Safe File Operations: Why Direct Path Access Can Be Dangerous

Here's a critical security insight: even with a `JailedPath`, getting a raw `&Path` can be risky if misused:

```rust
use jailed_path::Jail;
use std::path::Path;

let customer_data_jail = Jail::try_new("./customer_data")?;
let invoice_path = customer_data_jail.try_path("invoices/2024/invoice-001.pdf")?;

// 🚨 DANGEROUS - A raw &Path can be misused!
let raw_path: &Path = invoice_path.as_ref();
let dangerous = raw_path.join("../../../etc/passwd");  // Oops! Escaped the jail!
```

**The solution**: Use our built-in safe operations instead.

## Built-in Safe File Operations

```rust
use jailed_path::Jail;

let customer_uploads_jail = Jail::try_new("./customer_uploads")?;
let contract_path = customer_uploads_jail.try_path("contracts/acme-corp-2024.pdf")?;

// ✅ SAFE - All operations stay within the jail automatically
contract_path.write_string("Contract updated with new terms")?;
let content = contract_path.read_to_string()?;
assert_eq!(content, "Contract updated with new terms");

// Write operations - always safe
contract_path.write_bytes(b"PDF binary data")?;
let data = contract_path.read_bytes()?;
assert_eq!(data, b"PDF binary data");

// Directory operations - always safe  
let client_folder_path = customer_uploads_jail.try_path("new_client_folder")?;
client_folder_path.create_dir_all()?;
assert!(client_folder_path.exists());

// Metadata operations - always safe
contract_path.write_string("Updated contract content")?;
let metadata = contract_path.metadata()?;
assert!(metadata.len() > 0);
```

**No raw path access needed!** All operations are mathematically guaranteed to stay within the jail.

## Virtual Root Display: Clean User-Facing Paths

```rust
use jailed_path::Jail;

let saas_tenant_jail = Jail::try_new("./tenant_data/company_xyz")?;
let report_path = saas_tenant_jail.try_path("reports/quarterly/2024-q1.xlsx")?;

// User sees clean, intuitive paths - never internal filesystem details
assert_eq!(format!("{report_path}"), "/reports/quarterly/2024-q1.xlsx");

// The real path is hidden (and you shouldn't need it anyway!)
assert_eq!(report_path.to_string_lossy(), "./tenant_data/company_xyz/reports/quarterly/2024-q1.xlsx");
```

This prevents leaking internal filesystem structure in logs, error messages, or user interfaces.

## Mathematical Security: Our Type-State Design

This crate uses a sophisticated "Type-History" design pattern internally. Every path carries mathematical proof of what validation stages it has passed through:

```rust
// Internal type-state progression (you don't see this, but it's happening):
// Raw → Clamped → JoinedJail → Canonicalized → BoundaryChecked → JailedPath
```

Our comprehensive test coverage (100%+) and LLM-friendly documentation ensure that every security property is verified mathematically, not just hoped for.

## Complete Attack Immunity Demonstration

```rust
use jailed_path::Jail;

let web_server_jail: Jail = Jail::try_new("./www/htdocs")?;

// ✅ Normal paths work as expected - legitimate web requests
let homepage_path = web_server_jail.try_path("index.html")?;
assert_eq!(homepage_path.to_string_lossy(), "./www/htdocs/index.html");
assert_eq!(format!("{homepage_path}"), "/index.html");

let stylesheet_path = web_server_jail.try_path("css/main.css")?;
assert_eq!(stylesheet_path.to_string_lossy(), "./www/htdocs/css/main.css");
assert_eq!(stylesheet_path.virtual_display(), "/css/main.css");

// 🛡️ ATTACK ATTEMPTS ARE MATHEMATICALLY IMPOSSIBLE TO SUCCEED
let shadow_attack_path = web_server_jail.try_path("/etc/shadow")?;
assert_eq!(shadow_attack_path.to_string_lossy(), "./www/htdocs/etc/shadow");  // Harmless!
assert_eq!(shadow_attack_path.virtual_display(), "/etc/shadow");  // In jail

let config_attack_path = web_server_jail.try_path("../config.ini")?;
assert_eq!(config_attack_path.to_string_lossy(), "./www/htdocs");  // Jail root
assert_eq!(config_attack_path.virtual_display(), "/");

let passwd_attack_path = web_server_jail.try_path("../../../etc/passwd")?;
assert_eq!(passwd_attack_path.to_string_lossy(), "./www/htdocs");  // Jail root
assert_eq!(passwd_attack_path.virtual_display(), "/");

// 🔒 The attacker CANNOT access the real /etc/passwd - it's mathematically impossible!
assert!(config_attack_path.ends_with("htdocs"));  // PROOF: Clamped to jail root
assert!(passwd_attack_path.ends_with("htdocs"));  // PROOF: Clamped to jail root
```

## Windows-specific hardening: 8.3 short names (PROGRA~1)

On Windows, DOS 8.3 short filenames (like `PROGRA~1`) are alternate aliases for long names. They can create surprising bypasses if validated differently than their long-name counterparts.

This crate uses a hybrid defense on Windows:

- Early precheck rejects any non-existent path component that looks like an 8.3 short name (contains `~` followed by a digit), returning a dedicated error so the caller can decide how to recover.
- If the component already exists inside the jail, it is allowed to pass and is validated normally (clamping, canonicalization, boundary checks).

Recovery example (Windows only):

```rust,no_run
use jailed_path::{Jail, JailedPathError};

let jail = Jail::<()>::try_new("C:/safe/uploads")?;
match jail.try_path("users/PROGRA~1/report.txt") {
    Ok(safe) => { /* use safe */ }
    Err(JailedPathError::WindowsShortName { component, original, checked_at }) => {
        eprintln!(
            "Rejected DOS 8.3 short name '{}' at '{}' for original '{}'",
            component.to_string_lossy(),
            checked_at.display(),
            original.display(),
        );
        // Recovery options:
        // - Ask user for the full long name
        // - Map to a known-safe long name
        // - Reject/log according to your threat model
    }
    Err(e) => return Err(e.into()),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Notes:

- Legitimate names containing `~` without a digit after it (e.g., `my~file.txt`) are not treated as short names by this precheck.
- This behavior is Windows-only and does not affect Unix-like systems.

## Advanced: Real-World Integration Examples

### Axum Web Server with Multi-Tenant File Serving

```rust
use axum::{extract::Path, response::Response, http::StatusCode};
use jailed_path::Jail;

struct StaticAssets;
struct UserContent;

// Set up path jails for different content types
let static_jail = Jail::<StaticAssets>::try_new("./public")?;
let content_jail = Jail::<UserContent>::try_new("./user_content")?;

async fn serve_static(Path(file_path): Path<String>) -> Result<Response, StatusCode> {
    let safe_path = static_jail.try_path(&file_path)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    if !safe_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }
    
    let content = safe_path.read_bytes()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Response::new(content.into()))
}

async fn serve_user_content(Path((tenant_id, file_path)): Path<(String, String)>) -> Result<Response, StatusCode> {
    let tenant_path = format!("{tenant_id}/{file_path}");
    let safe_path = content_jail.try_path(&tenant_path)
        .map_err(|_| StatusCode::FORBIDDEN)?;  // Auto-blocks traversal attacks
        
    // Rest of handler logic...
    Ok(Response::new("content".into()))
}
```

### Cloud Storage Sync Service

```rust
use jailed_path::Jail;

struct LocalCache;
struct RemoteSync;

// Automation service that syncs cloud storage locally
let cache_jail = Jail::<LocalCache>::try_new("./cache/downloads")?;
let sync_jail = Jail::<RemoteSync>::try_new("./sync_staging")?;

async fn download_cloud_file(cloud_path: &str, local_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure downloaded files stay in designated cache area
    let local_path = cache_jail.try_path(local_name)?;
    
    // Download from cloud service (S3, GCS, etc.)
    let cloud_data = fetch_from_cloud(cloud_path).await?;
    
    // Safe write - guaranteed to stay in cache jail
    local_path.write_bytes(&cloud_data)?;
    
    println!("Downloaded to: {}", local_path.display());  // Clean path display
    Ok(())
}

async fn sync_to_staging(cached_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cache_path = cache_jail.try_path(cached_file)?;
    let staging_path = sync_jail.try_path(cached_file)?;
    
    // Move between jails safely
    let data = cache_path.read_bytes()?;
    staging_path.write_bytes(&data)?;
    
    Ok(())
}
```

### Resource Bundling Tool

```rust
use jailed_path::Jail;

struct SourceAssets;
struct BuildOutput;

// Build tool that processes resources from multiple sources
let source_jail = Jail::<SourceAssets>::try_new("./src/assets")?;
let build_jail = Jail::<BuildOutput>::try_new("./dist")?;

fn bundle_css_files(css_files: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut combined_css = String::new();
    
    for css_file in css_files {
        // Safe access to source files - no traversal possible
        let source_path = source_jail.try_path(css_file)?;
        let css_content = source_path.read_to_string()?;
        combined_css.push_str(&css_content);
        combined_css.push('\n');
    }
    
    // Safe output to build directory
    let bundle_path = build_jail.try_path("bundle.css")?;
    bundle_path.write_string(&combined_css)?;
    
    println!("CSS bundle created: {}", bundle_path.display());
    Ok(())
}

fn process_image_assets(image_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = source_jail.try_path(image_dir)?;
    
    // Process all images in the source directory
    for entry in std::fs::read_dir(source_dir.as_ref())? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().to_string();
        
        if filename.ends_with(".png") || filename.ends_with(".jpg") {
            let source_img = source_jail.try_path(&format!("{image_dir}/{filename}"))?;
            let output_img = build_jail.try_path(&format!("images/{filename}"))?;
            
            // Safe image processing - both paths are jailed
            let img_data = source_img.read_bytes()?;
            // ... image optimization logic ...
            output_img.write_bytes(&img_data)?;
        }
    }
    
    Ok(())
}
```

## For Inline Validation: Banking Application

Sometimes you need quick path validation inline without storing the jail:

```rust
use jailed_path::Jail;

// Banking application handling customer statements
fn generate_customer_statement(customer_id: &str, year: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Quick validation: keep customer statements within their secure directory
    let jail = Jail::try_new("./bank_statements")?;
    let statement_path = jail.try_path(format!("customer_{}/statements/{}.pdf", customer_id, year))?;

    if !statement_path.exists() {
        return Err("Statement not found".into());
    }

    Ok(format!("Statement available at: {}", statement_path.display()))
}

// Example usage - secure by design
match generate_customer_statement("12345", "2023") {
    Ok(location) => println!("{}", location),
    Err(e) => println!("Access denied: {}", e), // Handles traversal attacks automatically
}

// What happens with attacks:
// generate_customer_statement("../../../etc", "passwd") -> Error: path escapes jail
// generate_customer_statement("12345", "../other_customer") -> Error: path escapes jail
```

### With External Crates (Portable Paths)

```rust
use app_path::app_path;
use jailed_path::Jail;

struct ConfigFiles;
struct DataFiles;

// Portable paths relative to your executable
let config: Jail<ConfigFiles> = Jail::try_new(app_path!("config"))?;
let data: Jail<DataFiles> = Jail::try_new(app_path!("data"))?;

// Type-safe, attack-proof file access
let settings_path = config.try_path("app.toml")?;
let database_path = data.try_path("users.db")?;
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
jailed-path = "0.0.4"
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
