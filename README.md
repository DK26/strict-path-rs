# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)**
| 🧭 **[Choosing Canonicalized vs Lexical Solution](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)**

> **Note:** Our doc comments and `LLM_API_REFERENCE.md` are designed for LLMs with function calling—so an AI can use this crate safely and correctly for file and path operations.

**More than path comparisons: full, cross‑platform path security with type‑level guarantees.**

This crate is not a thin wrapper around `Path` or a naive string comparison.
It performs full normalization, canonicalization, and boundary enforcement with
symlink/junction handling, Windows‑specific edge cases (8.3 short names, UNC,
verbatim prefixes, ADS), and robust encoding/normalization behavior across
platforms. The type system encodes these guarantees: if a `StrictPath<Marker>`
exists, it’s already proven to be inside its allowed boundary — not by hope,
but by construction.

## Quick start

> "If you can read this, you passed the PathBoundary checkpoint."

```rust
use strict_path::{StrictPath, VirtualPath};

// Strict system path rooted at ./data
let sp = StrictPath::with_boundary("./data")?
    .strict_join("users/alice.txt")?;

// Virtual view rooted at ./public (displays as "/...")
let vp = VirtualPath::with_root("./public")?
    .virtual_join("assets/logo.png")?;
```

> *The Type-State Police have set up PathBoundary checkpoints*  
> *because your LLM is running wild*

## 🚨 **One Line of Code Away from Disaster**

> "One does not simply walk into /etc/passwd."

```rust
// ❌ This single line can destroy your server
std::fs::write(user_input, data)?;  // user_input = "../../../etc/passwd"

// ✅ This single line makes it mathematically impossible  
StrictPath::with_boundary("uploads")?
    .strict_join(user_input)?
    .write(data)?;
```

**The Reality**: Every web server, LLM agent, and file processor faces the same vulnerability. One unvalidated path from user input, config files, or AI responses can grant attackers full filesystem access.

**The Solution**: Comprehensive path security with mathematical guarantees — including symlink safety, Windows path quirks, and encoding pitfalls — not just string checks.

> Analogy: `StrictPath` is to paths what a prepared statement is to SQL.
>
> - The boundary/root you create is like preparing a statement: it encodes the policy (what’s allowed).
> - The untrusted filename or path segment is like a bound parameter: it’s validated/clamped safely via `strict_join`/`virtual_join`.
> - The API makes injection attempts inert: hostile inputs can’t escape the boundary, just like SQL parameters can’t change the query.

## 🛡️ **How We Solve The Entire Problem Class**

> "Symlinks: the ninja assassins of your filesystem."

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
strict-path = "0.1.0-alpha.6"
```

```rust
use strict_path::StrictPath;

// 1. Create a boundary (your security perimeter)
//    Use sugar for simple flows; switch to PathBoundary when you need reusable policy
let safe_root = StrictPath::with_boundary("uploads")?;

// 2. ANY external input becomes safe
let safe_path = safe_root.strict_join(dangerous_user_input)?;  // Attack = Error

// 3. Use normal file operations - guaranteed secure
safe_path.write(file_data)?;
let info = safe_path.metadata()?; // Inspect filesystem metadata when needed
safe_path.remove_file()?; // Remove when cleanup is required
```

**That's it.** No complex validation logic. No CVE research. No security expertise required.

## 🧠 Type-System Guarantees in Signatures

> "Marker types: because your code deserves a secret identity."

Use marker types in your function signatures to encode policy and prevent mix-ups across storage domains. The compiler enforces that only the correct paths reach each function.

// Example A — StrictPath with markers
```rust
use strict_path::{PathBoundary, StrictPath};

struct PublicAssets; // CSS, JS, images
struct UserUploads;  // Uploaded documents

// Create type-safe boundaries (policy)
let assets = PathBoundary::<PublicAssets>::try_new("./assets")?;
let uploads = PathBoundary::<UserUploads>::try_new("./uploads")?;

// Produce mathematically safe paths (cannot exist outside their boundary)
let css: StrictPath<PublicAssets> = assets.strict_join("style.css")?;
let avatar: StrictPath<UserUploads> = uploads.strict_join("avatar.jpg")?;

// Encode guarantees in signatures — prevents cross-domain mix-ups at compile time
fn serve_public_asset(file: &StrictPath<PublicAssets>) {
    // Safe by construction; `file` cannot escape `assets` boundary
}

serve_public_asset(&css);        // ✅ OK
// serve_public_asset(&avatar);  // ❌ Compile error: wrong marker
```

// Example B — VirtualPath for user-facing flows (per-user root)
```rust
use strict_path::{VirtualRoot, VirtualPath};

struct UserUploads; // Uploaded documents

let user_id = 42; // Example unique user identifier
let vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new(format!("./uploads/{user_id}"))?; // per-user root
let avatar_v: VirtualPath<UserUploads> = vroot.virtual_join("avatar.jpg")?;

fn process_upload(p: &VirtualPath<UserUploads>) {
    // Use virtualpath_display() for UI; clamp is guaranteed
}

process_upload(&avatar_v);       // ✅ OK
```

// Example C — One common helper shared by both
```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

struct PublicAssets;
struct UserUploads;

// A common helper that works with any StrictPath marker
fn process_common<M>(path: &StrictPath<M>) -> std::io::Result<Vec<u8>> {
    path.read()
}

// Prepare one strict and one virtual path
let assets = PathBoundary::<PublicAssets>::try_new("./assets")?;
let css: StrictPath<PublicAssets> = assets.strict_join("style.css")?;

let user_id = 42;
let vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new(format!("./uploads/{user_id}"))?;
let avatar_v: VirtualPath<UserUploads> = vroot.virtual_join("avatar.jpg")?;

// Call with either type
let _ = process_common(&css)?;                   // StrictPath
let _ = process_common(avatar_v.as_unvirtual())?; // Borrow strict view from VirtualPath
```

Why this matters:
- `StrictPath<Marker>` and `VirtualPath<Marker>` are boundary-checked — construction proves containment.
- Function signatures become policy — the type system rejects misuse and cross-domain mix-ups.
- Prefer simple, dimension-specific helpers; when needed, borrow a strict view from a virtual path with `as_unvirtual()`.

## 🛡️ **Security Features**

> "If you see a CVE, don't panic—just use strict-path."

- **CVE-Aware Protection**: Built on 19+ real-world path vulnerabilities — we've done the security research so you don't have to
- **Mathematical Guarantees**: Paths are canonicalized and boundary-checked - impossible to escape the restriction  
- **Type Safety**: Marker types prevent mixing different storage contexts at compile time
- **LLM-Ready**: Designed specifically for untrusted AI-generated paths and modern threat models
- **Platform Security**: Safe symlink/junction handling; Windows 8.3 short names, UNC, verbatim prefixes, ADS; Unicode normalization edge cases
- **Zero-Allocation Interop**: `.interop_path()` for seamless integration with existing `std::path` code
- **Misuse Resistant**: API design makes security violations visible in code review

## 📌 Where This Makes Sense

> "LLMs: great at generating paths, terrible at keeping secrets."

- Usefulness for LLM agents: LLMs can produce arbitrary paths; `StrictPath`/`VirtualPath` make those suggestions safe by validation (strict) or clamping (virtual) before any I/O.
- `PathBoundary`/`VirtualRoot`: When you want the compiler to enforce that a value is anchored to the initial root/boundary. Keeping the policy type separate from path values prevents helpers from “picking a root” silently. With features enabled, you also get ergonomic, policy‑aware constructors (e.g., `dirs`, `tempfile`, `app-path`).
- Marker types: Add domain context for the compiler and reviewers (e.g., `PublicAssets`, `UserUploads`). They read like documentation and prevent cross‑domain mix‑ups at compile time.

Trade‑offs you can choose explicitly:

- Zero‑trust, CVE‑aware approach: Prefer canonicalized solutions (this crate) to resolve to absolute, normalized system paths with symlink handling and platform quirks addressed. This defends against entire classes of traversal and aliasing attacks.
- Lexical approach (performance‑first, limited scope): If you’re absolutely certain there are no symlinks, junctions, mounts, or platform‑specific aliases and your inputs are already normalized, a lexical solution from another crate may be faster. Use this only when the invariants are guaranteed by your environment and tests.

## 🎯 **When to Use Each Type**

> "StrictPath: the bouncer at your filesystem nightclub."

| Your Input Source                           | Use This       | Why                                                 |
| ------------------------------------------- | -------------- | --------------------------------------------------- |
| **HTTP requests, LLM output, config files** | `StrictPath`   | Reject attacks explicitly - perfect for validation  |
| **User uploads, archive extraction**        | `VirtualPath`  | Clamp hostile paths safely - perfect for sandboxing |
| **Your own hardcoded paths**                | `Path/PathBuf` | You control it, no validation needed                |

**Think of it this way:**
- `StrictPath` = **Security Filter** — validates and rejects unsafe paths
- `VirtualPath` = **Complete Sandbox** — clamps any input to stay safe

## 🛡️ **Core Security Foundation**

> "StrictPath: the vault door, not just a velvet rope."

At the heart of this crate is **`StrictPath`** - the fundamental security primitive that provides our ironclad guarantee: **every `StrictPath` is mathematically proven to be within its boundary**. 

Everything in this crate builds upon `StrictPath`:
- `PathBoundary` creates and validates `StrictPath` instances
- `VirtualPath` extends `StrictPath` with user-friendly virtual root semantics  
- `VirtualRoot` provides a root context for creating `VirtualPath` instances

**The core promise:** If you have a `StrictPath<Marker>`, it is impossible for it to reference anything outside its designated boundary. This isn't just validation - it's a type-level guarantee backed by cryptographic-grade path canonicalization.


**Core Security Principle: Secure Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a boundary‑enforced type (`StrictPath` or `VirtualPath`) before I/O.

## 🎯 **Choose Your Weapon: When to Use What**

> "Choose wisely: not all paths lead to safety."

### 🌐 **VirtualPath** - User Sandboxes & Cloud Storage
*"Give users their own private universe"*

```rust
use strict_path::VirtualPath;

// Archive extraction - hostile names get clamped, not rejected
let extract_root = VirtualPath::with_root("./extracted")?;
for entry_name in malicious_zip_entries {
    let safe_path = extract_root.virtual_join(entry_name)?; // "../../../etc" → "/etc"  
    safe_path.write(entry.data())?; // Always safe
}

// User cloud storage - users see friendly paths
let doc = VirtualPath::with_root(format!("users/{user_id}"))?
    .virtual_join("My Documents/report.pdf")?;
println!("Saved to: {}", doc.virtualpath_display()); // Shows "/My Documents/report.pdf"
```

### ⚔️ **StrictPath** - LLM Agents & System Boundaries  
*"Validate everything, trust nothing"*

```rust
use strict_path::PathBoundary;

// LLM Agent file operations
let ai_workspace = PathBoundary::try_new("ai_sandbox")?;
let ai_request = llm.generate_path(); // Could be anything malicious
let safe_path = ai_workspace.strict_join(ai_request)?; // Attack = Explicit Error
safe_path.write(&ai_generated_content)?;

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

> "If you didn't create the path yourself, it's probably plotting against you."

| Input Source                              | Use This       | Why                        |
| ----------------------------------------- | -------------- | -------------------------- |
| **HTTP requests, CLI args, config files** | `StrictPath`   | Reject attacks explicitly  |
| **LLM/AI output, database records**       | `StrictPath`   | Validate before execution  |
| **Archive contents, user uploads**        | `VirtualPath`  | Clamp hostile paths safely |
| **Your own code, hardcoded paths**        | `Path/PathBuf` | You control it             |

## 🚀 **Real-World Examples**

> "Every example here survived a close encounter with an LLM."

### LLM Agent File Manager
```rust
use strict_path::PathBoundary;

// Encode guarantees in signature: pass workspace boundary and untrusted request
async fn llm_file_operation(workspace: &PathBoundary, request: &LlmRequest) -> Result<String> {
    // LLM could suggest anything: "../../../etc/passwd", "C:/Windows/System32", etc.
    let safe_path = workspace.strict_join(&request.filename)?; // Attack = Error

    match request.operation.as_str() {
        "write" => safe_path.write(&request.content)?,
        "read" => return Ok(safe_path.read_to_string()?),
        _ => return Err("Invalid operation".into()),
    }
    Ok(format!("File {} processed safely", safe_path.strictpath_display()))
}
```

### Zip Extraction (Zip Slip Prevention)
```rust
use strict_path::VirtualPath;

// Encode guarantees in signature: construct a root once; pass untrusted entry names
fn extract_zip(zip_entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
    let extract_root = VirtualPath::with_root("./extracted")?;
    for (name, data) in zip_entries {
        // Hostile names like "../../../etc/passwd" get clamped to "/etc/passwd"
        let vpath = extract_root.virtual_join(&name)?;
        vpath.create_parent_dir_all()?;
        vpath.write(&data)?;
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
    Ok(Response::new(safe_path.read()?))
}

// Function signature prevents bypass - no validation needed inside!
async fn serve_file(safe_path: &strict_path::StrictPath<StaticFiles>) -> Response {
    Response::new(safe_path.read().unwrap_or_default())
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

> "If your attacker has root, strict-path can't save you—but it can make them work for it."

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

> "If you need a matrix to decide, you probably need strict-path."

| Source                      | Typical Input                  | Use VirtualPath For                       | Use StrictPath For        | Notes                                                   |
| --------------------------- | ------------------------------ | ----------------------------------------- | ------------------------- | ------------------------------------------------------- |
| 🌐 **HTTP requests**         | URL path segments, file names  | Display/logging, safe virtual joins       | System-facing interop/I/O | Always clamp user paths via `VirtualPath::virtual_join` |
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

**Unified signatures note**: Prefer marker-specific `&StrictPath<Marker>` or `&VirtualPath<Marker>` for intent clarity. Use a generic `&StrictPath<_>` only when helpers are intentionally shared; borrow from virtual with `as_unvirtual()` as shown above.

## 🔐 **Advanced: Type-Safe Context Separation**

> "Type safety: because mixing up user files and web assets is so 2005."

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
serve_asset(css.as_unvirtual());         // Correct context
// serve_asset(doc.as_unvirtual());      // Compile error!
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
safe_config.write(&settings)?;
```

## ⚠️ Anti-Patterns (Tell‑offs and Fixes)

> "Don't be that developer: use the right display method."

### DON'T Mix Interop with Display

```rust
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new("uploads")?;

// ❌ ANTI-PATTERN: Wrong method for display
println!("Path: {}", boundary.interop_path().to_string_lossy());

// ✅ CORRECT: Use proper display methods
println!("Path: {}", boundary.strictpath_display());

// For virtual flows, prefer `VirtualPath` and borrow strict view when needed:
use strict_path::VirtualPath;
let vpath = VirtualPath::with_root("uploads")?.virtual_join("file.txt")?;
println!("Virtual: {}", vpath.virtualpath_display());
println!("System: {}", vpath.as_unvirtual().strictpath_display());
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
    Ok(Response::new(safe_path.read()?))
}

// Caller handles validation once:
let static_files_dir = PathBoundary::<StaticFiles>::try_new("./static")?;
let safe_path = static_files_dir.strict_join(&user_requested_path)?;
serve_static_file(&safe_path).await?;
```

### Archive Extraction (Zip Slip Prevention)
```rust
let extract_root = VirtualPath::with_root("./extracted")?;
for (name, data) in zip_entries {
    let vpath = extract_root.virtual_join(&name)?;  // Neutralizes zip slip (clamps hostile)
    vpath.create_parent_dir_all()?;
    vpath.write(&data)?;
}
```

### Cloud Storage API  

```rust
// User chooses any path - always safe
let file_path = VirtualPath::with_root(format!("/cloud/user_{id}"))?
    .virtual_join(&user_requested_path)?;
file_path.write(upload_data)?;
```

### Configuration Files
```rust
use strict_path::PathBoundary;

// Encode guarantees via the signature: pass the boundary and an untrusted name
fn load_config(config_dir: &PathBoundary, name: &str) -> Result<String> {
    config_dir.strict_join(name)?.read_to_string()
}
```




### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_workspace = PathBoundary::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_workspace.strict_join(ai_suggested_path)?; // Guaranteed safe
safe_ai_path.write(&ai_generated_content)?;
```



## 📚 **API Quick Reference**

> "StrictPath: the only path that doesn't ghost you at runtime."

| Feature            | `Path`/`PathBuf`                            | `StrictPath`                        | `VirtualPath`                                      |
| ------------------ | ------------------------------------------- | ----------------------------------- | -------------------------------------------------- |
| **Security**       | None 💥                                      | Validates & rejects ✅               | Clamps any input ✅                                 |
| **Join safety**    | Unsafe (can escape)                         | Boundary-checked                    | Boundary-clamped                                   |
| **Example attack** | `"../../../etc/passwd"` → **System breach** | `"../../../etc/passwd"` → **Error** | `"../../../etc/passwd"` → **`/etc/passwd`** (safe) |
| **Best for**       | Known-safe paths                            | System boundaries                   | User interfaces                                    |

```rust
// StrictPath - validate and reject
let path = StrictPath::with_boundary("uploads")?.strict_join("file.txt")?; // Error if unsafe

// VirtualPath - clamp any input safely  
let vpath = VirtualPath::with_root("userspace")?.virtual_join("any/path/here")?; // Always works

// Both support the same I/O operations
path.write(data)?;
vpath.read_to_string()?;
```

## 📚 **Documentation & Resources**

> "If you read the docs, you get +10 security points."

- **📖 [Complete API Reference](https://docs.rs/strict-path)** - Comprehensive API documentation
- **📚 [User Guide & Examples](https://dk26.github.io/strict-path-rs/)** - In-depth tutorials and patterns  
- **🔧 [LLM_API_REFERENCE.md](LLM_API_REFERENCE.md)** - Quick reference for all methods (LLM-focused)
- **🛠️ [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - The underlying path resolution engine

## 🔌 **Integrations**

> "Integrate like a pro: strict-path plays nice with everyone except attackers."

- **🗂️ OS Directories** (`dirs` feature): `PathBoundary::try_new_os_config()`, `try_new_os_downloads()`, etc.
- **📄 Serde** (`serde` feature): Safe serialization/deserialization of path types
- **🌐 Axum**: Custom extractors for web servers (see `demos/` for examples)

## 📄 **License**

MIT OR Apache-2.0
