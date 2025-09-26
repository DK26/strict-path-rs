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

Stop path attacks before they happen. This crate makes sure file paths can't escape where you want them to go.

## What this crate does

- **Blocks path attacks**: Turn dangerous paths like `../../../etc/passwd` into either safe paths or clear errors
- **Compiler-enforced guarantees**: `StrictPath<Marker>` types prove at compile-time that paths stay within boundaries
- **Enables authorization architectures**: When you design markers to require authorization for construction, the compiler mathematically proves that any use of those markers went through authorization first
- **Two modes to choose from**:
  - **StrictPath**: Rejects bad paths with an error (good for APIs and system access guarantees)  
  - **VirtualPath**: Clamps bad paths to safe ones (good for simulating virtual user spaces, extracting archives in isolation, etc.)
- **Handles the tricky stuff**: Follows symlinks, resolves `..` and `.`, deals with Windows weirdness
- **Easy to use**: Drop-in replacement for standard file operations, same return values
- **Works everywhere**: Handles platform differences so you don't have to

## What this crate is NOT

- **Not just string checking**: We actually follow filesystem links and resolve paths properly
- **Not a simple wrapper**: Built from the ground up for security, not a thin layer over existing types  
- **Not just removing ".."**: Handles symlinks, Windows short names, and other escape tricks
- **Not a permission system**: Works with your existing file permissions, doesn't replace them
- **Not a sandbox**: We secure paths at the path level, not at the OS level

## Quick start

> "If you can read this, you passed the PathBoundary checkpoint."

```rust
use strict_path::{StrictPath, VirtualPath};

// Strict system path rooted at ./data
let alice_file = StrictPath::with_boundary("./data")?
    .strict_join("users/alice.txt")?;

// Virtual view rooted at ./public (displays as "/...")
let logo_file = VirtualPath::with_root("./public")?
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
4. **🔐 Authorization architecture**: Enable compile-time authorization guarantees through marker types
5. **👁️ Explicit operations**: Method names like `strict_join()` make security violations visible in code review
6. **🤖 LLM-aware design**: Built specifically for untrusted AI-generated paths and modern threat models
7. **🔗 Symlink resolution**: Safe handling of symbolic links with cycle detection and boundary enforcement
8. **⚡ Dual protection modes**: Choose **Strict** (validate & reject) or **Virtual** (clamp & contain) based on your use case
9. **🏗️ Battle-tested architecture**: Prototyped and refined across real-world production systems
10. **🎯 Zero-allocation interop**: Seamless integration with existing `std::path` ecosystems

### **Recently Addressed CVEs**
- **CVE-2025-8088** (WinRAR ADS): NTFS Alternate Data Stream traversal prevention
- **CVE-2022-21658** (TOCTOU): Race condition protection during path resolution  
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793**: Windows 8.3 short name vulnerabilities

**Your security audit becomes**: *"We use strict-path for comprehensive path security."* ✅

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1.0-beta.1"
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

## 🧠 **The Secret Weapon: `StrictPath<Marker>` Types**

> "Marker types: because your code deserves a secret identity."

**The most powerful feature** you haven't discovered yet: `StrictPath<Marker>` doesn't just prevent path attacks—the **`<Marker>` part unlocks secret superpowers** that make **wrong path usage a compile error**.

**StrictPath = Promise of path security**  
**`<Marker>` = Unlocks extra secret powers!** 

**Basic superpower**: Prevent cross-domain mix-ups forever.
**Advanced superpower**: Encode authorization requirements into the type system.

### **Level 1: Basic Domain Separation** 

```rust
use strict_path::{PathBoundary, StrictPath};

struct PublicAssets; // CSS, JS, images
struct UserUploads;  // User documents

let public_assets_dir: PathBoundary<PublicAssets> = PathBoundary::try_new("public")?;
let user_uploads_dir: PathBoundary<UserUploads> = PathBoundary::try_new("uploads")?;

let css_file: StrictPath<PublicAssets> = public_assets_dir.strict_join("style.css")?;
let user_doc: StrictPath<UserUploads> = user_uploads_dir.strict_join("report.pdf")?;

fn serve_public_asset(asset: &StrictPath<PublicAssets>) { /* ... */ }

serve_public_asset(&css_file);    // ✅ Works
// serve_public_asset(&user_doc); // ❌ Compile error: wrong domain!
```

**The power**: Mix up user uploads with public assets? **Impossible**. The compiler catches domain violations.

### **Level 2: Authorization Architecture**

```rust
// Marker describes the user's home directory inside a shared filesystem
struct UserHome { _proof: () }

impl UserHome {
    pub fn authenticate_home_access(token: &Token) -> Result<Self, AuthError> {
        verify_token(token)?;  // Real authentication here
        Ok(UserHome { _proof: () })
    }
}

// Functions work with pre-authorized paths
fn read_home_file(path: &StrictPath<UserHome>) -> io::Result<String> {
    // Guaranteed: path is safe AND user passed authentication
    path.read_to_string()
}
```

**The power**: Access user home directories without authentication? **Impossible**. The compiler mathematically proves authorization happened first.

### **Level 3: Permission Matrix** 

```rust
use strict_path::{PathBoundary, StrictPath};

// Resource types (what) + Permission levels (how)
struct SystemFiles;
struct ReadOnly { _proof: () }
struct AdminPermission { _proof: () }

fn view_system_file(path: &StrictPath<(SystemFiles, ReadOnly)>) -> io::Result<String> {
    path.read_to_string() // Can read, but not modify
}

fn manage_system_file(path: &StrictPath<(SystemFiles, AdminPermission)>) -> io::Result<()> {
    path.write("admin changes") // Full control
}

// Authentication returns the complete tuple
let (system_access, readonly_perm) = authenticate_user(&credentials)?;
let system_files_dir: PathBoundary<SystemFiles> = PathBoundary::try_new("system")?;
let system_file: StrictPath<(SystemFiles, ReadOnly)> = 
    system_files_dir.strict_join("config.txt")?;

view_system_file(&system_file)?;    // ✅ Has ReadOnly permission  
// manage_system_file(&system_file)?; // ❌ Needs AdminPermission!
```

**The power**: Create authorization matrices at compile-time. Wrong permission level? **Impossible**. The type system enforces your security model.

### **Why This Changes Everything**

- **Zero runtime cost**: All marker logic erased at compile time
- **Refactoring safety**: Change authorization requirements → get compile errors everywhere affected  
- **Self-documenting**: Function signatures show exactly what permissions are needed
- **Impossible to bypass**: No runtime checks to forget or skip

**Bottom line**: Turn authorization bugs from "runtime disasters" into "won't compile" problems.

> 📚 **[Learn More](https://dk26.github.io/strict-path-rs/authorization_security.html)**: See the complete guide for advanced patterns like role hierarchies, capability-based markers, and web framework integration.

##  Where This Makes Sense

> "LLMs: great at generating paths, terrible at keeping secrets."

- Usefulness for LLM agents: LLMs can produce arbitrary paths; `StrictPath`/`VirtualPath` make those suggestions safe by validation (strict) or clamping (virtual) before any I/O.
- `PathBoundary`/`VirtualRoot`: When you want the compiler to enforce that a value is anchored to the initial root/boundary. Keeping the policy type separate from path values prevents helpers from “picking a root” silently. With features enabled, you also get ergonomic, policy‑aware constructors (e.g., `dirs`, `tempfile`, `app-path`).
- Marker types: Add domain context for the compiler and reviewers (e.g., `PublicAssets`, `UserUploads`). They read like documentation and prevent cross‑domain mix‑ups at compile time.

Trade‑offs you can choose explicitly:

- Zero‑trust, CVE‑aware approach: Prefer canonicalized solutions (this crate) to resolve to absolute, normalized system paths with symlink handling and platform quirks addressed. This defends against entire classes of traversal and aliasing attacks.
- Lexical approach (performance‑first, limited scope): If you’re absolutely certain there are no symlinks, junctions, mounts, or platform‑specific aliases and your inputs are already normalized, a lexical solution from another crate may be faster. Use this only when the invariants are guaranteed by your environment and tests.

## 🎯 **Decision Guide: When to Use What**

> Golden Rule: If you didn't create the path yourself, secure it first.

| Source/Input                                                                                              | Choose         | Why                                            | Notes                                            |
| --------------------------------------------------------------------------------------------------------- | -------------- | ---------------------------------------------- | ------------------------------------------------ |
| HTTP/CLI args/config/LLM/DB (untrusted segments)                                                          | `StrictPath`   | Reject attacks explicitly before I/O           | Validate with `PathBoundary.strict_join(...)`    |
| Archive contents, user uploads (user-facing UX)                                                           | `VirtualPath`  | Clamp hostile paths safely; rooted "/" display | Per-user `VirtualRoot`; use `.virtual_join(...)` |
| UI-only path display                                                                                      | `VirtualPath`  | Show clean rooted paths                        | `virtualpath_display()`; no system leakage       |
| Your own code/hardcoded paths                                                                             | `Path/PathBuf` | You control the value                          | Never for untrusted input                        |
| External APIs/webhooks/inter-service messages                                                             | `StrictPath`   | System-facing interop/I/O requires validation  | Validate on consume before touching FS           |
| *(See the [full decision matrix](https://dk26.github.io/strict-path-rs/best_practices.html) in the book)* |                |                                                |                                                  |

Notes that matter:
- This isn’t StrictPath vs VirtualPath. `VirtualPath` conceptually extends `StrictPath` with a virtual "/" view; both support I/O and interop. Choose based on whether you need virtual, user-facing semantics (VirtualPath) or raw system-facing validation (StrictPath).
- Unified helpers: Prefer dimension-specific signatures. When sharing a helper across both, accept `&StrictPath<_>` and call with `vpath.as_unvirtual()` as needed.

### At‑a‑glance: API Modes

| Feature            | `Path`/`PathBuf`                            | `StrictPath`                        | `VirtualPath`                                      |
| ------------------ | ------------------------------------------- | ----------------------------------- | -------------------------------------------------- |
| **Security**       | None 💥                                      | Validates & rejects ✅               | Clamps any input ✅                                 |
| **Join safety**    | Unsafe (can escape)                         | Boundary-checked                    | Boundary-clamped                                   |
| **Example attack** | `"../../../etc/passwd"` → **System breach** | `"../../../etc/passwd"` → **Error** | `"../../../etc/passwd"` → **`/etc/passwd`** (safe) |
| **Best for**       | Known-safe paths                            | System boundaries                   | User interfaces                                    |

Further reading in the book:
- Best Practices (full decision matrix and rationale): https://dk26.github.io/strict-path-rs/best_practices.html
- Anti-Patterns (what not to do, with fixes): https://dk26.github.io/strict-path-rs/anti_patterns.html
- Examples (end-to-end realistic scenarios): https://dk26.github.io/strict-path-rs/examples.html

## 🛡️ **Core Security Foundation**

> "StrictPath: the vault door, not just a velvet rope."

At the heart of this crate is **`StrictPath`** - the fundamental security primitive that provides our ironclad guarantee: **every `StrictPath` is mathematically proven to be within its boundary**. 

Everything in this crate builds upon `StrictPath`:
- `PathBoundary` creates and validates `StrictPath` instances
- `VirtualPath` extends `StrictPath` with user-friendly virtual root semantics  
- `VirtualRoot` provides a root context for creating `VirtualPath` instances

**The core promise:** If you have a `StrictPath<Marker>`, it is impossible for it to reference anything outside its designated boundary. This isn't just validation - it's a type-level guarantee backed by cryptographic-grade path canonicalization.

**Unique capability:** By making markers authorization-aware, strict-path becomes the foundation for **compile-time authorization architectures** - where the compiler mathematically proves that any path with an authorization-requiring marker went through proper authorization during construction.


**Core Security Principle: Secure Every External Path**

Any path from untrusted sources (HTTP, CLI, config, DB, LLMs, archives) must be validated into a boundary‑enforced type (`StrictPath` or `VirtualPath`) before I/O.

## 🧪 Examples by Mode

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
let ai_workspace_dir = PathBoundary::try_new("ai_sandbox")?;
let ai_request = llm.generate_path(); // Could be anything malicious
let safe_path = ai_workspace_dir.strict_join(ai_request)?; // ✅ Attack = Explicit Error
safe_path.write(&ai_generated_content)?;

// Limited system access with clear boundaries
struct ConfigFiles; 
let app_config_dir = PathBoundary::<ConfigFiles>::try_new("./config")?;
let user_config = app_config_dir.strict_join(user_selected_config)?; // ✅ Validated
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


## 🚀 **Real-World Examples**

> "Every example here survived a close encounter with an LLM."

### LLM Agent File Manager
```rust
use strict_path::PathBoundary;

// Encode guarantees in signature: pass workspace directory boundary and untrusted request
async fn llm_file_operation(workspace_dir: &PathBoundary, request: &LlmRequest) -> Result<String> {
    // LLM could suggest anything: "../../../etc/passwd", "C:/Windows/System32", etc.
    let safe_path = workspace_dir.strict_join(&request.filename)?; // ✅ Attack = Error

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
        let vpath = extract_root.virtual_join(&name)?; // ✅ Zip slip impossible
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
    let safe_path = static_dir.strict_join(path)?; // ✅ "../../../" → Error
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


## 🔐 **Advanced: Type-Safe Context Separation**

> "Type safety: because mixing up user files and web assets is so 2005."

Use markers to prevent mixing different storage contexts at compile time:

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

struct WebAssets;    // CSS, JS, images  
struct UserFiles;    // Uploaded documents

// Functions enforce context via type system
fn serve_asset(web_asset_file: &StrictPath<WebAssets>) -> Response { /* ... */ }
fn process_upload(user_file: &StrictPath<UserFiles>) -> Result<()> { /* ... */ }

// Create context-specific roots
let public_assets_root: VirtualRoot<WebAssets> = VirtualRoot::try_new("public")?;
let user_uploads_root: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;

let css_file: VirtualPath<WebAssets> = public_assets_root.virtual_join("app.css")?;
let report_file: VirtualPath<UserFiles> = user_uploads_root.virtual_join("report.pdf")?;

// Type system prevents context mixing
serve_asset(css_file.as_unvirtual());         // ✅ Correct context
// serve_asset(report_file.as_unvirtual());   // ❌ Compile error!
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
let app_config_dir = PathBoundary::try_new_create(AppPath::new("MyApp").get_app_dir())?;
let safe_config = app_config_dir.strict_join(user_config_name)?; // ✅ Validated
safe_config.write(&settings)?;
```

## ⚠️ Anti-Patterns (Tell‑offs and Fixes)

> "Don't be that developer: use the right display method."

### DON'T Mix Interop with Display

```rust
use strict_path::PathBoundary;
let user_uploads_dir = PathBoundary::try_new("./uploads")?; // user uploads directory boundary

// ❌ ANTI-PATTERN: Wrong method for display
println!("Path: {}", user_uploads_dir.interop_path().to_string_lossy());

// ✅ CORRECT: Use proper display methods
println!("Path: {}", user_uploads_dir.strictpath_display());

// For virtual flows, prefer `VirtualPath` and borrow strict view when needed:
use strict_path::VirtualPath;
let user_uploads_vroot = VirtualPath::with_root("./uploads")?; // user uploads root
let profile_avatar_file = user_uploads_vroot.virtual_join("profile/avatar.png")?; // file by domain role
println!("Virtual: {}", profile_avatar_file.virtualpath_display());
println!("System: {}", profile_avatar_file.as_unvirtual().strictpath_display());
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
let safe_path = static_files_dir.strict_join(&user_requested_path)?; // ✅ Validated
serve_static_file(&safe_path).await?;
```

### Archive Extraction (Zip Slip Prevention)
See the mdBook archive extractors guide for the full example and rationale:
https://dk26.github.io/strict-path-rs/archive_extractors.html

### Cloud Storage API  

```rust
// User chooses any path - always safe
let user_cloud_root = VirtualPath::with_root(format!("/cloud/user_{id}"))?;
let user_cloud_file = user_cloud_root.virtual_join(&user_requested_path)?; // ✅ Always safe
user_cloud_file.write(upload_data)?;
```

### Configuration Files
```rust
use strict_path::PathBoundary;

// Encode guarantees via the signature: pass the boundary and an untrusted name
fn load_config(config_dir: &PathBoundary, name: &str) -> Result<String> {
    config_dir.strict_join(name)?.read_to_string() // ✅ Validated
}
```

### LLM/AI File Operations
```rust
// AI suggests file operations - always validated
let ai_workspace_dir = PathBoundary::try_new("ai_workspace")?;
let ai_suggested_path = llm_generate_filename(); // Could be anything!
let safe_ai_path = ai_workspace_dir.strict_join(ai_suggested_path)?; // ✅ Guaranteed safe
safe_ai_path.write(&ai_generated_content)?;
```

## 📚 **Documentation & Resources**

> "If you read the docs, you get +10 security points."

- **📖 [Complete API Reference](https://docs.rs/strict-path)** - Comprehensive API documentation
- **📚 [User Guide & Examples](https://dk26.github.io/strict-path-rs/)** - In-depth tutorials and patterns
    - Best Practices (detailed decision matrix): https://dk26.github.io/strict-path-rs/best_practices.html
    - Anti-Patterns (don’t-do list with fixes): https://dk26.github.io/strict-path-rs/anti_patterns.html
    - Examples (copy/pasteable scenarios): https://dk26.github.io/strict-path-rs/examples.html
- **🔧 [LLM_API_REFERENCE.md](LLM_API_REFERENCE.md)** - Quick reference for all methods (LLM-focused)
- **🛠️ [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - The underlying path resolution engine

## 🔌 **Integrations**

> "Integrate like a pro: strict-path plays nice with everyone except attackers."

- **🗂️ OS Directories** (`dirs` feature): `PathBoundary::try_new_os_config()`, `try_new_os_downloads()`, etc.
- **📄 Serde** (`serde` feature): Safe serialization/deserialization of path types
- **🌐 Axum**: Custom extractors for web servers (see `demos/` for examples)

## 📄 **License**

MIT OR Apache-2.0
