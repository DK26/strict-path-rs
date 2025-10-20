# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)**
| 🧭 **[Choosing Canonicalized vs Lexical Solution](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)**

**Prevent directory traversal attacks with compile-time path boundary enforcement.** File paths are mathematically proven to stay within designated boundaries—no exceptions, no escapes. Choose **StrictPath** to detect and reject escape attempts, or **VirtualPath** to contain and isolate them. Built on battle-tested canonicalization defending against 19+ real-world CVEs including symlinks, Windows 8.3 short names, and encoding tricks.

> **Note:** Our doc comments and [LLM_API_REFERENCE.md](https://github.com/DK26/strict-path-rs/blob/main/LLM_API_REFERENCE.md) are designed for LLMs with function calling—enabling AI agents to use this crate safely and correctly for file and path operations.
> 
> ### 🤖 LLM agent prompt (copy/paste)
> 
> ``` 
> Fetch and follow this reference (single source of truth):
> https://github.com/DK26/strict-path-rs/blob/main/LLM_API_REFERENCE.md
> ```
>
> #### Context7 Style
>
> ```
> Fetch and follow this reference (single source of truth):
> https://github.com/DK26/strict-path-rs/blob/main/LLM_USER.md
> ```

---

## Quick start

> *"If you can read this file, you've already passed your first PathBoundary checkpoint."*

### Policy types (reusable, explicit)

```rust
use strict_path::PathBoundary;

// 1. Define the boundary - paths are contained within ./app/uploads_dir
//    try_new() requires directory exists (use try_new_create() to create if missing)
let uploads_boundary = PathBoundary::try_new("./app/uploads_dir")?;

// 2. Validate untrusted user input against the boundary
let user_file = uploads_boundary.strict_join("documents/report.pdf")?;

// 3. Safe I/O operations - guaranteed within boundary
user_file.create_parent_dir_all()?;
user_file.write(b"file contents")?;
let contents = user_file.read_to_string()?;

// 4. Escape attempts are detected and rejected
match uploads_boundary.strict_join("../../etc/passwd") {
    Ok(_) => panic!("Escapes should be caught!"),
    Err(e) => println!("Attack blocked: {e}"), // PathEscapesBoundary error
}
```

**With `virtual-path` feature enabled:**

```rust
use strict_path::VirtualRoot;

// Virtual filesystem for multi-tenant isolation (requires "virtual-path" feature)
// Note: path_absolutize::absolutize_virtually REJECTS escapes (returns Err);
// VirtualPath CLAMPS them within the boundary (returns Ok, contained path)
let tenant_id = "alice";
let tenant_vroot = VirtualRoot::try_new_create(format!("./tenant_data/{tenant_id}"))?;
let tenant_file = tenant_vroot.virtual_join("../../../sensitive")?;
// Escape attempt is silently clamped - stays within tenant_data
println!("Virtual path: {}", tenant_file.virtualpath_display()); // Shows: "/sensitive"
```

### One-liner sugar (quick prototyping)

```rust
use strict_path::StrictPath;

// Concise form - boundary created inline and joined in one expression
// with_boundary() requires directory exists; use with_boundary_create() to create if missing
let config_file = StrictPath::with_boundary("./app/config")?.strict_join("app.toml")?;
config_file.write(b"settings")?;
```

**With `virtual-path` feature enabled:**

```rust
use strict_path::VirtualPath;

// Virtual paths require dynamic tenant/user IDs for per-user isolation
let user_id = get_authenticated_user_id();
let user_avatar = VirtualPath::with_root_create(format!("./user_data/{user_id}"))?.virtual_join("/profile/avatar.png")?;
user_avatar.create_parent_dir_all()?;
user_avatar.write(b"image data")?;
// Each user sees "/profile/avatar.png" but they're isolated on disk
```

> 📖 **New to strict-path?** Start with the **[Tutorial: Stage 1 - The Basic Promise →](https://dk26.github.io/strict-path-rs/tutorial/stage1_basic_promise.html)** to learn the core concepts step-by-step.

## 🚨 **One Line of Code Away from Disaster**

> "One does not simply walk into /etc/passwd."

```rust
use strict_path::StrictPath;

let user_input = "../../../etc/passwd";

// ❌ This single line can destroy your server
// std::fs::write(user_input, data)?;

// ✅ This single line makes it mathematically impossible - boundary + validation chained
let result = StrictPath::with_boundary_create("./app/uploads_dir")?.strict_join(user_input)?; // Returns Err(PathEscapesBoundary) - attack blocked!
```

## Features

- `virtual-path` (opt-in): Enables `VirtualRoot`/`VirtualPath` and all virtual APIs.
- `junctions` (Windows-only, opt-in): Enables built-in NTFS directory junction helpers.

Enable in Cargo.toml:

```toml
[dependencies]
strict-path = { version = "...", features = ["virtual-path"] }
```

Windows junction helpers:

```toml
[dependencies]
strict-path = { version = "...", features = ["junctions"] }
```

### Ecosystem Integration

📚 **[Complete Integration Guide →](https://dk26.github.io/strict-path-rs/ecosystem_integration.html)** - Full examples for tempfile, dirs, app-path, and serde patterns

**The Reality**: Every web server, LLM agent, and file processor faces the same vulnerability. One unvalidated path from user input, config files, or AI responses can grant attackers full filesystem access.

**The Solution**: Comprehensive path security with mathematical guarantees — including symlink safety, Windows path quirks, and encoding pitfalls.

> Analogy: `StrictPath` is to paths what a prepared statement is to SQL.
>
> - The boundary/root you create is like preparing a statement: it encodes the policy (what’s allowed).
> - The untrusted filename or path segment is like a bound parameter: it’s validated/clamped safely via `strict_join`/`virtual_join`.
> - The API makes injection attempts inert: hostile inputs can’t escape the boundary, just like SQL parameters can’t change the query.

## 🛡️ **How We Solve The Entire Problem Class**

> "Symlinks: the ninja assassins of your filesystem."

**strict-path isn't just validation—it's a complete solution that handles edge cases you'd never think to check:**

1. **🔧 [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation**: Battle-tested against 19+ real-world path CVEs
2. **🚫 Advanced pattern detection**: Catches encoding tricks, Windows 8.3 short names (`PROGRA~1`), UNC paths, NTFS Alternate Data Streams, and malformed inputs
3. **🔗 Full canonicalization pipeline**: Resolves symlinks, junctions, `.` and `..` components, and handles filesystem race conditions
4. **📐 Mathematical correctness**: Rust's type system provides compile-time proof of path boundaries
5. **🔐 Authorization architecture**: Enable compile-time authorization guarantees through marker types
6. **👁️ Explicit operations**: Method names like `strict_join()` make security violations visible in code review
7. **🛡️ Safe builtin I/O operations**: Complete filesystem API for everyday operations
8. **🤖 LLM-aware design**: Built for untrusted AI-generated paths and modern threat models
9. **⚡ Dual protection modes**: Choose **Strict** (validate & reject) or **Virtual** (clamp & contain) based on your use case
10. **🏗️ Battle-tested architecture**: Prototyped and refined across real-world production systems
11. **🎯 Zero-allocation interop**: Seamless integration with existing `std::path` ecosystems when needed

> 📖 **[Read our complete security methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)**  
> *Deep dive into our 7-layer security approach: from CVE research to comprehensive testing*

### **Recently Addressed CVEs**
- **CVE-2025-8088** (WinRAR ADS): NTFS Alternate Data Stream traversal prevention
- **CVE-2022-21658** (TOCTOU): Race condition protection during path resolution  
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793**: Windows 8.3 short name vulnerabilities

**Your security audit becomes**: *"We use strict-path for comprehensive path security."* ✅

📚 **[Built-in I/O Methods →](https://dk26.github.io/strict-path-rs/best_practices.html#builtin-io-operations)** - Complete reference for safe filesystem operations without `.interop_path()`

## What this is NOT

- **Not just string checking**: Actually follows filesystem links and resolves paths properly
- **Not a simple wrapper**: Built from the ground up for security, not a thin layer over existing types  
- **Not just removing ".."**: Handles symlinks, Windows short names, and other escape tricks
- **Not a permission system**: Works with your existing file permissions, doesn't replace them
- **Not a sandbox**: Secures paths at the path level, not at the OS level

## 🔍 **Comparison with Other Solutions**

### **strict-path vs soft-canonicalize**

`soft-canonicalize` is the **low-level foundation**; `strict-path` is the **complete security solution** built on top.

| Aspect          | `soft-canonicalize`            | `strict-path`                                             |
| --------------- | ------------------------------ | --------------------------------------------------------- |
| **Level**       | Low-level path resolution      | High-level security API                                   |
| **Purpose**     | Normalize paths for comparison | Enforce path boundaries                                   |
| **Type system** | Returns `PathBuf`              | Returns `StrictPath<Marker>` with compile-time guarantees |

**Use `soft-canonicalize`** for custom path security logic; **use `strict-path`** for comprehensive protection with minimal code.

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1.0-rc.1"
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

## 🧬 **The Edge Cases You'd Never Think Of**

> "Security is hard because the edge cases are infinite—until now."

**What would you check for when validating a file path?** Most developers think: *"I'll block `../` and call it a day."* But real attackers use techniques you've probably never heard of:

- **Windows 8.3 short names**: `PROGRA~1` → `Program Files` (filesystem aliases that bypass string checks)
- **NTFS Alternate Data Streams**: `config.txt:hidden:$DATA` (secret channels in "normal" files)
- **Unicode normalization**: `..∕..∕etc∕passwd` (visually identical but different bytes)
- **Symlink time-bombs**: Links that resolve differently between validation and use (TOCTOU)
- **Mixed path separators**: `../\../etc/passwd` (exploiting parser differences)
- **UNC path shenanigans**: `\\?\C:\Windows\..\..\..\etc\passwd` (Windows extended paths)

**The reality**: You'd need months of research, testing across platforms, and deep filesystem knowledge to handle these correctly.

**Our approach**: We've already done the research. `strict-path` is built on `soft-canonicalize`, which has been battle-tested against 19+ real CVEs. You get comprehensive protection without becoming a path security expert.

## 🧠 **Marker Types: Compile-Time Guarantees**

`StrictPath<Marker>` enables **compile-time domain separation and authorization guarantees**—making wrong path usage a compiler error. Use markers like `StrictPath<SystemFiles>` for domain separation or `StrictPath<(SystemFiles, ReadOnly)>` for permission matrices.

📖 **[Complete Marker Tutorial →](https://dk26.github.io/strict-path-rs/tutorial/stage3_markers.html)** - Domain separation, authorization patterns, permission matrices, and `change_marker()` usage

## 🎯 **When to Use What**

**Critical distinction - Detect vs. Contain:**
- **`StrictPath` (default):** Detects escape attempts and returns `Err(PathEscapesBoundary)`. Use when path escapes indicate **malicious intent**.
- **`VirtualPath` (opt-in):** Contains escape attempts by clamping to virtual root. Use when path escapes are **expected but must be controlled**.

**Primary threats:**
- **Malicious actors**: Attackers actively probe for path traversal through user inputs, config files, archives, and external APIs. `StrictPath` detects and rejects; `VirtualPath` contains within isolated boundaries.
- **LLM agents**: While generally reliable, LLMs can occasionally produce unexpected paths. `StrictPath`/`VirtualPath` provides insurance—validation (strict) or clamping (virtual) ensures safe operation.

| Source/Input                                     | Choose         | Why                                    |
| ------------------------------------------------ | -------------- | -------------------------------------- |
| HTTP/CLI args/config/LLM/DB (untrusted segments) | `StrictPath`   | Detect and reject attacks explicitly   |
| Archive extraction, file uploads                 | `StrictPath`   | Detect malicious paths; fail on escape |
| Malware analysis sandbox, multi-tenant isolation | `VirtualPath`  | Contain escapes; observe safely        |
| Your own code/hardcoded paths                    | `Path/PathBuf` | You control the value                  |
| External APIs/webhooks/inter-service messages    | `StrictPath`   | Validate on consume before touching FS |

 **[Complete Decision Matrix →](https://dk26.github.io/strict-path-rs/best_practices.html)** - Full guide with rationale, symlink behavior, edge cases, and advanced patterns

## 🚀 **Real-World Examples**

### Archive Extraction (Zip Slip Prevention)
```rust
use strict_path::PathBoundary;

fn extract_zip(zip_entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
    let extract_boundary = PathBoundary::try_new_create("./app/extracted")?;
    for (name, data) in zip_entries {
        // Hostile names like "../../../etc/passwd" are rejected with PathEscapesBoundary error
        let safe_path = extract_boundary.strict_join(&name)?; // Zip slip detected & blocked
        safe_path.create_parent_dir_all()?;
        safe_path.write(&data)?;
    }
    Ok(())
}
```

### Multi-Tenant Isolation (VirtualPath)
```rust
use strict_path::VirtualRoot;

// Each tenant gets isolated filesystem view
let tenant_id = get_authenticated_tenant_id();
let tenant_root = VirtualRoot::try_new_create(format!("./app/tenant_data/{tenant_id}"))?;

// User sees "/documents/report.pdf" - system stores at ./app/tenant_data/{tenant_id}/documents/report.pdf
let user_file = tenant_root.virtual_join("/documents/report.pdf")?;
user_file.create_parent_dir_all()?;
user_file.write(b"tenant data")?;

// Escape attempts are silently clamped within tenant boundary
let escaped = tenant_root.virtual_join("../../../etc/passwd")?;
println!("{}", escaped.virtualpath_display()); // Shows: "/etc/passwd" (still within tenant_root)
```

📚 **[More Real-World Examples →](https://dk26.github.io/strict-path-rs/examples.html)** - LLM agents, web servers, config managers, and more

## ⚠️ **Security Scope**

**What this protects against (99% of real attacks):**
- Path traversal (`../../../etc/passwd`)
- Symlink escapes and directory bombs
- Archive extraction attacks (Zip slip)
- Encoding bypass attempts (Unicode normalization, null bytes)
- Windows-specific attacks (8.3 short names, UNC paths, NTFS ADS, junctions)
- Race conditions (TOCTOU during path resolution)
- Canonicalization edge cases (mixed separators, malformed paths)

**The reality**: These aren't theoretical—they're real vulnerabilities. Instead of researching each CVE, you get comprehensive protection from day one.

**What requires system privileges (rare):** Hard links and mount points require admin/root access. If attackers have that level of access, they've already won. This library stops the 99% of practical attacks that don't require special privileges.

📚 **[Complete Security Methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)** - Deep dive into our 7-layer security approach  
📚 **[Anti-Patterns Guide →](https://dk26.github.io/strict-path-rs/anti_patterns.html)** - Common mistakes and how to fix them

## 📚 **Documentation & Resources**

- **📖 [Complete API Reference](https://docs.rs/strict-path)** - Comprehensive API documentation
- **📚 [User Guide & Examples](https://dk26.github.io/strict-path-rs/)** - In-depth tutorials and patterns
    - Best Practices (detailed decision matrix): https://dk26.github.io/strict-path-rs/best_practices.html
    - Anti-Patterns (don’t-do list with fixes): https://dk26.github.io/strict-path-rs/anti_patterns.html
    - Examples (copy/pasteable scenarios): https://dk26.github.io/strict-path-rs/examples.html
- **🔧 [LLM_API_REFERENCE.md](LLM_API_REFERENCE.md)** - Quick reference for all methods (LLM-focused)
- **🛠️ [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - The underlying path resolution engine

## 🔌 **Integrations**

> "Integrate like a pro: strict-path plays nice with everyone except attackers."

- **🗂️ OS Directories**: Compose with `dirs` crate for platform-specific paths - **[Full Guide](https://dk26.github.io/strict-path-rs/os_directories.html)**
- **📄 Serde**: Use `FromStr` for safe deserialization - **[Integration Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#serde-and-fromstr)**
- **🧪 Temporary Files**: Compose with `tempfile` crate for secure temp directories - **[tempfile Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#tempfile)**
- **📦 App Paths**: Compose with `app-path` crate for application directories - **[app-path Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#app-path)**
- **🌐 Axum**: Custom extractors for web servers - **[Complete Tutorial](https://dk26.github.io/strict-path-rs/axum_tutorial/overview.html)**
- **📦 Archive Handling**: Safe ZIP/TAR extraction - **[Extractor Guide](https://dk26.github.io/strict-path-rs/examples/archive_extraction.html)**

## 📄 **License**

MIT OR Apache-2.0
