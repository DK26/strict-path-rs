# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)** | 🧭 **[Choosing Canonicalized vs Lexical Solution](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)**

Prevent directory traversal attacks with compile-time path boundary enforcement. File paths are mathematically proven to stay within designated boundaries. Choose **StrictPath** to detect and reject escape attempts, or **VirtualPath** to contain and isolate them. Built on battle-tested canonicalization defending against 19+ real-world CVEs including symlinks, Windows 8.3 short names, and encoding tricks.

---

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1.0-rc.1"
```

```rust
use strict_path::StrictPath;

// GET /download?file=report.pdf
let untrusted_user_input = request.query_param("file").to_string(); // Untrusted: "report.pdf" or "../../etc/passwd"

let file = StrictPath::with_boundary("/var/app/downloads")?
    .strict_join(&untrusted_user_input)?; // Validates untrusted input - attack blocked!

let contents = file.read()?; // Safe built-in I/O sugar operation
```

**That's it.** Simple, safe, and path traversal attacks are blocked automatically.

> **Analogy:** `StrictPath` is to paths what prepared statements are to SQL. The boundary is your prepared statement (the policy). The untrusted segment is the parameter (validated safely). Injection attempts become inert.

### Which type should I use?

- **Path/PathBuf** (std): When the path comes from a safe source within your control, not external input.
- **StrictPath**: When you want to restrict paths to a specific boundary and error if they escape.
- **VirtualPath**: When you want to provide path freedom under isolation.

See the detailed decision matrix below: **StrictPath vs VirtualPath: When to Use What**.

**For reusable boundaries** (e.g., passing to functions):

```rust
use strict_path::PathBoundary;

fn extract_archive(
    extraction_dir: PathBoundary,
    entries: Vec<(String, Vec<u8>)>) -> std::io::Result<()> {
    
    for (entry_name, data) in entries {
        let safe_file = extraction_dir.strict_join(&entry_name)?;
        safe_file.create_parent_dir_all()?;
        safe_file.write(&data)?;
    }
    Ok(())
}
```

> 📖 **New to strict-path?** Start with the **[Tutorial: Stage 1 - The Basic Promise →](https://dk26.github.io/strict-path-rs/tutorial/stage1_basic_promise.html)**

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

## 🚀 **More Real-World Examples**

### Archive Extraction (Zip Slip Prevention)

```rust
use strict_path::PathBoundary;

fn extract_archive(
    extraction_dir: PathBoundary,
    archive_entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {

    for (entry_path, data) in archive_entries {
        // Malicious paths like "../../../etc/passwd" → Err(PathEscapesBoundary)
        let safe_file = extraction_dir.strict_join(&entry_path)?;
        safe_file.create_parent_dir_all()?;
        safe_file.write(&data)?;
    }
    Ok(())
}
```

Prevents [CVE-2018-1000178 (Zip Slip)](https://snyk.io/research/zip-slip-vulnerability) automatically.

### Multi-Tenant Isolation

```rust
use strict_path::VirtualRoot;

fn handle_file_request(tenant_id: &str, requested_path: &str) -> std::io::Result<Vec<u8>> {
    let tenant_root = VirtualRoot::try_new_create(format!("./tenants/{tenant_id}"))?;
    
    // "../../other_tenant/secrets.txt" → clamped to "/other_tenant/secrets.txt" in THIS tenant
    let user_file = tenant_root.virtual_join(requested_path)?;
    user_file.read()
}
```

---

## 🛡️ **Complete Security Solution**

**strict-path handles edge cases you'd never think to check:**

1. **🔧 [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation**: Battle-tested against 19+ real-world path CVEs
2. **🔗 Full canonicalization**: Resolves symlinks, junctions, `.`/`..` components, handles race conditions
3. **🚫 Advanced attacks**: Catches Windows 8.3 short names (`PROGRA~1`), UNC paths, NTFS ADS, encoding tricks
4. **📐 Compile-time proof**: Rust's type system enforces path boundaries
5. **👁️ Explicit operations**: Method names like `strict_join()` make security visible in code review
6. **🛡️ Built-in I/O**: Complete filesystem API without needing `.interop_path()`
7. **🤖 LLM-aware**: Built for untrusted AI-generated paths and modern threat models
8. **⚡ Dual modes**: **Strict** (detect & reject) or **Virtual** (clamp & contain)

**Real attacks we handle automatically:**
- Windows 8.3 short names (`PROGRA~1` → `Program Files`)
- NTFS Alternate Data Streams (`file.txt:hidden:$DATA`)
- Unicode normalization bypasses (`..∕..∕etc∕passwd`)
- Symlink time-bombs (TOCTOU race conditions)
- Mixed separators (`../\../etc/passwd`)
- UNC path tricks (`\\?\C:\..\..\etc\passwd`)

**Recently Addressed CVEs:**
- **CVE-2025-8088** (WinRAR): NTFS Alternate Data Stream traversal
- **CVE-2022-21658**: Race condition protection (TOCTOU)
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793**: Windows 8.3 short names

> 📖 **[Read our complete security methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)** | 📚 **[Built-in I/O Methods →](https://dk26.github.io/strict-path-rs/best_practices.html#builtin-io-operations)**

## 🎯 **StrictPath vs VirtualPath: When to Use What**

**The Core Question**: Are path escapes attacks or expected behavior?

| Mode            | Philosophy                        | Returns on Escape           | Use When                             |
| --------------- | --------------------------------- | --------------------------- | ------------------------------------ |
| **StrictPath**  | "Detect & reject escape attempts" | `Err(PathEscapesBoundary)`  | Archive extraction, file uploads     |
| **VirtualPath** | "Contain & clamp escape attempts" | Clamped within virtual root | Multi-tenant apps, malware sandboxes |

**Choose StrictPath (90% of cases):**
- Archive extraction, file uploads, config loading
- LLM/AI agent file operations
- Shared system resources (logs, cache, assets)
- **Any case where escapes = attacks**

**Choose VirtualPath (10% of cases):**
- Multi-tenant isolation (per-user filesystem views)
- Malware analysis sandboxes
- Container-like plugins
- **Any case where escapes = expected but must be controlled**

> 📖 **[Complete Decision Matrix →](https://dk26.github.io/strict-path-rs/best_practices.html)** | 📚 **[More Examples →](https://dk26.github.io/strict-path-rs/examples.html)**

---

## 🧠 **Compile-Time Safety with Markers**

`StrictPath<Marker>` enables **domain separation and authorization** at compile time:

```rust
struct UserFiles;
struct SystemFiles;

fn process_user(f: &StrictPath<UserFiles>) -> Vec<u8> { f.read().unwrap() }

let user_boundary = PathBoundary::<UserFiles>::try_new_create("user_data")?;
let sys_boundary = PathBoundary::<SystemFiles>::try_new_create("system")?;

let user_input = get_filename_from_request();
let user_file = user_boundary.strict_join(user_input)?;
// process_user(&sys_file)?; // ❌ Compile error - wrong marker type!
```

> 📖 **[Complete Marker Tutorial →](https://dk26.github.io/strict-path-rs/tutorial/stage3_markers.html)** - Authorization patterns, permission matrices, `change_marker()` usage

---

## ⚠️ **Security Coverage**

**Protects Against (99% of attacks):**
- Path traversal (`../../../etc/passwd`)
- Symlink/junction escapes
- Archive attacks (Zip slip - CVE-2018-1000178)
- Encoding tricks (Unicode, null bytes)
- Windows attacks (8.3 names, UNC, NTFS ADS)
- Race conditions (TOCTOU - CVE-2022-21658)

**What This Is / Is NOT:**
- ✅ **Follows filesystem links** and resolves paths properly
- ✅ **Works with your permissions** (doesn't replace them)
- ❌ **Not just string checking** (handles symlinks, Windows quirks)
- ❌ **Not an OS-level sandbox** (path-level security)
- ❌ **Not a replacement for proper auth** (validates paths, not users)

**vs. soft-canonicalize:**
- `soft-canonicalize` = low-level path resolution engine (returns `PathBuf`)
- `strict-path` = high-level security API (returns `StrictPath<Marker>` with compile-time guarantees)

> 📖 **[Security Methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)** | 📚 **[Anti-Patterns Guide →](https://dk26.github.io/strict-path-rs/anti_patterns.html)**

---

## 🔌 **Ecosystem Integration**

Compose with standard Rust crates for complete solutions:

| Integration  | Purpose                 | Guide                                                                                       |
| ------------ | ----------------------- | ------------------------------------------------------------------------------------------- |
| **tempfile** | Secure temp directories | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#tempfile)          |
| **dirs**     | OS standard directories | [Guide](https://dk26.github.io/strict-path-rs/os_directories.html)                          |
| **app-path** | Application directories | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#app-path)          |
| **serde**    | Safe deserialization    | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#serde-and-fromstr) |
| **Axum**     | Web server extractors   | [Tutorial](https://dk26.github.io/strict-path-rs/axum_tutorial/overview.html)               |
| **Archives** | ZIP/TAR extraction      | [Guide](https://dk26.github.io/strict-path-rs/examples/archive_extraction.html)             |

> 📚 **[Complete Integration Guide →](https://dk26.github.io/strict-path-rs/ecosystem_integration.html)**

---

## 📚 **Learn More**

- 📖 **[API Documentation](https://docs.rs/strict-path)** - Complete API reference
- 📚 **[User Guide](https://dk26.github.io/strict-path-rs/)** - Tutorials and patterns
  - [Best Practices](https://dk26.github.io/strict-path-rs/best_practices.html) - Detailed decision matrix
  - [Anti-Patterns](https://dk26.github.io/strict-path-rs/anti_patterns.html) - Common mistakes
  - [Examples](https://dk26.github.io/strict-path-rs/examples.html) - Copy-paste scenarios
- 🔧 **[LLM_API_REFERENCE.md](LLM_API_REFERENCE.md)** - Quick reference for AI agents
- 🛠️ **[`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - Path resolution engine

---

## 📄 **License**

MIT OR Apache-2.0
