# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Kani Verified](https://github.com/DK26/strict-path-rs/actions/workflows/kani.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/kani.yml)
[![Protected CVEs](https://img.shields.io/badge/protected%20CVEs-19%2B-brightgreen.svg)](https://github.com/DK26/strict-path-rs/blob/main/strict-path/src/path/tests/cve_2025_11001.rs)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

**Handle paths from external or unknown sources securely.** `strict-path` defends against 19+ real-world CVEs including symlinks, Windows 8.3 short names, and encoding tricks and exploits.

> **Analogy:** `strict-path` is to paths what prepared statements are to SQL.

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1"
```

```rust
use strict_path::StrictPath;

// GET /download?file=report.pdf
let untrusted_user_input = request.query_param("file").to_string(); // Untrusted: "report.pdf" or "../../etc/passwd"

let file = StrictPath::with_boundary("/var/app/downloads")?
    .strict_join(&untrusted_user_input)?; // Validates untrusted input - attack blocked!

let contents = file.read()?; // Safe built-in I/O
send_response(contents);

// Need to pass to a third-party crate that requires AsRef<Path>?
third_party::process(file.interop_path()); // &OsStr — implements AsRef<Path>
```

> **Note:** Our doc comments and [LLM_CONTEXT_FULL.md](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md) are designed for LLMs with function calling—enabling AI agents to use this crate safely and correctly for file and path operations.
> 
> ### 🤖 LLM agent prompt (copy/paste)
> 
> ``` 
> Fetch and follow this reference (single source of truth):
> https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md
> ```
>
> #### Context7 Style
>
> ```
> Fetch and follow this reference (single source of truth):
> https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT.md
> ```

> 📖 **New to strict-path?** Start with the **[Tutorial: Chapter 1 - The Basic Promise →](https://dk26.github.io/strict-path-rs/tutorial/chapter1_basic_promise.html)**


## 🛡️ **Complete Path Security**

**strict-path handles edge cases you'd never think to check:**

1. **🔧 [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation**: Battle-tested against 19+ real-world path CVE scenarios
2. **🔗 Full canonicalization**: Resolves symlinks, junctions, `.`/`..` components, handles race conditions
3. **🚫 Advanced attacks**: Catches Windows 8.3 short names (`PROGRA~1`), UNC paths, NTFS ADS, encoding tricks
4. **📐 Compile-time proof**: Rust's type system enforces path boundaries
5. **👁️ Explicit operations**: Method names like `strict_join()` make security visible in code review
6. **🛡️ Built-in I/O**: Complete filesystem API
7. **🤖 LLM-aware**: Built for untrusted AI-generated code and modern threat models
8. **⚡ Dual modes**: **PathBoundary** (detection & rejection) or **VirtualRoot** (clamping & containing)

**Real attacks we handle automatically:**
- Path traversal (`../../../etc/passwd`)
- Symlink/junction escapes
- Windows 8.3 short names (`PROGRA~1` → `Program Files`)
- NTFS Alternate Data Streams (`file.txt:hidden:$DATA`)
- Unicode normalization bypasses (`..∕..∕etc∕passwd`)
- Null byte injection (`file.txt\x00.pdf`)
- Mixed separators (`../\../etc/passwd`)
- UNC path tricks (`\\?\C:\..\..\etc\passwd`)
- Archive attacks (Zip slip - CVE-2018-1000178)
- Race conditions (TOCTOU - CVE-2022-21658)

**Recently Addressed CVEs:**
- **CVE-2025-8088** (WinRAR): NTFS Alternate Data Stream traversal
- **CVE-2022-21658**: Race condition protection (TOCTOU)
- **CVE-2019-9855, CVE-2020-12279, CVE-2017-17793**: Windows 8.3 short names

**What This Is NOT:**
- ❌ **Not just string checking** (handles symlinks, Windows quirks)
- ❌ **Not a kernel based sandbox** (path-level security only)

> 📖 **[Read our complete security methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)** | 📚 **[Built-in I/O Methods →](https://dk26.github.io/strict-path-rs/best_practices.html#builtin-io-operations)**

## 🎯 **StrictPath vs VirtualPath: When to Use What**

### Which type should I use?

- **Path/PathBuf** (std): When the path comes from a safe source within your control, not external input.
- **StrictPath**: When you want to restrict paths to a specific boundary and error if they escape.
- **VirtualPath**: When you want to provide path freedom under isolation.

**Choose StrictPath (90% of cases):**
- Archive extraction, config loading
- File uploads to shared storage (admin panels, CMS assets, single-tenant apps)
- LLM/AI agent file operations
- Shared system resources (logs, cache, assets)
- **Any case where escaping a path boundary, is considered malicious**

**Choose VirtualPath (10% of cases):**
- Multi-tenant file uploads (SaaS per-user storage, isolated user directories)
- Multi-tenant isolation (per-user filesystem views)
- Malware analysis sandboxes
- Container-like plugins
- **Any case where you would like to allow freedom of operations under complete isolation**

> 📖 **[Complete Decision Matrix →](https://dk26.github.io/strict-path-rs/best_practices.html)** | 📚 **[More Examples →](https://dk26.github.io/strict-path-rs/examples.html)**

---

## 🔗 **Interop with Third-Party Crates**

`StrictPath` and `VirtualPath` intentionally do **not** implement `AsRef<Path>` or `Deref<Target = Path>` — doing so would let any code silently bypass path safety via `std::fs` operations.

When a third-party crate requires `AsRef<Path>`, use `.interop_path()`:

```rust
use strict_path::StrictPath;

let validated_file = StrictPath::with_boundary("/var/app/data")?
    .strict_join(&user_input)?;

// .interop_path() returns &OsStr, which implements AsRef<Path>
external_crate::open(validated_file.interop_path()); // ✅ Pass to third-party APIs

// Use built-in I/O when possible — no interop needed
let contents = validated_file.read_to_string()?; // ✅ Stays within safety boundary
```

**Why `&OsStr` instead of `&Path`?**  
Returning `&Path` would make it easy to accidentally chain `std::path::Path` methods (`.join()`, `.parent()`) that bypass validation. `&OsStr` forces an explicit cast, making unintended std path operations visible in code review.

**Rules of thumb:**
- **Built-in I/O** (`read()`, `write()`, `create_dir_all()`, etc.) → use directly, no interop needed
- **Third-party crate** needs `AsRef<Path>` → use `.interop_path()`
- **Display/logging** → use `.strictpath_display()` or `.virtualpath_display()` (never expose `.interop_path()` to end users — it contains real host paths)


> **API Philosophy:** Minimal, restrictive, and explicit—designed to prevent and easily detect both human and LLM agent API misuse. Security is prioritized above performance; if your use case doesn't involve symlinks and you need to squeeze every bit of performance, a lexical-only solution may be a better fit. `strict-path` accesses the disk to validate and secure paths, by resolving all its components. This predicts correctly where a path would end-up leading to on a disk filesystem by simulating disk access. This method ignores anything a hacker could put as input path string, since we validate only against where the file being accessed from or written to, would end up being.

---

## 🚀 **More Real-World Examples**

### Archive Extraction (Zip Slip Prevention)

`PathBoundary` is a special type that represents a boundary for paths. It is optional, and could be used to express parts in our code where we expect a path to represent a boundary path:

```rust
use strict_path::PathBoundary;

// Prevents CVE-2018-1000178 (Zip Slip) automatically (https://snyk.io/research/zip-slip-vulnerability)
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

> The equivalent `PathBoundary` for `VirtualPath` type is the `VirtualRoot` type.


### Multi-Tenant Isolation

```rust
use strict_path::VirtualRoot;

// No path-traversal or symlinks, could escape a tenant. 
// Everything is clamped to the virtual root, including symlink resolutions.
fn handle_file_request(tenant_id: &str, requested_path: &str) -> std::io::Result<Vec<u8>> {
    let tenant_root = VirtualRoot::try_new_create(format!("./tenants/{tenant_id}"))?;
    
    // "../../other_tenant/secrets.txt" → clamped to "/other_tenant/secrets.txt" in THIS tenant
    let user_file = tenant_root.virtual_join(requested_path)?;
    user_file.read()
}
```

---


## 🧠 **Compile-Time Safety with Markers**

`StrictPath<Marker>` enables **domain separation and authorization** at compile time:

```rust
struct UserFiles;
struct SystemFiles;

fn process_user(f: &StrictPath<UserFiles>) -> Vec<u8> { f.read().unwrap() }

let user_boundary = PathBoundary::<UserFiles>::try_new_create("./data/users")?;
let sys_boundary = PathBoundary::<SystemFiles>::try_new_create("./system")?;

let user_input = get_filename_from_request();
let user_file = user_boundary.strict_join(user_input)?;
process_user(&user_file); // ✅ OK - correct marker type

let sys_file = sys_boundary.strict_join("config.toml")?;
// process_user(&sys_file); // ❌ Compile error - wrong marker type!
```

> 📖 **[Complete Marker Tutorial →](https://dk26.github.io/strict-path-rs/tutorial/chapter3_markers.html)** - Authorization patterns, permission matrices, `change_marker()` usage

---

### vs `soft-canonicalize`

**Compared with manual soft-canonicalize path validations:**
- `soft-canonicalize` = low-level path resolution engine (returns `PathBuf`)
- `strict-path` = high-level security API (returns `StrictPath<Marker>` with compile-time guarantees: fit for LLM era)

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
- 🔧 **[LLM_CONTEXT_FULL.md](LLM_CONTEXT_FULL.md)** - Full API reference for AI agents
- 📝 **[LLM_CONTEXT.md](LLM_CONTEXT.md)** - Context7-style usage guide for AI agents
- 🛠️ **[`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)** - Path resolution engine

📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)** | 🧭 **[Choosing Canonicalized vs Lexical Solution](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)**

---

## 📄 **License**

MIT OR Apache-2.0
