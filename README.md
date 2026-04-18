# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Kani Verified](https://github.com/DK26/strict-path-rs/actions/workflows/kani.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/kani.yml)
[![Protected CVEs](https://img.shields.io/badge/protected%20CVEs-19%2B-brightgreen.svg)](https://github.com/DK26/strict-path-rs/blob/main/strict-path/src/path/tests/cve_2025_11001.rs)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

**Secure path handling for untrusted input.** Paths from users, config files, archives, or AI agents can't escape the directory you put them in — regardless of symlinks, encoding tricks, or platform quirks. [19+ real-world CVEs covered](https://dk26.github.io/strict-path-rs/security_methodology.html#12-coverage-what-we-protect-against).

> Prepared statements prevent SQL injection. `strict-path` prevents path injection.

## 🔍 Why String Checking Isn't Enough

You strip `..` and check for `/`. But attackers have a dozen other vectors:

| Attack vector | String filter | `strict-path` |
|---|---|---|
| `../../../etc/passwd` | ✅ Caught (if done right) | ✅ Blocked |
| Symlink inside boundary → outside | ❌ Passes silently | ✅ Symlink resolved, escape blocked |
| Windows 8.3: `PROGRA~1` bypasses filter | ❌ Passes silently | ✅ Short name resolved, escape blocked |
| NTFS ADS: `file.txt:secret:$DATA` | ❌ Passes silently | ✅ Blocked ([CVE-2025-8088](https://dk26.github.io/strict-path-rs/security_methodology.html)) |
| Unicode tricks: `..∕` (fraction slash U+2215) | ❌ Passes silently | ✅ Blocked |
| Junction/mount point → outside boundary | ❌ Passes silently | ✅ Resolved & blocked |
| TOCTOU race condition (CVE-2022-21658) | ❌ No defense | ⚡ Mitigated at validation |
| Null byte injection | ❌ Truncation varies | ✅ Blocked |
| Mixed separators: `..\../etc` | ❌ Often missed | ✅ Normalized & blocked |

**How it works:** `strict-path` resolves the path on disk — follows symlinks, expands short names, normalizes encoding — then proves the resolved path is inside the boundary. The input string is irrelevant. Only where the path *actually leads* matters.

<details>
<summary><strong>Why canonicalization beats string blocklists</strong></summary>

String-matching libraries maintain lists of dangerous patterns — `..`, `%2e%2e`, `%c0%ae` (overlong UTF-8), `&#46;` (HTML entities), full-width Unicode dots, zero-width characters, and dozens more. Every new encoding trick requires a new blocklist entry, and a single miss is a bypass.

`strict-path` doesn't play that game. It asks the OS to resolve the path, then checks where it landed. URL-encoded `%2e%2e` isn't decoded — it's a literal directory name containing percent signs. Overlong UTF-8 sequences, HTML entities, code-page homoglyphs (¥→`\` in CP932, ₩→`\` in CP949) — none of these matter because the OS never interprets them as path separators or traversal sequences. The canonicalized result either falls inside the boundary or it doesn't.

This is the same principle behind SQL prepared statements: instead of escaping every dangerous character (and inevitably missing one), you separate code from data structurally. `strict-path` separates *path resolution* from *path text*, making the entire class of encoding-bypass attacks irrelevant by design.

</details>

## ⚡ Get Secure in 30 Seconds

```toml
[dependencies]
strict-path = "0.2"  # every dependency closes a security gap — see "Zero Idle Dependencies" below
```

```rust
use strict_path::StrictPath;

// Untrusted input: user upload, API param, config value, AI agent output, archive entry...
let file = StrictPath::with_boundary("/var/app/downloads")?
    .strict_join(&untrusted_user_input)?; // Every attack vector above → Err(PathEscapesBoundary)

let contents = file.read()?; // Built-in safe I/O — stays within the secure API

// Third-party crate needs AsRef<Path>?
third_party::process(file.interop_path()); // &OsStr (implements AsRef<Path>)
```

If the input resolves outside the boundary — by *any* mechanism — `strict_join` returns `Err`.

**What you get beyond path validation:**
- 🛡️ **Built-in I/O** — `read()`, `write()`, `create_dir_all()`, `read_dir()` — no need to drop to `std::fs`
- 📐 **Compile-time markers** — `StrictPath<UserUploads>` vs `StrictPath<SystemConfig>` can't be mixed up
- ⚡ **Dual modes** — `StrictPath` (detect & reject escapes) or `VirtualPath` (clamp & contain)
- 🔒 **Thread-safe** — all types are `Send + Sync`; share across threads and async tasks
- 🤖 **LLM-ready** — doc comments and [context files](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md) designed for AI agents with function calling

**Why the API looks the way it does:**

This crate combines Rust's type system with Python's "one obvious way to do it" philosophy to build an API that **LLMs and humans physically cannot misuse** — wrong code doesn't compile, and the compiler itself teaches you the fix.

- **No `AsRef<Path>`, no `Deref`** — if `StrictPath` implemented these, anything could call `.join()` on it and build a new path that bypasses boundary validation entirely. That one method on `Path` undoes everything `strict_join()` enforces. The type system makes it unreachable.
- **`interop_path()` returns `&OsStr`, not `&Path`** — `Path` has `.join()` and `.parent()`, which let you build new unvalidated paths. `OsStr` has none of that — it's a one-way exit to third-party crates with no way to accidentally re-enter path manipulation.
- **One method per operation** — every operation has exactly one method. An LLM scanning the API can't pick the wrong overload because there isn't one. No aliases, no convenience wrappers, no "which one is the secure version?" Even the weakest model gets it right on the first try.
- **`#[must_use]` with instructions, not just warnings** — the compiler becomes the documentation. When an LLM generates code and forgets to handle a `strict_join()` result, it doesn't get a generic "unused Result" — it gets a message like *"always handle the Result to detect path traversal attacks"*. The LLM reads the compiler output, self-corrects, and gets it right on the next pass. No docs lookup needed.
- **Doc comments explain *why*, not just *what*** — every non-trivial function documents the reasoning behind the code, what attack a check prevents, or what invariant it enforces. An LLM working with just the source file can reason about design intent without any external context.
- **[Context7](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT.md) and [LLM context files](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md)** — machine-readable API references that ship with the crate, sized for different context windows. Critical mistakes front-loaded so an LLM agent hits the important stuff first.

> **Is this overkill for my use case?** If you accept paths from users, config files, archives, databases, or AI agents — no, this is the minimum.
> If all your paths are hardcoded constants — use `std::path`. See [choosing canonicalized vs lexical](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html).

> 📖 **New to strict-path?** Start with the **[Tutorial: Chapter 1 - The Basic Promise →](https://dk26.github.io/strict-path-rs/tutorial/chapter1_basic_promise.html)**

<details>
<summary>🤖 <strong>LLM / AI Agent Integration</strong></summary>

<br>

Our doc comments and [LLM_CONTEXT_FULL.md](https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md) are designed for LLMs with function calling — enabling AI agents to use this crate safely for file operations.

**LLM agent prompt (copy/paste):**
``` 
Fetch and follow this reference (single source of truth):
https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT_FULL.md
```

**Context7 style:**
```
Fetch and follow this reference (single source of truth):
https://github.com/DK26/strict-path-rs/blob/main/LLM_CONTEXT.md
```

</details>

> 📖 **[Security Methodology →](https://dk26.github.io/strict-path-rs/security_methodology.html)** | 📚 **[Built-in I/O Methods →](https://dk26.github.io/strict-path-rs/best_practices/common_operations.html)** | 📚 **[Anti-Patterns →](https://dk26.github.io/strict-path-rs/anti_patterns.html)**

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

> 📖 **[Complete Decision Matrix →](https://dk26.github.io/strict-path-rs/best_practices.html)** | 📚 **[More Examples →](https://dk26.github.io/strict-path-rs/examples/overview.html)**

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

### 🔒 Zero Idle Dependencies

Every runtime dependency exists to close a specific security gap. Each is audited, tested against attack payloads, and covered by `cargo audit` in CI.

| Crate | Platforms | Security role |
|---|---|---|
| [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize) | All | Canonicalization engine — symlink resolution, 8.3 short-name expansion, cycle detection, null-byte rejection. Maintained as part of this project. |
| [`dunce`](https://crates.io/crates/dunce) | Windows | Strips `\\?\` / `\\.\` verbatim prefixes via `std::path::Prefix` pattern matching — no lossy UTF-8 round-trip, refuses to strip when unsafe (reserved names, >260 chars, trailing dots). Zero transitive deps. |
| [`junction`](https://crates.io/crates/junction) | Windows (opt-in `junctions` feature) | NTFS junction creation and inspection for built-in junction helpers. |

On Unix the total runtime tree is **2 crates** (`soft-canonicalize` + `proc-canonicalize`). On Windows it adds `dunce` (zero transitive deps). No idle dependencies — if a crate is in the tree, it has a security job.

<details>
<summary><strong>vs manual <code>soft-canonicalize</code></strong></summary>

- `soft-canonicalize` = low-level path resolution engine (returns `PathBuf`)
- `strict-path` = high-level security API (returns `StrictPath<Marker>` with compile-time guarantees: fit for LLM era)

</details>

---

## 🔌 **Ecosystem Integration**

Compose with standard Rust crates for complete solutions:

| Integration  | Purpose                 | Guide                                                                                       |
| ------------ | ----------------------- | ------------------------------------------------------------------------------------------- |
| **tempfile** | Secure temp directories | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#temporary-directories-tempfile) |
| **dirs**     | OS standard directories | [Guide](https://dk26.github.io/strict-path-rs/os_directories.html)                          |
| **app-path** | Application directories | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#portable-application-paths-app-path) |
| **serde**    | Safe deserialization    | [Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#deserializing-boundaries-with-fromstr) |
| **Axum**     | Web server extractors   | [Tutorial](https://dk26.github.io/strict-path-rs/axum_tutorial/overview.html)               |
| **Archives** | ZIP/TAR extraction      | [Guide](https://dk26.github.io/strict-path-rs/examples/archive_extraction.html)             |

> 📚 **[Complete Integration Guide →](https://dk26.github.io/strict-path-rs/ecosystem_integration.html)**

---

## 📚 **Learn More**

📖 **[API Docs](https://docs.rs/strict-path)** | 📚 **[User Guide](https://dk26.github.io/strict-path-rs/)** | 📚 **[Anti-Patterns](https://dk26.github.io/strict-path-rs/anti_patterns.html)** | 📖 **[Security Methodology](https://dk26.github.io/strict-path-rs/security_methodology.html)** | 🧭 **[Canonicalized vs Lexical](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)** | 🛠️ **[`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs)**

---

## 📄 **License**

MIT OR Apache-2.0
