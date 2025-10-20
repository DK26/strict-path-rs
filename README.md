# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/strict-path-rs#license)
[![CI](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/strict-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/strict-path-rs)

📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Docs](https://docs.rs/strict-path)**
| 🧭 **[Choosing Canonicalized vs Lexical Solution](https://dk26.github.io/strict-path-rs/ergonomics/choosing_canonicalized_vs_lexical_solution.html)**

Strictly enforce path boundaries to prevent directory traversal attacks. This crate provides compile-time guarantees that file paths cannot escape their designated boundaries—no exceptions, no escapes.

> **Note:** Our doc comments and [LLM_API_REFERENCE.md](https://github.com/DK26/strict-path-rs/blob/main/LLM_API_REFERENCE.md) are designed for LLMs with function calling—so an AI can use this crate safely and correctly for file and path operations. 
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

## What this crate does

- **Strictly enforces path boundaries**: Prevents dangerous paths like `../../../etc/passwd` from escaping designated boundaries through compile-time type guarantees
- **Handles the obscure edge cases**: Windows 8.3 short names, symlink cycles, NTFS streams, UNC paths, encoding tricks—the stuff you'd never think to test for
- **Compiler-enforced guarantees**: `StrictPath<Marker>` types mathematically prove at compile-time that paths stay strictly within boundaries
- **Enables authorization architectures**: When you design markers to require authorization for construction, the compiler mathematically proves that any use of those markers went through authorization first
- **Safe builtin I/O operations**: Complete filesystem API (read, write, create_dir, metadata, rename, copy, etc.) that eliminates the need for `.interop_path()` calls in routine operations
- **Two modes to choose from**:
  - **StrictPath** (default): Detects and rejects escape attempts—perfect for security boundaries where escapes are attacks (archive extraction, file uploads, config loading)
  - **VirtualPath** (opt-in): Contains and redirects escape attempts—perfect for sandboxes where escapes are expected but must be controlled (malware analysis, multi-tenant isolation)
- **Built on battle-tested foundations**: Uses `soft-canonicalize` which has been validated against 19+ real-world path-related CVEs
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

### Policy types first (reusable, explicit)

```rust
use strict_path::{PathBoundary, VirtualRoot};

// 1. Define the boundary - paths are contained within ./uploads
let uploads_boundary = PathBoundary::try_new_create("./uploads")?;

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

// Virtual filesystem for multi-tenant isolation (requires "virtual-path" feature)
let tenant_id = "alice";
let tenant_vroot = VirtualRoot::try_new_create(format!("./tenant_data/{tenant_id}"))?;
let tenant_file = tenant_vroot.virtual_join("../../../sensitive")?;
// Escape attempt is silently clamped - stays within tenant_data
println!("Virtual path: {}", tenant_file.virtualpath_display()); // Shows: "/sensitive"
```

### One-liner sugar (quick prototyping)

```rust
use strict_path::{StrictPath, VirtualPath};

// Concise form - boundary created inline
let config_file = StrictPath::with_boundary_create("./config")?
    .strict_join("app.toml")?;
config_file.write(b"settings")?;

// Virtual paths require dynamic tenant/user IDs to serve their purpose
let user_id = get_authenticated_user_id();
let user_avatar = VirtualPath::with_root_create(format!("./user_data/{user_id}"))?
    .virtual_join("/profile/avatar.png")?;
user_avatar.create_parent_dir_all()?;
user_avatar.write(b"image data")?;
// Each user sees "/profile/avatar.png" but they're isolated on disk
```

## Typical Workflow

- Establish a root (policy type): `PathBoundary` for strict detection, or `VirtualRoot` for virtual containment.
- Accept safe types in internal APIs: `&StrictPath<Marker>` / `&VirtualPath<Marker>`.
- Validate any untrusted input (CLI, config, DB, user I/O) via `strict_join`/`virtual_join` before any I/O.

Strict link creation (hard link)
```rust
use strict_path::PathBoundary;

// 1) Establish boundary
let boundary: PathBoundary = PathBoundary::try_new_create("./link_demo")?;

// 2) Validate target path from untrusted input
let target = boundary.strict_join("data/target.txt")?;
target.create_parent_dir_all()?;
target.write(b"hello")?;

// 3) Create a sibling hard link (simple, no extra dirs)
target.strict_hard_link("alias.txt")?; // mirrors std::fs::hard_link

let alias = boundary.strict_join("data/alias.txt")?;
assert_eq!(alias.read_to_string()?, "hello");
```

Virtual link creation (hard link)
```rust
use strict_path::VirtualRoot;

// 1) Establish virtual root (per tenant)
let tenant_id = "tenant42";
let vroot: VirtualRoot = VirtualRoot::try_new_create(format!("./vlink_demo/{tenant_id}"))?;

// 2) Validate target in virtual space (absolute is clamped to root)
let vtarget = vroot.virtual_join("/data/target.txt")?;
vtarget.create_parent_dir_all()?;
vtarget.write(b"hi")?;

// 3) Create a sibling hard link (virtual semantics)
vtarget.virtual_hard_link("alias.txt")?;

let valias = vroot.virtual_join("/data/alias.txt")?;
assert_eq!(valias.read_to_string()?, "hi");
```

> 📖 **New to strict-path?** Start with the **[Tutorial: Stage 1 - The Basic Promise →](https://dk26.github.io/strict-path-rs/tutorial/stage1_basic_promise.html)** to learn the core concepts step-by-step.

> *The Type-State Police have set up PathBoundary checkpoints*  
> *because your LLM is running wild*

## 🚨 **One Line of Code Away from Disaster**

> "One does not simply walk into /etc/passwd."

```rust
use strict_path::StrictPath;

let user_input = "../../../etc/passwd";

// ❌ This single line can destroy your server
// std::fs::write(user_input, data)?;

// ✅ This single line makes it mathematically impossible  
let boundary = StrictPath::with_boundary_create("uploads")?;
let result = boundary.strict_join(user_input);
// Returns Err(PathEscapesBoundary) - attack blocked!
```

## Features

- `virtual-path` (opt-in): Enables `VirtualRoot`/`VirtualPath` and all virtual APIs. By default you get `PathBoundary`/`StrictPath` only (with full I/O).
- `junctions` (Windows-only, opt-in): Enables built-in NTFS directory junction helpers:
    - `StrictPath::strict_junction`, `PathBoundary::strict_junction`
    - `VirtualPath::virtual_junction`, `VirtualRoot::virtual_junction`
    - Junctions are directory-only. Parents aren't created automatically. Same-boundary rules apply.

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

Without `virtual-path`: only `PathBoundary` + `StrictPath` are available (I/O remains available); all virtual-only types and methods are removed.

### Ecosystem Integration

**strict-path** focuses on providing security primitives—not wrappers for ecosystem crates. You can easily compose strict-path with popular crates:

- **[tempfile](https://docs.rs/tempfile)**: Create secure temporary directories
- **[dirs](https://docs.rs/dirs)**: Access OS-standard directories
- **[app-path](https://docs.rs/app-path)**: Manage application data folders
- **Serde deserialization**: Use `FromStr` for path validation

📚 **[Complete Integration Guide →](https://dk26.github.io/strict-path-rs/ecosystem_integration.html)** - Full examples for tempfile, dirs, app-path, and serde patterns

**The Reality**: Every web server, LLM agent, and file processor faces the same vulnerability. One unvalidated path from user input, config files, or AI responses can grant attackers full filesystem access.

**The Solution**: Comprehensive path security with mathematical guarantees — including symlink safety, Windows path quirks, and encoding pitfalls — not just string checks.

> Analogy: `StrictPath` is to paths what a prepared statement is to SQL.
>
> - The boundary/root you create is like preparing a statement: it encodes the policy (what’s allowed).
> - The untrusted filename or path segment is like a bound parameter: it’s validated/clamped safely via `strict_join`/`virtual_join`.
> - The API makes injection attempts inert: hostile inputs can’t escape the boundary, just like SQL parameters can’t change the query.

## 🛡️ **How We Solve The Entire Problem Class**

> "Symlinks: the ninja assassins of your filesystem."

**strict-path isn't just validation—it's a complete solution to path security that handles edge cases you'd never think to check:**

1. **🔧 [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) foundation**: Heavily tested against 19+ globally known path-related CVEs—the battle-tested work you don't want to reimplement
2. **🚫 Advanced pattern detection**: Catches encoding tricks, Windows 8.3 short names (`PROGRA~1`), UNC paths, NTFS Alternate Data Streams, and malformed inputs that simple string checks miss
3. **🔗 Full canonicalization pipeline**: Resolves symlinks, junctions, `.` and `..` components, and handles filesystem race conditions—the complex stuff that's easy to get wrong
4. **📐 Mathematical correctness**: Rust's type system provides compile-time proof of path boundaries
5. **🔐 Authorization architecture**: Enable compile-time authorization guarantees through marker types
6. **👁️ Explicit operations**: Method names like `strict_join()` make security violations visible in code review
7. **🛡️ Safe builtin I/O operations**: Complete filesystem API that reduces the need for `.interop_path()` calls in routine operations
8. **🤖 LLM-aware design**: Built specifically for untrusted AI-generated paths and modern threat models
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
## I/O Equivalence (use these instead of std::fs)

Short, one-to-one mapping so you don’t reach for `std::fs` with `.interop_path()`:

- Directory listing: `std::fs::read_dir` → `StrictPath::read_dir` / `VirtualPath::read_dir`
- Read file: `std::fs::read`/`read_to_string` → `StrictPath::read`/`read_to_string`
- Write file: `std::fs::write` → `StrictPath::write`
- Open/create: `File::open`/`File::create` → `StrictPath::open_file`/`create_file`
- Mkdir: `create_dir`/`create_dir_all` → `StrictPath::create_dir`/`create_dir_all`
- Remove: `remove_file`/`remove_dir`/`remove_dir_all` → `StrictPath::{remove_file, remove_dir, remove_dir_all}`
- Move/copy: `rename`/`copy` → `StrictPath::strict_rename`/`strict_copy`
- Links: `hard_link`/`symlink_*` → `StrictPath::strict_hard_link`/`strict_symlink`
- Windows junctions: manual junction calls → `StrictPath::strict_junction` (feature = "junctions")

Golden rule: use `.interop_path()` only for third‑party `AsRef<Path>` APIs you cannot wrap.


## 🔍 **Comparison with Other Solutions**

### **strict-path vs soft-canonicalize**

> "High-level safety built on low-level precision."

**TL;DR:** `soft-canonicalize` is the foundation; `strict-path` is the complete security solution built on top.

| Aspect          | `soft-canonicalize`            | `strict-path`                                             |
| --------------- | ------------------------------ | --------------------------------------------------------- |
| **Level**       | Low-level path resolution      | High-level security API                                   |
| **Purpose**     | Normalize paths for comparison | Enforce path boundaries                                   |
| **Philosophy**  | Unopinionated DIY foundation   | Opinionated easy-to-use safety                            |
| **Usage**       | Build your own security logic  | Drop-in secure path handling                              |
| **Guarantees**  | Resolves paths correctly       | Prevents directory traversal                              |
| **Type system** | Returns `PathBuf`              | Returns `StrictPath<Marker>` with compile-time guarantees |

**When to use what:**
- **Use `soft-canonicalize`** if you need low-level path resolution as a building block for custom path security logic or specialized use cases
- **Use `strict-path`** for comprehensive path security with minimal code - it handles all the security considerations for you

**The relationship:** `strict-path` is built on `soft-canonicalize`, leveraging its battle-tested path resolution (validated against 19+ CVEs) and adding:
- Boundary enforcement and validation
- Type-safe marker system for domain separation
- Complete filesystem I/O API
- Authorization architecture patterns
- Ergonomic constructors and integrations

### **strict-path vs path_absolutize::absolutize_virtually**

> "Rejection vs containment: different tools for different threats."

Both provide virtual filesystem semantics, but with **fundamentally different security models**:

| Feature                | `path_absolutize::absolutize_virtually` | `strict-path` (`VirtualPath`)      |
| ---------------------- | --------------------------------------- | ---------------------------------- |
| **Philosophy**         | Strict validation                       | Permissive sandboxing              |
| **Escape handling**    | Error/rejection                         | Clamping to boundary               |
| **Symlink resolution** | None (lexical only)                     | Full resolution (filesystem-based) |
| **Security model**     | "Reject invalid"                        | "Contain within boundary"          |
| **Use case**           | Path validation                         | Virtual filesystem                 |
| **When escapes occur** | Returns `Err`                           | Clamps to virtual root             |

**Key insight:** These are **different security models**, not just implementation variations.

**Choose `path_absolutize::absolutize_virtually` when:**
- You want to validate that paths stay within boundaries
- Escape attempts should be treated as errors
- You're using lexical-only path resolution (no symlink following)
- You need strict rejection of invalid paths

**Choose `strict-path` (`VirtualPath`) when:**
- You need to contain all paths within a boundary regardless of escapes
- You want filesystem-based canonicalization (handles symlinks, junctions, etc.)
- You're building multi-tenant systems or sandboxes
- Escape attempts should be silently contained, not rejected

**Choose `strict-path` (`StrictPath`) when:**
- You want the rejection behavior but also need full canonicalization
- You're extracting archives, processing uploads, or loading configs
- You need both detection AND comprehensive CVE protection

**Example difference:**
```rust
// path_absolutize - rejects escapes
absolutize_virtually("../../../etc/passwd", "/sandbox")?; // Returns Err

// strict-path (VirtualPath) - contains escapes
let vroot = VirtualRoot::try_new("/sandbox")?;
vroot.virtual_join("../../../etc/passwd")?; // Returns Ok("/etc/passwd" within sandbox)

// strict-path (StrictPath) - rejects escapes with full canonicalization
let boundary = PathBoundary::try_new("/sandbox")?;
boundary.strict_join("../../../etc/passwd")?; // Returns Err(PathEscapesBoundary)
```

**Bottom line:** Use rejection models when escapes are attacks you want to detect. Use clamping models when you need guaranteed containment regardless of input.

## ⚡ **Get Secure in 30 Seconds**

```toml
[dependencies]
strict-path = "0.1.0-beta.3"
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

> 📖 **[Tutorial: Stage 3 - Markers →](https://dk26.github.io/strict-path-rs/tutorial/stage3_markers.html)** explains marker fundamentals and domain separation patterns.

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

> 📚 **[Learn Authorization Patterns →](https://dk26.github.io/strict-path-rs/tutorial/stage4_authorization.html)**: Step-by-step tutorial on encoding authorization in the type system with `change_marker()`, tuple markers, and capability-based patterns.

##  Where This Makes Sense

> "LLMs: great at generating paths, terrible at keeping secrets."

- Usefulness for LLM agents: LLMs can produce arbitrary paths; `StrictPath`/`VirtualPath` make those suggestions safe by validation (strict) or clamping (virtual) before any I/O.
- `PathBoundary`/`VirtualRoot`: When you want the compiler to enforce that a value is anchored to the initial root/boundary. Keeping the policy type separate from path values prevents helpers from "picking a root" silently.
- Marker types: Add domain context for the compiler and reviewers (e.g., `PublicAssets`, `UserUploads`). They read like documentation and prevent cross‑domain mix‑ups at compile time.

Trade‑offs you can choose explicitly:

- Zero‑trust, CVE‑aware approach: Prefer canonicalized solutions (this crate) to resolve to absolute, normalized system paths with symlink handling and platform quirks addressed. This defends against entire classes of traversal and aliasing attacks.
- Lexical approach (performance‑first, limited scope): If you’re absolutely certain there are no symlinks, junctions, mounts, or platform‑specific aliases and your inputs are already normalized, a lexical solution from another crate may be faster. Use this only when the invariants are guaranteed by your environment and tests.

## 🎯 **Decision Guide: When to Use What**

> Golden Rule: If you didn't create the path yourself, secure it first.

| Source/Input                                                                                              | Choose         | Why                                           | Notes                                            |
| --------------------------------------------------------------------------------------------------------- | -------------- | --------------------------------------------- | ------------------------------------------------ |
| HTTP/CLI args/config/LLM/DB (untrusted segments)                                                          | `StrictPath`   | Detect and reject attacks explicitly          | Validate with `PathBoundary.strict_join(...)`    |
| Archive extraction, file uploads                                                                          | `StrictPath`   | Detect malicious paths; fail on escape        | Use error handling to reject compromised files   |
| Malware analysis sandbox, multi-tenant isolation                                                          | `VirtualPath`  | Contain escapes; observe safely               | Per-user `VirtualRoot`; use `.virtual_join(...)` |
| UI-only path display (multi-user systems)                                                                 | `VirtualPath`  | Show clean rooted paths                       | `virtualpath_display()`; no system leakage       |
| Your own code/hardcoded paths                                                                             | `Path/PathBuf` | You control the value                         | Never for untrusted input                        |
| External APIs/webhooks/inter-service messages                                                             | `StrictPath`   | System-facing interop/I/O requires validation | Validate on consume before touching FS           |
| *(See the [full decision matrix](https://dk26.github.io/strict-path-rs/best_practices.html) in the book)* |                |                                               |                                                  |

**Critical distinction - Detect vs. Contain:**
- **`StrictPath` (default):** Detects escape attempts and returns `Err(PathEscapesBoundary)`. Use when path escapes indicate **malicious intent** (archive extraction, file uploads, config loading). No feature required.
- **`VirtualPath` (opt-in):** Contains escape attempts by clamping to virtual root. Use when path escapes are **expected but must be controlled** (malware sandboxes, multi-tenant isolation). Requires `virtual-path` feature.

**Symlink behavior:**
- **`VirtualPath`:** Implements true virtual filesystem semantics. When a symlink points to `/etc/config`, that absolute path is **clamped** to `vroot/etc/config`. Perfect for multi-tenant systems where each user's `/` is actually their virtual root.
- **`StrictPath`:** Uses system filesystem semantics. Symlinks point to their actual system targets. Best for shared system resources and detecting malicious symlinks.

Notes that matter:
- `VirtualPath` conceptually extends `StrictPath` with a virtual "/" view; both support I/O and interop. Choose based on whether escapes are attacks (detect with StrictPath) or expected (contain with VirtualPath).
- Unified helpers: Prefer dimension-specific signatures. When sharing a helper across both, accept `&StrictPath<_>` and call with `vpath.as_unvirtual()` as needed.

### At‑a‑glance: API Modes

| Feature             | `Path`/`PathBuf`                            | `StrictPath`                        | `VirtualPath`                                      |
| ------------------- | ------------------------------------------- | ----------------------------------- | -------------------------------------------------- |
| **Security**        | None 💥                                      | Validates & rejects ✅               | Clamps any input ✅                                 |
| **Join safety**     | Unsafe (can escape)                         | Boundary-checked                    | Boundary-clamped                                   |
| **Symlink targets** | System paths (can escape)                   | System paths (validated)            | **Clamped to virtual root** ✅                      |
| **Example attack**  | `"../../../etc/passwd"` → **System breach** | `"../../../etc/passwd"` → **Error** | `"../../../etc/passwd"` → **`/etc/passwd`** (safe) |
| **Symlink attack**  | `link -> /etc/passwd` → **System breach**   | `link -> /etc/passwd` → **Error**   | `link -> /etc/passwd` → **`/etc/passwd`** (safe)   |
| **Best for**        | Known-safe paths                            | System boundaries                   | User interfaces, multi-tenant storage              |

📚 **Further Reading in the Complete Guide:**
- **[Tutorial Series](https://dk26.github.io/strict-path-rs/tutorial/overview.html)** - 6-stage progressive guide from basics to advanced patterns
- **[Best Practices](https://dk26.github.io/strict-path-rs/best_practices.html)** - Full decision matrix and design rationale
- **[Anti-Patterns](https://dk26.github.io/strict-path-rs/anti_patterns.html)** - What not to do, with fixes
- **[Real-World Examples](https://dk26.github.io/strict-path-rs/examples/overview.html)** - End-to-end realistic scenarios
- **[Type-System Guarantees](https://dk26.github.io/strict-path-rs/type_system_guarantees.html)** - How markers prevent bugs at compile-time

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

> 📚 **[Visual Guide: Examples by Mode →](https://dk26.github.io/strict-path-rs/examples_by_mode.html)**  
> *Quick visual reference showing when to use StrictPath vs VirtualPath vs Path/PathBuf with side-by-side code examples*
>
> 📖 **[Complete Decision Matrix →](https://dk26.github.io/strict-path-rs/best_practices.html#security-philosophy-detect-vs-contain)**  
> *Detailed decision matrix with 15+ scenarios, security philosophy, and real-world guidance*

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

**What this protects against (99% of attacks)—including edge cases most developers miss:**
- **Basic path traversal**: `../../../etc/passwd`
- **Symlink escapes**: Following links outside boundaries, including directory bombs and cycle detection
- **Archive extraction attacks**: Zip slip and similar archive-based traversal attempts
- **Encoding bypass attempts**: Unicode normalization attacks, null bytes, and other encoding tricks
- **Windows platform-specific attacks**:
  - 8.3 short name aliasing (`PROGRA~1` → `Program Files`)
  - UNC path manipulation (`\\?\C:\` and `\\server\share\`)
  - NTFS Alternate Data Streams (`file.txt:hidden`)
  - Drive-relative path forms and junction points
- **Race conditions**: TOCTOU (Time-of-Check-Time-of-Use) during path resolution
- **Canonicalization edge cases**: Mixed separators, redundant separators, current/parent directory references

**The reality**: These aren't theoretical attacks—they're real vulnerabilities found in production systems. Instead of researching each CVE and implementing custom defenses, you get comprehensive protection from day one.

**What requires system-level privileges (rare):**
- **Hard links**: Multiple filesystem entries to same file data
- **Mount points**: Admin/root can redirect paths via filesystem mounts

**Bottom line**: If attackers have root/admin access, they've already won. This library stops the 99% of practical attacks that don't require special privileges—and handles all the edge cases you'd probably forget to check.


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
let user_id = "alice";
let user_uploads_root: VirtualRoot<UserFiles> = VirtualRoot::try_new(format!("uploads/{user_id}"))?;

let css_file: VirtualPath<WebAssets> = public_assets_root.virtual_join("app.css")?;
let report_file: VirtualPath<UserFiles> = user_uploads_root.virtual_join("report.pdf")?;

// Type system prevents context mixing
serve_asset(css_file.as_unvirtual());         // ✅ Correct context
// serve_asset(report_file.as_unvirtual());   // ❌ Compile error!
```

**Your IDE and compiler become security guards.**

**App Configuration with `app-path`:**
```rust
// ❌ Vulnerable - app dirs + user paths
use app_path::AppPath;
let app_dir = AppPath::with("config");
let config_file = app_dir.join(user_config_name); // 🚨 Potential escape
fs::write(config_file, settings)?;

// ✅ Protected - bounded app directories
use strict_path::PathBoundary;
use app_path::AppPath;
let app_config_dir = PathBoundary::try_new_create(AppPath::with("config"))?;
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
let user_id = "alice";
let user_uploads_vroot = VirtualPath::with_root(format!("./uploads/{user_id}"))?; // per-user uploads root
let profile_avatar_file = user_uploads_vroot.virtual_join("profile/avatar.png")?; // file by domain role
println!("Virtual: {}", profile_avatar_file.virtualpath_display());
println!("System: {}", profile_avatar_file.as_unvirtual().strictpath_display());
```

**Why this matters:**
- `interop_path()` is designed solely for unavoidable third-party API interop (`AsRef<Path>`)
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

📘 **[Complete Archive Extraction Guide →](https://dk26.github.io/strict-path-rs/examples/archive_extraction.html)** - Full patterns for ZIP/TAR handling, security rationale, and anti-patterns

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

- **🗂️ OS Directories**: Compose with `dirs` crate for platform-specific paths - **[Full Guide](https://dk26.github.io/strict-path-rs/os_directories.html)**
- **📄 Serde**: Use `FromStr` for safe deserialization - **[Integration Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#serde-and-fromstr)**
- **🧪 Temporary Files**: Compose with `tempfile` crate for secure temp directories - **[tempfile Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#tempfile)**
- **📦 App Paths**: Compose with `app-path` crate for application directories - **[app-path Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html#app-path)**
- **🌐 Axum**: Custom extractors for web servers - **[Complete Tutorial](https://dk26.github.io/strict-path-rs/axum_tutorial/overview.html)**
- **📦 Archive Handling**: Safe ZIP/TAR extraction - **[Extractor Guide](https://dk26.github.io/strict-path-rs/examples/archive_extraction.html)**

## 📄 **License**

MIT OR Apache-2.0
