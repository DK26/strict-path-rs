//! # strict-path
//!
//! Prevent directory traversal with type-safe path restriction and safe symlinks.
//!
//! 📚 **[Complete Guide & Examples](https://dk26.github.io/strict-path-rs/)** | 📖 **[API Reference](https://docs.rs/strict-path)**
//!
//! ## Core Security Foundation: `StrictPath`
//!
//! **`StrictPath` is the fundamental security primitive** that provides our core guarantee: every
//! `StrictPath` is mathematically proven to be within its designated boundary. This is not just
//! validation - it's a type-level security contract that makes path traversal attacks impossible.
//!
//! Everything else in this crate builds upon `StrictPath`:
//! - `PathBoundary` creates and validates `StrictPath` instances from external input
//! - `VirtualPath` extends `StrictPath` with user-friendly virtual root semantics
//! - `VirtualRoot` provides a root context for creating `VirtualPath` instances
//!
//! **The security model:** If you have a `StrictPath<Marker>` in your code, it cannot reference
//! anything outside its boundary - this is enforced by the type system and cryptographic-grade
//! path canonicalization.
//!
//! ## Path Types and Their Relationships
//!
//! - **`StrictPath`**: The core security primitive - a validated, system-facing path that proves
//!   the wrapped filesystem path is within the predefined boundary. If a `StrictPath` exists,
//!   it is mathematical proof that the path is safe.
//! - **`VirtualPath`**: Extends `StrictPath` with a virtual-root view (treating the PathBoundary
//!   as "/"), adding user-friendly operations while preserving all `StrictPath` security guarantees.
//!
//! ## Design Philosophy: PathBoundary as Foundation
//!
//! The `PathBoundary` represents the secure foundation or starting point from which all path operations begin.
//! Think of it as establishing a safe boundary (like `/home/users/alice`) and then performing validated
//! operations from that foundation. When you call `path_boundary.strict_join("documents/file.txt")`,
//! you're building outward from the secure boundary with validated path construction.
//!
//! ## When to Use Which Type
//!
//! **Use `VirtualRoot`/`VirtualPath` for isolation and sandboxing:**
//! - User uploads, per-user data directories, tenant-specific storage
//! - Web applications serving user files, document management systems
//! - Plugin systems, template engines, user-generated content
//! - Any case where users should see a clean "/" root and not the real filesystem structure
//!
//! **Use `PathBoundary`/`StrictPath` for shared system spaces:**
//! - Application configuration, shared caches, system logs
//! - Temporary directories, build outputs, asset processing
//! - Cases where you need the real system path for interoperability or debugging
//! - When working with existing APIs that expect system paths
//!
//! Both types support I/O. The key difference is the user experience: `VirtualPath` provides isolation
//! and clean virtual paths, while `StrictPath` maintains system path semantics for shared resources.
//!
//! ## 🔑 Critical Design Decision: StrictPath vs Path/PathBuf
//!
//! **The Key Principle: Use `StrictPath` when you DON'T control the path source**
//!
//! ```rust
//! # use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // ✅ USE StrictPath - External/untrusted input (you don't control the source)
//! // Encode guarantees in the signature: pass the boundary and the untrusted segment
//! fn handle_user_config(boundary: &PathBoundary, config_name: &str) -> Result<(), Box<dyn std::error::Error>> {
//!     let config_path: StrictPath = boundary.strict_join(config_name)?;  // Validate!
//!     let _content = config_path.read_to_string()?;
//!     Ok(())
//! }
//!
//! // ✅ USE VirtualRoot - External/untrusted input for user-facing paths
//! // Encode guarantees in the signature: pass the virtual root and the untrusted segment
//! fn process_upload(uploads: &VirtualRoot, user_filename: &str) -> Result<(), Box<dyn std::error::Error>> {
//!     let safe_file: VirtualPath = uploads.virtual_join(user_filename)?;  // Sandbox!
//!     safe_file.write_bytes(b"data")?;
//!     Ok(())
//! }
//!
//! // ✅ USE Path/PathBuf - Internal/controlled paths (you generate the path)
//! fn create_backup() -> std::path::PathBuf {
//!     use std::path::PathBuf;
//!     let timestamp = "20240101_120000"; // Simulated timestamp
//!     PathBuf::from(format!("backups/backup_{}.sql", timestamp))  // You control this
//! }
//!
//! fn get_log_file() -> &'static std::path::Path {
//!     std::path::Path::new("/var/log/myapp/app.log")  // Hardcoded, you control this
//! }
//! # Ok(()) }
//! ```
//!
//! **Decision Matrix:**
//! - **External Input** (config files, CLI args, API requests, user uploads) → `StrictPath`/`VirtualPath`
//! - **Internal Generation** (timestamps, IDs, hardcoded paths, system APIs) → `Path`/`PathBuf`
//! - **Unknown Origin** → `StrictPath`/`VirtualPath` (err on the side of security)
//! - **Performance Critical + Trusted** → `Path`/`PathBuf` (avoid validation overhead)
//!
//! This principle ensures security where it matters while avoiding unnecessary overhead for paths you generate and control.
//!
//! ### Example: Isolation vs Shared System Space
//!
//! ```rust
//! use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // ISOLATION: User upload directory - users see clean "/" paths
//! fs::create_dir_all("uploads/user_42")?;
//! let user_space: VirtualRoot = VirtualRoot::try_new("uploads/user_42")?;
//! let user_file: VirtualPath = user_space.virtual_join("documents/report.pdf")?;
//!
//! // User sees: "/documents/report.pdf" (clean, isolated)
//! println!("User sees: {}", user_file.virtualpath_display());
//! user_file.create_parent_dir_all()?;
//! user_file.write_bytes(b"user content")?;
//!
//! // SHARED SYSTEM: Application cache - you see real system paths
//! fs::create_dir_all("app_cache")?;
//! let cache_boundary: PathBoundary = PathBoundary::try_new("app_cache")?;
//! let cache_file: StrictPath = cache_boundary.strict_join("build/output.json")?;
//!
//! // Developer sees: "app_cache/build/output.json" (real system path)  
//! println!("System path: {}", cache_file.strictpath_display());
//! cache_file.create_parent_dir_all()?;
//! cache_file.write_bytes(b"cache data")?;
//!
//! # fs::remove_dir_all("uploads").ok(); fs::remove_dir_all("app_cache").ok();
//! # Ok(()) }
//! ```
//!
//! ## Filter vs Sandbox: Conceptual Difference
//!
//! **`StrictPath` acts like a security filter** - it validates that a specific path is safe and
//! within boundaries, but operates on actual filesystem paths. Perfect for **shared system spaces**
//! where you need safety while maintaining system-level path semantics (logs, configs, caches).
//!
//! **`VirtualPath` acts like a complete sandbox** - it encapsulates the filtering (via the underlying
//! `StrictPath`) while presenting a virtualized, user-friendly view where the PathBoundary root appears as "/".
//! Users can specify any path they want, and it gets automatically clamped to stay safe. Perfect for
//! **isolation scenarios** where you want to hide the underlying filesystem structure from users
//! (uploads, per-user directories, tenant storage).
//!
//! ## Unified Signatures (Explicit Borrow)
//!
//! Prefer marker-specific signatures that accept `&StrictPath<Marker>` and borrow strict view with `as_unvirtual()`.
//! This keeps conversions explicit and avoids vague conversions.
//!
//!
//! ```rust
//! use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};
//!
//! // Write ONE function that works with both types
//! fn process_file(path: &StrictPath) -> std::io::Result<String> {
//!     path.read_to_string()
//! }
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let restriction = PathBoundary::try_new_create("./data")?;
//! let jpath = restriction.strict_join("config.toml")?;
//! let vroot = VirtualRoot::try_new("./data")?;
//! let vpath = vroot.virtual_join("config.toml")?;
//!
//! let _ = process_file(&jpath)?;               // StrictPath
//! process_file(vpath.as_unvirtual())?; // VirtualPath -> borrow strict view explicitly
//! # Ok(()) }
//! ```
//!
//! This keeps conversions explicit by dimension and aligns with the crate's security model.
//! automatically, giving you the best of both worlds: type safety and API simplicity.
//!
//! The core security guarantee is that all paths are mathematically proven to stay within their
//! designated boundaries, neutralizing traversal attacks like `../../../etc/passwd`.
//!
//! ## About This Crate: StrictPath and VirtualPath
//!
//! `StrictPath` is a system-facing filesystem path type, mathematically proven (via
//! canonicalization, boundary checks, and type-state) to remain inside a configured PathBoundary directory.
//! `VirtualPath` wraps a `StrictPath` and therefore guarantees everything a `StrictPath` guarantees -
//! plus a rooted, forward-slashed virtual view (treating the PathBoundary as "/") and safe virtual
//! operations (joins/parents/file-name/ext) that preserve clamping and hide the real system path.
//! With `VirtualPath`, users are free to specify any path they like while you still guarantee it
//! cannot leak outside the underlying restriction.
//!
//! Construct them with `PathBoundary::try_new(_create)` and `VirtualRoot::try_new(_create)`. Ingest
//! untrusted paths as `VirtualPath` for UI/UX and safe joins; perform I/O from either type.
//!
//! ## Security Foundation
//!
//! Built on [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize), this crate inherits
//! protection against documented CVEs including:
//! - **CVE-2025-8088** (NTFS ADS path traversal), **CVE-2022-21658** (TOCTOU attacks)
//! - **CVE-2019-9855, CVE-2020-12279** and others (Windows 8.3 short name vulnerabilities)  
//! - Path traversal, symlink attacks, Unicode normalization bypasses, and race conditions
//!
//! This isn't simple string comparison-paths are fully canonicalized and boundary-checked
//! against known attack patterns from real-world vulnerabilities.
//!
//! Guidance
//! - Accept untrusted input via `VirtualRoot::virtual_join(..)` to obtain a `VirtualPath`.
//! - Perform I/O directly on `VirtualPath` or on `StrictPath`. Unvirtualize only when you need a
//!   `StrictPath` explicitly (e.g., for a signature that requires it or for system-facing logs).
//! - For `AsRef<Path>` interop, pass `interop_path()` from either type (no allocation).
//!
//! Switching views (upgrade/downgrade)
//! - Prefer staying in one dimension for a given flow:
//!   - Virtual view: `VirtualPath` + `virtualpath_*` ops and direct I/O.
//!   - System view: `StrictPath` + `StrictPath_*` ops and direct I/O.
//! - Edge cases: upgrade with `StrictPath::virtualize()` or downgrade with `VirtualPath::unvirtual()`
//!   to access the other view's operations explicitly.
//!
//! Markers and type inference
//! - All public types are generic over a `Marker` with a default of `()`.
//! - Inference usually works once a value is bound:
//!   - `let vroot: VirtualRoot = VirtualRoot::try_new("root")?;`
//!   - `let vp = vroot.virtual_join("a.txt")?; // inferred as VirtualPath<()>`
//! - When inference needs help, annotate the type or use an empty turbofish:
//!   - `let vroot: VirtualRoot<()> = VirtualRoot::try_new("root")?;`
//!   - `let vroot: VirtualRoot = VirtualRoot::try_new("root")?;`
//! - With custom markers, annotate as needed:
//!   - `struct UserFiles; let vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;`
//!   - `let uploads = VirtualRoot::try_new::<UserFiles>("uploads")?;`

//! ### Examples: Encode Guarantees in Signatures
//!
//! ```rust
//! # use strict_path::{VirtualRoot, VirtualPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Cloud storage per-user PathBoundary
//! let user_id = 42u32;
//! let root = format!("./cloud_user_{user_id}");
//! let vroot: VirtualRoot = VirtualRoot::try_new_create(&root)?;
//!
//! // Accept untrusted input, then pass VirtualPath by reference to functions
//! let requested = "projects/2025/report.pdf";
//! let vp: VirtualPath = vroot.virtual_join(requested)?;  // Stays inside ./cloud_user_42
//! // Ensure parent directory exists before writing
//! vp.create_parent_dir_all()?;
//!
//! fn save_doc(p: &VirtualPath) -> std::io::Result<()> { p.write_bytes(b"user file content") }
//! save_doc(&vp)?; // Compiler enforces correct usage via the type
//! println!("virtual: {}", vp.virtualpath_display());
//!
//! # // Cleanup
//! # std::fs::remove_dir_all(&root).ok();
//! # Ok(()) }
//! ```
//!
//! ```rust
//! # use strict_path::{VirtualRoot, VirtualPath};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Web/E-mail templates resolved in a user-scoped virtual root
//! # let user_id = 7u32;
//! let tpl_root = format!("./tpl_space_{user_id}");
//! let templates: VirtualRoot = VirtualRoot::try_new_create(&tpl_root)?;
//! let tpl: VirtualPath = templates.virtual_join("emails/welcome.html")?;
//! fn render(p: &VirtualPath) -> std::io::Result<String> { p.read_to_string() }
//! let _ = render(&tpl);
//!
//! # std::fs::remove_dir_all(&tpl_root).ok();
//! # Ok(()) }
//! ```
//!
//! ## Quickstart: User-Facing Virtual Paths (with signatures)
//!
//! ```rust
//! use strict_path::{VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a virtual root, which corresponds to a real directory.
//! fs::create_dir_all("user_data")?;
//! let vroot: VirtualRoot = VirtualRoot::try_new("user_data")?;
//!
//! // 2. Create a virtual path from user input. Traversal attacks are neutralized.
//! let virtual_path: VirtualPath = vroot.virtual_join("documents/report.pdf")?;
//! let attack_path: VirtualPath = vroot.virtual_join("../../../etc/hosts")?;
//!
//! // 3. Displaying the path is always safe and shows the virtual view.
//! assert_eq!(virtual_path.virtualpath_display().to_string(), "/documents/report.pdf");
//! assert_eq!(attack_path.virtualpath_display().to_string(), "/etc/hosts"); // Clamped, not escaped
//!
//! // 4. Prefer signatures requiring `VirtualPath` for operations.
//! fn ensure_dir(p: &VirtualPath) -> std::io::Result<()> { p.create_dir_all() }
//! ensure_dir(&virtual_path)?;
//! assert!(virtual_path.exists());
//!
//! fs::remove_dir_all("user_data")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! - Two Views: `VirtualPath` extends `StrictPath` with a virtual-root UX; both support I/O.
//! - Mathematical Guarantees: Rust's type system proves security at compile time.
//! - Zero Attack Surface: No `Deref` to `Path`, validation cannot be bypassed.
//! - Built-in Safe I/O: `StrictPath` provides safe file operations.
//! - Multi-PathBoundary Safety: Marker types prevent cross-PathBoundary contamination at compile time.
//! - Type-History Design: Internal pattern ensures paths carry proof of validation stages.
//! - Cross-Platform: Works on Windows, macOS, and Linux.
//!
//! Display/Debug semantics
//! - `Display` for `VirtualPath` shows a rooted virtual path (e.g., "/a/b.txt") for user-facing output.
//! - `Debug` for `VirtualPath` is developer-facing and verbose (derived): it includes the inner
//!   `StrictPath` (system path and PathBoundary root) and the virtual view for diagnostics.
//!
//! ### Example: Display vs Debug
//! ```rust
//! # use strict_path::{VirtualRoot, VirtualPath};
//! # use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # fs::create_dir_all("vp_demo")?;
//! let vroot: VirtualRoot = VirtualRoot::try_new("vp_demo")?;
//! let vp: VirtualPath = vroot.virtual_join("users/alice/report.txt")?;
//!
//! // Display is user-facing, rooted, forward-slashed
//! assert_eq!(vp.virtualpath_display().to_string(), "/users/alice/report.txt");
//!
//! // Debug is developer-facing and verbose
//! let dbg = format!("{:?}", vp);
//! assert!(dbg.contains("VirtualPath"));
//! assert!(dbg.contains("system_path"));
//! assert!(dbg.contains("virtual"));
//!
//! # fs::remove_dir_all("vp_demo").ok();
//! # Ok(()) }
//! ```
//!
//! ## When to Use Which Type
//!
//! | Use Case                               | Type                       | Example                                                     |
//! | -------------------------------------- | -------------------------- | ----------------------------------------------------------- |
//! | Displaying a path in a UI or log       | `VirtualPath`              | `println!("File: {}", virtual_path.virtualpath_display());` |
//! | Manipulating a path based on user view | `VirtualPath`              | `virtual_path.virtualpath_parent()`                         |
//! | Reading or writing a file              | `VirtualPath` or `StrictPath` | `virtual_path.read_bytes()?` or `strict_path.read_bytes()?` |
//! | Integrating with an external API       | Either (borrow `&OsStr`)   | `external_api(virtual_path.interop_path())`         |
//!
//! ## Multi-PathBoundary Type Safety
//!
//! Use marker types to prevent paths from different restrictions from being used interchangeably.
//!
//! ```rust
//! use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! struct StaticAssets;
//! struct UserUploads;
//!
//! fn serve_asset(asset: &StrictPath<StaticAssets>) -> Result<Vec<u8>, std::io::Error> {
//!     asset.read_bytes()
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # fs::create_dir_all("assets")?; fs::create_dir_all("uploads")?;
//! # fs::write("assets/style.css", "body{}")?;
//! let assets_vroot: VirtualRoot<StaticAssets> = VirtualRoot::try_new("assets")?;
//! let uploads_vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new("uploads")?;
//!
//! let css_file: VirtualPath<StaticAssets> = assets_vroot.virtual_join("style.css")?;
//! let user_file: VirtualPath<UserUploads> = uploads_vroot.virtual_join("avatar.jpg")?;
//!
//! serve_asset(css_file.as_unvirtual())?; // ✅ Correct type
//! // serve_asset(user_file.as_unvirtual())?; // ❌ Compile error: wrong marker type!
//! # fs::remove_dir_all("assets").ok(); fs::remove_dir_all("uploads").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Guarantees
//!
//! All `..` components are clamped, symbolic links are resolved, and the final real path is
//! validated against the PathBoundary boundary. Path traversal attacks are prevented by construction.
//!
//! ## Security Limitations
//!
//! This library operates at the **path level**, not the operating system level. While it provides
//! strong protection against path traversal attacks using symlinks and standard directory
//! navigation, it **cannot protect against** certain privileged operations:
//!
//! - **Hard Links**: If a file is hard-linked outside the restricted path, accessing it through the
//!   PathBoundary will still reach the original file data. Hard links create multiple filesystem entries
//!   pointing to the same inode.
//! - **Mount Points**: If a filesystem mount is introduced (by a system administrator or attacker
//!   with sufficient privileges) that redirects a path within the PathBoundary to an external location,
//!   this library cannot detect or prevent access through that mount.
//!
//! **Important**: These attack vectors require **high system privileges** (typically
//! root/administrator access) to execute. If an attacker has such privileges on your system, they
//! can bypass most application-level security measures anyway. This library effectively protects
//! against the much more common and practical symlink-based traversal attacks that don't require
//! special privileges.
//!
//! Our symlink resolution via [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize)
//! handles the most accessible attack vectors that malicious users can create without elevated
//! system access.
//!
//! ### Windows-only hardening: DOS 8.3 short names
//!
//! On Windows, paths like `PROGRA~1` are DOS 8.3 short-name aliases. To prevent ambiguity,
//! this crate rejects paths containing non-existent components that look like 8.3 short names
//! with a dedicated error, `StrictPathError::WindowsShortName`.
//!
//! ## Why We Don't Expose `Path`/`PathBuf`
//!
//! Exposing raw `Path` or `PathBuf` encourages use of std path methods (`join`, `parent`, ...)
//! that bypass this crate's virtual-root clamping and boundary checks.
//!
//! - `join` danger: `std::path::Path::join` has no notion of a virtual root. Joining an
//!   absolute path, or a path with enough `..` components, can override or conceptually
//!   escape the intended root. That undermines the guarantees of `StrictPath`/`VirtualPath`.
//!   **Critical:** `std::path::Path::join("/absolute")` completely replaces the base path,
//!   making it the #1 cause of path traversal vulnerabilities. Our `strict_join` validates
//!   the result stays within PathBoundary bounds, while `virtual_join` clamps absolute paths
//!   to the virtual root.
//!   Use `StrictPath::strict_join(...)` or `VirtualPath::virtual_join(...)` instead.
//! - `parent` ambiguity: `Path::parent` ignores PathBoundary/virtual semantics; our
//!   `strictpath_parent()` and `virtualpath_parent()` preserve the correct behavior.
//! - Predictability: Users unfamiliar with the crate may accidentally mix virtual and
//!   system semantics if they are handed a raw `Path`.
//!
//! What to use instead:
//! - Passing to external APIs: Prefer `strict_path.interop_path()` which borrows the
//!   inner system-facing path as `&OsStr` (implements `AsRef<Path>`). This is the cheapest and most
//!   correct way to interoperate without exposing risky methods.
//! - Ownership escape hatches: Use `.unvirtual()` (to get a `StrictPath`) and `.unstrict()`
//!   (to get an owned `PathBuf`) explicitly and sparingly. These are deliberate, opt-in
//!   operations to make potential risk obvious in code review.
//!
//! Explicit method names (rationale)
//! - Operation names encode their dimension so intent is obvious:
//!   - `p.join(..)` (std) - unsafe on untrusted input; can escape the restriction.
//!   - `jp.strict_join(..)` - safe, validated system-path join.
//!   - `vp.virtual_join(..)` - safe, clamped virtual-path join.
//! - This naming applies broadly: `*_parent`, `*_with_file_name`, `*_with_extension`,
//!   `*_starts_with`, `*_ends_with`, etc.
//! - This makes API abuse easy to spot even when type declarations aren't visible.
//!
//! Why `&OsStr` works well:
//! - `OsStr`/`OsString` are OS-native string types; you don't lose platform-specific data.
//! - `Path` is just a thin wrapper over `OsStr`. Borrowing `&OsStr` is the straightest,
//!   allocation-free, and semantically correct way to pass a path to `AsRef<Path>` APIs.
//!
//! ## Common Pitfalls (and How to Avoid Them)
//!
//! - **NEVER wrap our secure types in `Path::new()` or `PathBuf::from()`**.
//!   This is a critical anti-pattern that bypasses all security guarantees.
//!   ```rust,no_run
//!   # use strict_path::*;
//!   # let restriction = PathBoundary::<()>::try_new(".").unwrap();
//!   # let safe_path = restriction.strict_join("file.txt").unwrap();
//!   // ❌ DANGEROUS: Wrapping secure types defeats the purpose
//!   let dangerous = std::path::Path::new(safe_path.interop_path());
//!   let also_bad = std::path::PathBuf::from(safe_path.interop_path());
//!   
//!   // ✅ CORRECT: Use interop_path() directly for external APIs
//!   # fn some_external_api<P: AsRef<std::path::Path>>(_path: P) {}
//!   some_external_api(safe_path.interop_path()); // AsRef<Path> satisfied
//!   
//!   // ✅ CORRECT: Use our secure operations
//!   let child = safe_path.strict_join("subfile.txt")?;
//!   # Ok::<(), Box<dyn std::error::Error>>(())
//!   ```
//! - **NEVER use `.interop_path().to_string_lossy()` for display purposes**.
//!   This mixes interop concerns with display concerns. Use proper display methods:
//!   ```rust,no_run
//!   # use strict_path::*;
//!   # let restriction = PathBoundary::<()>::try_new(".").unwrap();
//!   # let safe_path = restriction.strict_join("file.txt").unwrap();
//!   // ❌ ANTI-PATTERN: Wrong method for display
//!   println!("{}", safe_path.interop_path().to_string_lossy());
//!   
//!   // ✅ CORRECT: Use proper display methods
//!   println!("{}", safe_path.strictpath_display());
//!   # Ok::<(), Box<dyn std::error::Error>>(())
//!   ```
//!   
//!   ### Tell‑offs and fixes
//!   - Validating only constants → validate real external segments (HTTP/DB/manifest/archive entries); use `boundary.interop_path()` for root discovery.
//!   - Constructing boundaries/roots inside helpers → accept `&PathBoundary`/`&VirtualRoot` and the untrusted segment, or a `&StrictPath`/`&VirtualPath`.
//!   - Wrapping secure types (`Path::new(sp.interop_path())`) → pass `interop_path()` directly.
//!   - `interop_path().as_ref()` or `as_unvirtual().interop_path()` → `interop_path()` is enough; both `VirtualRoot`/`VirtualPath` expose it.
//!   - Using std path ops on leaked values → use `strict_join`/`virtual_join`, `strictpath_parent`/`virtualpath_parent`.
//!   - Raw `&str` parameters for safe helpers → take `&StrictPath<_>`/`&VirtualPath<_>` or (boundary/root + segment).
//! - Do not leak raw `Path`/`PathBuf` from `StrictPath` or `VirtualPath`.
//!   Use `interop_path()` when an external API needs `AsRef<Path>`.
//! - Do not call `Path::join`/`Path::parent` on leaked paths — they ignore PathBoundary/virtual semantics.
//!   Use `strict_join`/`strictpath_parent` and `virtual_join`/`virtualpath_parent`.
//! - Avoid `.unvirtual()`/`.unstrict()` unless you explicitly need ownership for the specific type.
//!   Prefer borrowing with `interop_path()` for interop.
//! - Virtual strings are rooted. For UI/logging, use `vp.virtualpath_display()` or `vp.virtualpath_display().to_string()`.
//!   No borrowed `&str` accessors are exposed for virtual paths.
//! - Creating a restriction: `PathBoundary::try_new(..)` requires the directory to exist.
//!   Use `PathBoundary::try_new_create(..)` if it may be missing.
//! - Windows: 8.3 short names (e.g., `PROGRA~1`) are rejected to avoid ambiguous resolution.
//! - Markers matter. Functions should take `StrictPath<MyMarker>` for their domain to prevent cross-PathBoundary mixing.
//!
//! ## Escape Hatches and Best Practices
//!
//! Prefer passing references to the inner system path instead of taking ownership:
//! - If an external API accepts `AsRef<Path>`, pass `strict_path.interop_path()`.
//! - Avoid `.unstrict()` unless you explicitly need an owned `PathBuf`.
//!
//! ```rust
//! # use strict_path::PathBoundary;
//! # fn external_api<P: AsRef<std::path::Path>>(_p: P) {}
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let restriction = PathBoundary::try_new_create("./safe")?;
//! let jp = restriction.strict_join("file.txt")?;
//!
//! // Preferred: borrow as &OsStr (implements AsRef<Path>)
//! external_api(jp.interop_path());
//!
//! // Escape hatches (use sparingly):
//! let owned: std::path::PathBuf = jp.clone().unstrict();
//! let v: strict_path::VirtualPath = jp.clone().virtualize();
//! let back: strict_path::StrictPath = v.clone().unvirtual();
//! let owned_again: std::path::PathBuf = v.unvirtual().unstrict();
//! # // Cleanup created PathBoundary directory for doctest hygiene
//! # std::fs::remove_dir_all("./safe").ok();
//! # Ok(()) }
//! ```
//!
//! ## API Reference (Concise)
//!
//! For a minimal, copy-pastable guide to the API (optimized for both humans and LLMs),
//! see the repository reference:
//! <https://github.com/DK26/strict-path-rs/blob/main/API_REFERENCE.md>
//!
//! This link is provided here so readers coming from docs.rs can easily discover it.
#![forbid(unsafe_code)]

pub mod error;
pub mod path;
pub mod validator;
#[cfg(feature = "serde")]
pub mod serde_ext {
    //! Serde helpers and notes.
    //!
    //! Built‑in `Serialize` (feature `serde`):
    //! - `StrictPath` → system path string
    //! - `VirtualPath` → virtual root string (e.g., "/a/b.txt")
    //!
    //! Deserialization requires context (a `PathBoundary` or `VirtualRoot`). Use the context helpers
    //! below to deserialize with context, or deserialize to `String` and validate explicitly.
    //!
    //! Example: Deserialize a single `StrictPath` with context
    //! ```rust
    //! use strict_path::{PathBoundary, StrictPath};
    //! use strict_path::serde_ext::WithBoundary;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let boundary: PathBoundary = PathBoundary::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let jp: StrictPath = WithBoundary(&boundary).deserialize(&mut de)?;
    //! // OS-agnostic assertion: file name should be "b.txt"
    //! assert_eq!(jp.strictpath_file_name().unwrap().to_string_lossy(), "b.txt");
    //! # Ok(()) }
    //! ```
    //!
    //! Example: Deserialize a single `VirtualPath` with context
    //! ```rust
    //! use strict_path::{VirtualPath, VirtualRoot};
    //! use strict_path::serde_ext::WithVirtualRoot;
    //! use serde::de::DeserializeSeed;
    //! # fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! # let td = tempfile::tempdir()?;
    //! let vroot: VirtualRoot = VirtualRoot::try_new(td.path())?;
    //! let mut de = serde_json::Deserializer::from_str("\"a/b.txt\"");
    //! let vp: VirtualPath = WithVirtualRoot(&vroot).deserialize(&mut de)?;
    //! assert_eq!(vp.virtualpath_display().to_string(), "/a/b.txt");
    //! # Ok(()) }
    //! ```

    use crate::{
        path::strict_path::StrictPath, path::virtual_path::VirtualPath,
        validator::virtual_root::VirtualRoot, PathBoundary,
    };
    use serde::de::DeserializeSeed;
    use serde::Deserialize;

    /// Deserialize a `StrictPath` with PathBoundary context.
    pub struct WithBoundary<'a, Marker>(pub &'a PathBoundary<Marker>);

    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithBoundary<'a, Marker> {
        type Value = StrictPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.strict_join(s).map_err(serde::de::Error::custom)
        }
    }

    /// Deserialize a `VirtualPath` with virtual root context.
    pub struct WithVirtualRoot<'a, Marker>(pub &'a VirtualRoot<Marker>);

    impl<'a, 'de, Marker> DeserializeSeed<'de> for WithVirtualRoot<'a, Marker> {
        type Value = VirtualPath<Marker>;
        fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            self.0.virtual_join(s).map_err(serde::de::Error::custom)
        }
    }
}

// Public exports
pub use error::StrictPathError;
pub use path::{strict_path::StrictPath, virtual_path::VirtualPath};
pub use validator::path_boundary::PathBoundary;
pub use validator::virtual_root::VirtualRoot;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, StrictPathError>;

#[cfg(test)]
mod tests;
