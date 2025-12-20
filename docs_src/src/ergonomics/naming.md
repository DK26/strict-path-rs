# Naming

Prefer domain-based names; avoid type-based names.

- Good: `config_dir`, `uploads_root`, `archive_src`, `user_vroot`, `system_root`.
- Avoid: `boundary`, `jail`, `source_` prefixes, or one-letter variables.
- Keep names consistent with the directory they represent and convey intent in code review.

---

## Quick Reference Table

| Context             | ✅ Good Names                                                    | ❌ Avoid                             |
| ------------------- | --------------------------------------------------------------- | ----------------------------------- |
| **Untrusted input** | `requested_file`, `user_input`, `uploaded_data`, `attack_input` | `filename`, `path`, `name`, `file`  |
| **Boundaries**      | `uploads_root`, `config_dir`, `archive_src`, `static_assets`    | `boundary`, `jail`, `root`, `b`     |
| **Virtual roots**   | `user_vroot`, `tenant_sandbox`, `project_root`                  | `vroot`, `vr`, `sandbox`            |
| **Markers**         | `UserUploads`, `MediaLibrary`, `BrandAssets`                    | `UserUploadsMarker`, `Root`, `Type` |
| **Paths**           | `avatar_file`, `config_path`, `entry_path`                      | `p`, `f`, `temp`, `x`               |

### Why This Matters

Variable names are documentation. When reviewing security-critical code, names should immediately communicate:

1. **What is being validated** — `requested_file` screams "this came from outside"
2. **What boundary protects it** — `uploads_root` explains the restriction
3. **What marker type encodes** — `UserUploads` tells you what's stored

**Anti-pattern example:**
```rust
// ❌ What is `filename`? Where did it come from? Is it safe?
let path = boundary.strict_join(filename)?;
```

**Improved:**
```rust
// ✅ Obvious: user-provided input being validated against upload boundary
let avatar_path = user_uploads_root.strict_join(requested_avatar_filename)?;
```

---

### Marker Types

- Name markers after the storage domain (`struct PublicAssets;`, `struct BrandEditorWorkspace;`). Reviewers should understand the filesystem contents from the type alone.
- Skip suffixes like `Marker`, `Type`, or `Root`; they repeat what Rust already communicates. `struct MediaLibrary;` is clearer than `struct MediaLibraryMarker;`.
- Tuples that pair storage with authorization should keep the resource first and the capability second: `StrictPath<(BrandDirectorArchive, FullControlCapability)>`.
- Focus on what's stored, not who uses it. A marker like `BrandAssets` tells you the directory contains brand materials, while `EditorFiles` only tells you someone called "Editor" uses it. The marker describes the filesystem contents and access policy, not the caller's identity.
