# Design Decisions & Anti-Patterns

Settled design decisions for the `strict-path` crate. These are non-negotiable.

## Symlink Resolution (Critical — Read First)

Canonicalization **always resolves symlinks** to their targets. You can
NEVER get a `StrictPath` or `VirtualPath` pointing to a symlink itself.
This is by design: it proves the path is truly within the boundary.

**Before proposing ANY filesystem API, ask:**
1. Does it need to operate on a symlink itself? → Cannot work with `StrictPath`/`VirtualPath`
2. Does it assume the path might be a symlink? → It won't be — already resolved
3. Does it wrap `std::fs` that behaves differently on symlinks vs files? → Verify with resolved paths only

## No Leaky Trait Impls (Forbidden)

Never implement for any crate type:
- `AsRef<Path>`, `Deref<Target = Path>`, implicit `From`/`Into` conversions

Rationale: They bypass `interop_path()`, let callers silently escape the
secure API, and blur strict vs virtual dimension semantics.

## `interop_path()` Returns `&OsStr` (Settled — Do Not Revisit)

All four core types return `&std::ffi::OsStr` from `.interop_path()`.

- `OsStr` lacks `.join()`, `.parent()`, `.starts_with()` — prevents accidental
  re-entry into path manipulation after leaving the secure API.
- `&OsStr` implements `AsRef<Path>` — pass directly to third-party APIs.
- To get `&Path`, callers must write `Path::new(x.interop_path())` — a visible,
  deliberate step signaling departure from strict-path's security scope.
- A newtype wrapper was tried (`InteropPath<'a>`) and deliberately removed —
  zero additional security value over `&OsStr`.

## One Way Principle (Non-Negotiable)

Exactly **one correct way** per operation. No redundant convenience methods.

| Goal | The ONE way | Notes |
|---|---|---|
| Path as string | `strictpath_display().to_string()` | Returns `std::path::Display<'_>` |
| Path for `AsRef<Path>` APIs | `.interop_path()` | Returns `&OsStr` |
| Virtual user-visible string | `virtualpath_display()` | Rooted forward-slash view |
| Escape to owned `PathBuf` | `.unstrict()` / `.unvirtual()` | Explicit escape hatch |

Do not add `to_string_lossy()`, `to_str()`, `as_path()`, or similar alternatives.

## Helper API Restrictions

- Never introduce new `pub` helpers or constructors without explicit maintainer direction.
- Before adding any `fn` / `pub(crate) fn`, request maintainer approval.

## Marker Transformation with `change_marker()`

Use `change_marker::<NewMarker>()` only **after authorization checks** to transform
the compile-time marker. Conversions between path types preserve markers automatically.

```rust
// ✅ After authorization check
fn grant_write(path: StrictPath<(Docs, ReadOnly)>, user: &User)
    -> Result<StrictPath<(Docs, ReadWrite)>> {
    if user.has_write_permission() { Ok(path.change_marker()) }
    else { Err(AccessDenied) }
}

// ❌ Pointless — conversion already preserves marker
let boundary = strict_path.change_marker::<NewMarker>().try_into_boundary()?;
```

## IO Return Value Policy

Built-in IO helpers return the same value as their `std::fs` counterparts
(`rename`/`symlink` → `io::Result<()>`, `copy` → `io::Result<u64>`, etc.).
Preserves exact OS signal; no extra filesystem probes.

## Hard Link Helpers

`PathBoundary::strict_hard_link` and `VirtualRoot::virtual_hard_link` forward
to `StrictPath` helpers. Many platforms forbid directory hard links
(`io::ErrorKind::PermissionDenied`) — treat as acceptable outcome.

## Mandatory API Addition Checklist

Before adding ANY new public or internal API:

**Design Compatibility:**
- [ ] Understood PathHistory type-state flow? (Raw → Canonicalized → BoundaryChecked)
- [ ] Works correctly with symlinks ALWAYS resolved?
- [ ] Works correctly with ALWAYS canonicalized paths (no `.`, `..`)?
- [ ] Makes sense for BOTH `StrictPath` and `VirtualPath`?

**Semantic Verification:**
- [ ] Tested underlying `std::fs` function with resolved paths?
- [ ] Tested on BOTH Windows and Linux?
- [ ] Preserves boundary security guarantee?

**Approval:**
- [ ] Searched codebase — functionality doesn't already exist?
- [ ] Requested explicit maintainer approval?

**If ANY checkbox fails, STOP and discuss.**
