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

## Error Variants Are Not Terminal-State Sentinels

Error variants must not double as terminal-state sentinels. `Option::None`
signals "no more data", "at the root", or "absent". `Err(...)` signals that
the operation failed.

If an error variant is being used to indicate end-of-iteration or
legitimately reaching the boundary, the API is conflating unrelated concerns.
Split the return type or add a distinct state-carrying variant.

Example: `StrictPath::strictpath_parent()` returns `Ok(None)` at the boundary
root. It must not return `Err(PathEscapesBoundary)`, because no escape attempt
occurred.

## Ingestion Boundaries Are Typed

`PathBoundary<Marker>` and `VirtualRoot<Marker>` are trust anchors:
application-owned, constructed at startup, parameterized by a marker that
names the domain. Once a downstream function takes
`&PathBoundary<Marker>` or `&VirtualRoot<Marker>`, the type itself proves
the value came through a vetted constructor and belongs to the claimed
domain. The security story depends on that property being reachable at
every place a string enters the program.

The anti-pattern to avoid is **raw `PathBuf` in runtime `Cli`/`Config`
fields**, with construction deferred to a later explicit call. Between
the field definition and that late call, nothing stops a reader (or a
refactor) from passing the raw `PathBuf` around without validation. The type-system
proof is erased at the exact point this crate should be strongest.

### `FromStr` Forwards to `try_new_create`

`FromStr` for `PathBoundary` / `VirtualRoot` creates the target directory
if missing, then canonicalizes and validates. The choice of `try_new_create`
over `try_new` follows from the realistic use case: who parses a string
into a `PathBoundary` or `VirtualRoot` and specifically does *not* want the
directory created if it is missing? That scenario is essentially
nonexistent. When a caller hands a string to a boundary constructor, they
are bootstrapping their anchor — the natural expectation is that the anchor
will exist afterwards. If a caller genuinely needs "must already exist"
semantics, they reach for `try_new` by name in hand-written code.

Forcing `try_new` as the `FromStr` default would also break framework use:
when clap or serde invokes `from_str`, there is no mechanism to pass a
policy choice — the framework just calls `parse()`. A `try_new`-based
`FromStr` would require callers to pre-create every output or cache
directory before running the program, or fall back to raw `PathBuf` and
lose the type-system guarantee entirely.

Trade-off acknowledged: `FromStr` implementations conventionally avoid
filesystem mutation. That convention is about reader clarity, not a hard
rule (`try_new` itself already performs I/O via canonicalization and
`is_dir` probes). The convention is waived here because the ergonomic
alternative degrades the type-system guarantee. The style rule below
preserves reader clarity without crippling the default.

### Style Rule: Named Constructors in Hand-Written Code

- In **hand-written code**, prefer the named constructors `try_new` /
  `try_new_create` so the construction policy is visible at the call
  site. `let root = VirtualRoot::try_new_create(s)?;` is clearer than
  `let root: VirtualRoot = s.parse()?;`.
- Reserve `FromStr` for **framework-invoked** construction (clap
  `#[arg]`, serde `#[serde(deserialize_with = "…")]` adapter functions).
  In those contexts the typed field declaration is what makes the
  ingestion boundary visible, and forcing named constructors would
  require wrapping every field in boilerplate.
- Runtime `Cli` / `Config` fields are always typed
  `PathBoundary<Marker>` / `VirtualRoot<Marker>`, never raw `PathBuf`.
  When a specific field's policy differs from the bootstrap default
  (e.g. a deployment artifact that must already exist), express it
  explicitly at the ingestion point via `value_parser` (clap) or a
  dedicated `deserialize_with` adapter (serde) that calls `try_new` by
  name.

### `Deserialize` Is Not Implemented Directly

Boundary and root types do not implement `Deserialize`. Wiring them to
serde is the user's integration choice (via `serde`'s own mechanisms —
`deserialize_with`, third-party crates like `serde_with`, or user-defined
wrappers). We do not ship or prescribe a specific serde adapter — doing so
would teach serde, not this crate, and would lock downstream projects into
our convention. What this crate commits to is the `FromStr` contract and
the typed-field principle; how callers turn that into serde plumbing is
outside scope.

New public surface (a blanket `Deserialize` impl, a `serde_ext::*` module
of named helpers) is gated behind the "no new public APIs without
maintainer approval" rule and requires concrete evidence that
user-written integration is insufficient.
