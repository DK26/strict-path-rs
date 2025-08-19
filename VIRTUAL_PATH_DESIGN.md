# VirtualPath and VirtualRoot: Clear Separation of UX vs FS Concerns

Status: Draft design (breaking changes acceptable pre-1.0)  
Scope: Single-crate, internal refactor + new public types (VirtualRoot, VirtualPath)

## Why this change

The current `JailedPath` mixes two conceptual dimensions:
- Virtual (user-facing) paths: what users should see and manipulate
- Real (filesystem) paths: what the OS uses and what we should restrict

This duality on a single type creates cognitive load and increases the risk of human error: developers must constantly choose the correct variant (`*_virtual` vs `*_real`), and it's easy to misuse or display the wrong thing.

Goal: Make the user-facing API obvious and safe by default, and keep system-facing operations explicit and clearly named—by separating them into different types.

## Core principles

1. **Separation of concerns**
   - `VirtualPath` is for user-facing interactions (display, path manipulation, UX semantics).
   - `JailedPath` is for system-facing interactions (I/O, comparisons on real paths, integration with external APIs).

2. **One obvious way**
   - Virtual operations live on `VirtualPath` with natural names (`join_virtual`, `parent_virtual`, etc.).
   - Real/fact-of-the-filesystem operations live on `JailedPath` with explicit naming (`*_real`, `unjail`).

3. **Strong guarantees preserved**
   - All paths stay within the jail boundary (virtual root).
   - Traversal is clamped; symlinks are resolved; Windows 8.3 short-name hardening remains.

4. **Fewer sharp edges**
   - Eliminate mixed-method sets on the same type where possible.
   - Reduce accidental UI leakage of real filesystem structure.

Note: We will never expose raw `Path` or `&Path` from `JailedPath` publicly. Instead we provide explicit `realpath_` prefixed accessors (e.g. `realpath_to_string()`, `realpath_as_os_str()`) and matching `_real` suffixed methods. Likewise, `VirtualPath` exposes `virtualpath_` aliases for its string accessors. This naming makes conversions explicit and prevents accidental, unchecked joins on a leaked `Path`.

## Type evolution (explicit)

To avoid ambiguity we document the canonical evolution of path types and the exact conversion functions you must use. These conversions are explicit and named — there are no hidden `From`/`Into` conversions.

Paths -> (jailed) -> JailedPath -> (virtualize()) -> VirtualPath

- To go from an unchecked Path-like value into a system-validated path use the `Jail::try_path(...) -> JailedPath` entrypoints (not pictured above).
- From `JailedPath` to the user-facing `VirtualPath` call `JailedPath::virtualize()` (explicit upgrade).
- From `VirtualPath` back to `JailedPath` call `VirtualPath::unvirtual()` (explicit downgrade).
- From `JailedPath` to raw owned `PathBuf` call `JailedPath::unjail()` — this is an explicit escape hatch and loses all safety guarantees.

Important rules to follow:
- No implicit `From`/`Into` conversions between `JailedPath` and `VirtualPath` — conversions are explicit only.
- Never expose `&Path` or `PathBuf` from `JailedPath` public API (we provide `realpath_` string/os accessors instead). This prevents accidental use of `Path::join` that would bypass validation.
- All user-facing virtual string accessors have `*_virtual` suffixes and `virtualpath_` aliases; all system-facing real accessors have `*_real` suffixes and `realpath_` aliases. Example: `to_string_virtual()` / `virtualpath_to_string()` vs `to_string_real()` / `realpath_to_string()`.

Rationale: The explicit evolution and naming remove ambiguity at call sites, make grep/search easy for virtual vs real operations, and ensure reviewers can quickly see when code leaves the safe virtual API surface.

## Types overview

- **Jail\<M\>**
  - Validator and holder of the real jail root (filesystem boundary)
  - Purpose: Establish boundary, construct `JailedPath` (system-facing only)

- **VirtualRoot\<M\>**
  - Dedicated type representing the virtual root (the jail, but for UX semantics)
  - Purpose: Construct `VirtualPath` via intuitive operations (e.g., `join_virtual`, `try_path_virtual`)

- **JailedPath\<M\>** (system-facing)
  - Represents a validated path guaranteed to be within the jail.
  - Intended for file I/O, security checks, and integration with external APIs.
  - Does NOT expose user-facing/virtual manipulation or display.

- **VirtualPath\<M\>** (user-facing)
  - Stores both the underlying `JailedPath<M>` and the virtual path as `PathBuf`.
  - Contains all virtual path logic directly (no delegation to JailedPath virtual methods).
  - Treats the jail as the virtual root `/` for display/manipulation.
   - Ideal for UI/UX, navigation, path edits, and any user-visible output.

### Important clarity: JailedPath is a simple system path; clamping belongs to VirtualPath

- `JailedPath` is a thin, validated, system-facing representation of a filesystem path inside the jail. It behaves like a simple, canonicalized path wrapper intended for I/O and integration with external APIs.
- `JailedPath` itself does NOT perform virtual clamping or virtual-root-relative normalization. It exposes the real filesystem path semantics (reads/writes, real comparisons, and `Display` shows the real path).
- All virtual semantics — stripping the jail prefix, treating the jail as `/`, clamping upward traversal at the virtual root, and any UX-oriented normalization — are performed by `VirtualRoot`/`VirtualPath` during construction or when calling `_virtual` methods.
- In short: use `JailedPath` when you need a plain, system-facing path; use `VirtualPath`/`VirtualRoot` when you need clamping, virtual normalization, or any user-facing path behavior.

## Type relationships

- VirtualPath<M> encapsulates JailedPath<M> (composition) + stores virtual PathBuf
   - Upgrade: call `JailedPath::virtualize()` to obtain a `VirtualPath` (explicit upgrade)
   - Downgrade: `VirtualPath::unvirtual()` or `JailedPath::from(VirtualPath)`

VirtualRoot is a dedicated type (not an alias). It focuses on virtual semantics and hides system-facing APIs.

## Design Decisions and Rationale

### Decision 1: Dedicated VirtualRoot type (not alias)
**Decision**: Create `VirtualRoot<M>` as a separate type, not `type VirtualRoot<M> = Jail<M>`

**Rationale**: 
- A type alias would expose all `Jail` methods, including system-facing ones like `path()` access
- Users should not need to think about the underlying filesystem boundary when working with virtual paths
- Dedicated type allows us to expose only virtual-oriented constructors and methods
- Cleaner separation of concerns: `Jail` = system validator, `VirtualRoot` = user-facing virtual root

### Decision 2: Single constructor per type (no dual try_path methods)
**Decision**: 
- `Jail` has only `try_path() -> JailedPath<M>` (system-facing)
- `VirtualRoot` has only `try_path_virtual() -> VirtualPath<M>` (user-facing)

**Rationale**:
- Eliminates the "which method should I use?" decision fatigue
- Type choice (Jail vs VirtualRoot) now drives the behavior, not method choice
- Reduces API surface and potential confusion
- Each type has a clear, focused purpose

### Decision 3: Keep _virtual suffixes on VirtualPath methods
**Decision**: Use explicit suffixes like `join_virtual()`, `parent_virtual()` on `VirtualPath`

**Rationale**:
- **Mixed-usage clarity**: In codebases that use both virtual and real paths, suffixes prevent confusion
- **Security focus**: For a security crate, explicit is better than implicit - mistakes have real consequences  
- **Type tracking burden**: Without suffixes, developers must mentally track "am I working with VirtualPath or JailedPath now?" during conversions
- **Call-site readability**: `vp.join_virtual("file")` vs `jp.to_string_real()` - immediately clear what's happening
- **Grep-friendly**: Easy to search for all virtual operations
- **Future-proof**: Naming pattern scales if we add more path types

### Decision 4: JailedPath gets Display back (showing real paths)
**Decision**: Restore `Display` implementation on `JailedPath` that shows the real filesystem path

**Rationale**:
- `JailedPath` is system-facing, so showing real paths is appropriate for its use cases
- Provides a convenient way to display paths for logging, debugging, and system integration
- Users of `JailedPath` explicitly chose the system-facing type, so they expect system-facing behavior
- Alternative (`Debug` only) would be overly restrictive for legitimate system-facing use cases

### Decision 5: VirtualPath stores virtual PathBuf directly
**Decision**: `VirtualPath<M>` contains both `JailedPath<M>` and the virtual `PathBuf`

**Rationale**:
- **Direct manipulation**: Virtual `PathBuf` enables direct path operations without computation
- **Performance**: No repeated path stripping calculations
- **Standard library compatibility**: Path methods work directly on the virtual PathBuf
- **Memory efficiency**: PathBuf is more memory-efficient than String for path operations
- **Type safety**: Virtual path operations work on actual Path types, not strings

### Decision 6: Complete method migration from JailedPath to VirtualPath
**Decision**: ALL virtual-related methods move from `JailedPath` to `VirtualPath`

**Methods moving to VirtualPath:**
- `to_string_virtual()` → `VirtualPath::to_string_virtual()`
- `as_os_str_virtual()` → `VirtualPath::as_os_str_virtual()`
- `starts_with_virtual()` → `VirtualPath::starts_with_virtual()`
- `ends_with_virtual()` → `VirtualPath::ends_with_virtual()`
- `file_name()` → `VirtualPath::file_name()` (operates on virtual path)
- `file_stem()` → `VirtualPath::file_stem()` (operates on virtual path)
- `extension()` → `VirtualPath::extension()` (operates on virtual path)
- `join()` → `VirtualPath::join_virtual()` (operates on virtual path)
- `parent()` → `VirtualPath::parent_virtual()` (operates on virtual path)
- `with_file_name()` → `VirtualPath::with_file_name_virtual()` (operates on virtual path)
- `with_extension()` → `VirtualPath::with_extension_virtual()` (operates on virtual path)

**Rationale**:
- **Complete separation**: No virtual logic remains in JailedPath
- **Type clarity**: Virtual operations are impossible to confuse with real operations
- **Direct implementation**: VirtualPath implements virtual logic directly, not through delegation
- **API consistency**: All virtual operations have consistent `_virtual` suffixes

### Decision 7: VirtualPath manipulation methods architecture
**Challenge**: VirtualPath needs jail access for path manipulation validation

**Options considered**:
1. Store jail reference in VirtualPath (circular dependency issues)
2. Make manipulation methods fallible and delegate to underlying JailedPath
3. Move all manipulation to VirtualRoot (creator pattern)
4. Accept that some VirtualPath manipulations might be limited

**Decision**: Hybrid approach - simple manipulations work directly, complex ones may require going through VirtualRoot

### Decision 8: Single crate (not separate crates)
**Decision**: Keep VirtualPath and JailedPath in the same crate

**Rationale**:
- Avoids dependency management complexity
- Shared validation logic and internal types
- Easier to maintain API consistency
- Lower barrier to adoption (one dependency instead of two)
- Conversions between types are seamless

### Decision 9: Preserve all existing security guarantees
**Decision**: Keep all current validation, clamping, and hardening behavior unchanged

**Rationale**:
- Proven security model - don't fix what isn't broken
- Maintains compatibility with existing security assumptions
- Windows 8.3 short-name hardening remains important
- Symlink resolution and boundary checking are core features
- Path traversal clamping is fundamental to the security model

## VirtualPath Internal Structure

```rust
#[derive(Clone, Debug)]
pub struct VirtualPath<Marker = ()> {
    /// The underlying jailed path (system-facing, real filesystem path)
    inner: JailedPath<Marker>,
    /// The virtual path (relative to jail root) stored as PathBuf
    virtual_path: PathBuf,
}
```

### Virtual Path Storage Details

- **Source**: Computed from `JailedPath` by stripping jail root prefix
- **Format**: Standard `PathBuf` relative to jail root
- **Display**: Converted to forward-slash format with jail root as `/`
- **Operations**: Direct PathBuf operations for components, joining, parent access
- **Validation**: New virtual paths validated through existing jail infrastructure

## Construction patterns (ergonomics)

- Construct the virtual root:
  - `VirtualRoot::<M>::try_new("/some/jail/path") -> Result<VirtualRoot<M>>`
  - Optional: `VirtualRoot::<M>::try_new_create(...)` to create directories proactively

- Produce a VirtualPath (user-facing):
  - `vroot.try_path_virtual(p) -> Result<VirtualPath<M>>`  (accepts absolute/relative; clamps as needed)
  - `vroot.join_virtual(p) -> Result<VirtualPath<M>>` (ergonomic helper)

- Produce a JailedPath (system-facing):
  - `Jail::<M>::try_new(jail_path)?.try_path(p) -> Result<JailedPath<M>>`

### VirtualRoot is independent of JailedPath

`VirtualRoot` is a user-facing entrypoint and does not require you to create a `JailedPath` first. Use `VirtualRoot::try_path_virtual()` / `join_virtual()` to obtain `VirtualPath` values directly from user input. Internally these call the same validation and canonicalization machinery used by `Jail`, but the public surface is tailored for virtual UX flows.

Example:

```rust
let vroot = VirtualRoot::<M>::try_new("/app/storage")?;
let vp = vroot.try_path_virtual("users/alice/report.pdf")?; // no JailedPath needed
```

## Method surfaces (final shape)

### JailedPath<M> (system-facing only)
**Keep real/system operations only:**
- Real string: `to_string_real()` 
- Real comparisons: `starts_with_real()`, `ends_with_real()`
- External integration: `unjail()` (PathBuf ownership)
- File I/O helpers: `read_*`, `write_*`, `metadata`, etc.

**Remove all virtual operations:**
- ❌ Remove: `to_string_virtual()`, `as_os_str_virtual()`
- ❌ Remove: `starts_with_virtual()`, `ends_with_virtual()`
- ❌ Remove: `join()`, `parent()`, `with_file_name()`, `with_extension()`
- ❌ Remove: Virtual-focused `file_name()`, `file_stem()`, `extension()`

**Display/Debug behavior:**
- `Display` impl shows real path (system-facing)
- `Debug` shows real path and jail info for diagnostics
- Conversion: `virtualize()` method to create VirtualPath

### VirtualPath<M> (user-facing only)
**Natural virtual operations with explicit suffixes:**
- `join_virtual(&self, p) -> Option<VirtualPath<M>>` (operates on virtual PathBuf)
- `parent_virtual(&self) -> Option<VirtualPath<M>>` (operates on virtual PathBuf)
- `with_file_name_virtual(&self, name) -> Option<VirtualPath<M>>` (operates on virtual PathBuf)
- `with_extension_virtual(&self, ext) -> Option<VirtualPath<M>>` (operates on virtual PathBuf)

**Virtual strings and display:**
- `to_string_virtual() -> String` (forward slashes, jail as `/`)
- `as_os_str_virtual() -> OsString`
- `Display` shows virtual path (forward slashes; jail is `/`)
- `Debug` includes type name and virtual path

**Virtual path components:**
- `file_name() -> Option<OsString>` (from virtual PathBuf)
- `file_stem() -> Option<OsString>` (from virtual PathBuf)
- `extension() -> Option<OsString>` (from virtual PathBuf)

**Virtual path checks:**
- `starts_with_virtual<P: AsRef<Path>>(&self, p) -> bool` (virtual PathBuf comparison)
- `ends_with_virtual<P: AsRef<Path>>(&self, p) -> bool` (virtual PathBuf comparison)

**File system operations (delegated to inner JailedPath):**
- All I/O operations delegate to `inner: JailedPath<M>`

**Escape hatch:**
- `unvirtual(self) -> JailedPath<M>` (when you need system-facing behavior)

## Virtualization/clamping semantics (unchanged core behavior)

- `virtualize_to_jail` strips root components and clamps upward traversal at the virtual root.
- After virtual normalization, paths are joined to the jail and canonicalized.
- Symlinks are resolved; final containment verified against jail boundary.
- Windows hardening: early rejection of non-existent components that look like 8.3 short names.

## Migration guidance (breaking; staged)

1. **Add VirtualPath<M> newtype**:
   - Stores `JailedPath<M>` + virtual `PathBuf`
   - Implements all virtual operations directly
   - No delegation to JailedPath virtual methods

2. **Introduce VirtualRoot<M>**:
   - Holds canonicalized jail root data (same as `Jail<M>`)
   - Exposes only virtual constructors:
     - `try_new` / `try_new_create`
     - `try_path_virtual(&self, p) -> Result<VirtualPath<M>>`
     - `join_virtual(&self, p) -> Result<VirtualPath<M>>`

3. **Update Jail<M>** (system-facing only):
   - Keep: `try_new` / `try_new_create`
   - Keep: `try_path(&self, p) -> Result<JailedPath<M>>`
   - Remove: Any virtual-related methods

4. **Remove virtual operations from JailedPath**:
   - ❌ Deprecate then remove: ALL `*_virtual` methods
   - ❌ Remove: `join()`, `parent()`, `with_file_name()`, `with_extension()`
   - ❌ Remove: virtual-focused `file_name()`, `file_stem()`, `extension()`
   - ✅ Keep: All `*_real` methods, I/O operations, `unjail()`

5. **Update Display implementations**:
   - `JailedPath::Display` shows real path
   - `VirtualPath::Display` shows virtual path with forward slashes

6. **Provide conversion methods**:
   - `JailedPath::virtualize() -> VirtualPath<M>`
   - `VirtualPath::unvirtual() -> JailedPath<M>`

## Example flows (illustrative)

**User-facing (virtual):**
```rust
let vroot = VirtualRoot::<M>::try_new("/app/storage")?;
let vp = vroot.try_path_virtual("users/alice/report.pdf")?;
println!("{}", vp); // "/users/alice/report.pdf"
let parent = vp.parent_virtual()?.unwrap();
let sibling = parent.join_virtual("summary.txt")?;
```

**System-facing (real):**
```rust
let jail = Jail::<M>::try_new("/app/storage")?;
let jp = jail.try_path("users/alice/report.pdf")?;
assert!(jp.starts_with_real(jail.path()));
let bytes = jp.read_bytes()?;
external_api(jp.unjail()); // PathBuf ownership when needed
```

**Mixed usage:**
```rust
let vroot = VirtualRoot::<M>::try_new("/app/storage")?;
let vp = vroot.try_path_virtual("users/alice/report.pdf")?;
println!("User sees: {}", vp); // Virtual path
let jp = vp.unvirtual();
println!("System logs: {}", jp); // Real path
let content = jp.read_bytes()?; // I/O operations
```

## Security and UX outcomes

- **Safer by default**: Any code destined for UI naturally uses `VirtualPath` where display is correct by construction
- **Reduced cognitive load**: No method suffix scanning - type choice drives behavior
- **Fewer leaks**: `JailedPath` no longer has virtual methods that could leak to UI
- **Clear separation**: Virtual logic completely separated from real filesystem logic
- **Performance**: Virtual path stored directly, no repeated computation

## Open questions (to finalize in implementation)

1. **VirtualPath manipulation validation**: How to handle `join_virtual()` etc. that need jail validation?
   - Option A: Store weak reference to jail in VirtualPath
   - Option B: Make manipulation methods fallible and use inner JailedPath validation  
   - Option C: Move complex manipulations to VirtualRoot factory methods

2. **Method naming consistency**: Should VirtualRoot methods have `_virtual` suffixes?
   - Current: `try_path_virtual()`, `join_virtual()` 
   - Alternative: `try_path()`, `join()` (since type implies virtual)

3. **File system operations on VirtualPath**: Direct delegation or selective exposure?
   - Current: Delegate all I/O to inner JailedPath
   - Alternative: Expose only read operations, require conversion for writes

## Closing

This design achieves complete separation of concerns: user-facing logic is clean and intuitive on `VirtualRoot` + `VirtualPath`, while `Jail` + `JailedPath` become precise, system-facing tools. The separation eliminates confusion, clarifies intent at call sites, and preserves the crate's strong security guarantees while dramatically improving ergonomics for virtual path operations.

The explicit suffix approach and complete method migration prioritizes **clarity over brevity**, which is essential for a security-focused crate where the cost of confusion or mistakes is high. All virtual path logic now lives in `VirtualPath` where it belongs, with no delegation or mixed responsibilities.