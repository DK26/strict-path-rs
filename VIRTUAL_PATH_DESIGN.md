# VirtualPath and VirtualRoot: Clear Separation of UX vs FS Concerns

Status: Draft design (breaking changes acceptable pre-1.0)
Sco2. Introduce `VirtualRoot<M>` (holds the same canonicalized jail root data## Design Decisions and Rationale

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

**Example of problematic suffix-free code**:
```rust
let vp = vroot.join("file.txt")?;        // VirtualPath
let parent = vp.parent()?.unwrap();      // Still VirtualPath
let jp = parent.into_jailed();           // Now JailedPath - type changed!
let real_path = jp.to_string_real();     // Have to remember jp is JailedPath
let vp2 = jp.into_virtual();             // Back to VirtualPath
let display = vp2.to_string();           // What method is this? Display trait?
```

**With suffixes (chosen approach)**:
```rust
let vp = vroot.join_virtual("file.txt")?;       // Clear: virtual operation
let parent = vp.parent_virtual()?.unwrap();     // Clear: still virtual
let jp = parent.into_jailed();                  // Clear: converting to real
let real_path = jp.to_string_real();            // Clear: real operation
let vp2 = jp.into_virtual();                    // Clear: back to virtual
let display = vp2.to_string_virtual();          // Clear: virtual operation
```

### Decision 4: JailedPath gets Display back (showing real paths)
**Decision**: Restore `Display` implementation on `JailedPath` that shows the real filesystem path

**Rationale**:
- `JailedPath` is system-facing, so showing real paths is appropriate for its use cases
- Provides a convenient way to display paths for logging, debugging, and system integration
- Users of `JailedPath` explicitly chose the system-facing type, so they expect system-facing behavior
- Alternative (`Debug` only) would be overly restrictive for legitimate system-facing use cases

### Decision 5: VirtualPath wraps JailedPath (composition over inheritance)
**Decision**: `VirtualPath<M>` contains `JailedPath<M>` as a private field

**Rationale**:
- Encapsulation: prevents accidental access to real-path methods
- Type safety: impossible to use VirtualPath where JailedPath is expected (and vice versa)
- Clear ownership: VirtualPath controls which operations are exposed
- Performance: zero-cost wrapper (just changes the API surface)
- Conversion control: explicit `into_jailed()` method makes real-path access intentional

### Decision 6: Single crate (not separate crates)
**Decision**: Keep VirtualPath and JailedPath in the same crate

**Rationale**:
- Avoids dependency management complexity
- Shared validation logic and internal types
- Easier to maintain API consistency
- Lower barrier to adoption (one dependency instead of two)
- Conversions between types are seamless

### Decision 7: Preserve all existing security guarantees
**Decision**: Keep all current validation, clamping, and hardening behavior unchanged

**Rationale**:
- Proven security model - don't fix what isn't broken
- Maintains compatibility with existing security assumptions
- Windows 8.3 short-name hardening remains important
- Symlink resolution and boundary checking are core features
- Path traversal clamping is fundamental to the security model

## Closing

This design restores simplicity: user-facing logic is clean and intuitive on `VirtualRoot` + `VirtualPath`, while `Jail` + `JailedPath` become precise, system-facing tools. The separation reduces mistakes, clarifies intent at call sites, and preserves the crate's strong security guarantees without sacrificing ergonomics.

The explicit suffix approach prioritizes **clarity over brevity**, which is essential for a security-focused crate where the cost of confusion or mistakes is high. `Jail<M>` but exposes only virtual constructors):
   - `try_new` / `try_new_create`
   - `try_path_virtual(&self, p) -> Result<VirtualPath<M>>` (clamps absolute/relative as needed)Single-crate, internal refactor + new public types (VirtualRoot, VirtualPath)

## Why this change

The current `JailedPath` mixes two conceptual dimensions:
- Virtual (user-facing) paths: what users should see and manipulate
- Real (filesystem) paths: what the OS uses and what we should restrict

This duality on a single type creates cognitive load and increases the risk of human error: developers must constantly choose the correct variant (`*_virtual` vs `*_real`), and it’s easy to misuse or display the wrong thing.

Goal: Make the user-facing API obvious and safe by default, and keep system-facing operations explicit and clearly named—by separating them into different types.

## Core principles

1. Separation of concerns
   - `VirtualPath` is for user-facing interactions (display, path manipulation, UX semantics).
   - `JailedPath` is for system-facing interactions (I/O, comparisons on real paths, integration with external APIs).

2. One obvious way
   - Virtual operations live on `VirtualPath` with natural names (`join`, `parent`, etc.).
   - Real/fact-of-the-filesystem operations live on `JailedPath` with explicit naming (`*_real`, `unjail`).

3. Strong guarantees preserved
   - All paths stay within the jail boundary (virtual root).
   - Traversal is clamped; symlinks are resolved; Windows 8.3 short-name hardening remains.

4. Fewer sharp edges
   - Eliminate mixed-method sets on the same type where possible.
   - Reduce accidental UI leakage of real filesystem structure.

## Types overview

- Jail<M>
  - Validator and holder of the real jail root (filesystem boundary)
  - Purpose: Establish boundary, construct `JailedPath` (system-facing only)

- VirtualRoot<M>
  - Dedicated type representing the virtual root (the jail, but for UX semantics)
  - Purpose: Construct `VirtualPath` via intuitive operations (e.g., `join`, `resolve`)

- JailedPath<M> (system-facing)
  - Represents a validated path guaranteed to be within the jail.
  - Intended for file I/O, security checks, and integration with external APIs.
  - Does not expose user-facing/virtual manipulation or display.

- VirtualPath<M> (user-facing)
  - Thin wrapper around `JailedPath<M>` that exposes only virtual operations.
  - Treats the jail as the virtual root `/` for display/manipulation.
  - Ideal for UI/UX, navigation, path edits, and any user-visible output.

## Type relationships

- VirtualPath<M> encapsulates JailedPath<M> (composition)
  - Upgrade: `VirtualPath::from_jailed(JailedPath)` or `VirtualPath::from(JailedPath)`
  - Downgrade: `VirtualPath::into_jailed()` or `JailedPath::from(VirtualPath)`

VirtualRoot is a dedicated type (not an alias). It focuses on virtual semantics and hides system-facing APIs.

## Construction patterns (ergonomics)

- Construct the virtual root:
  - `VirtualRoot::<M>::try_new("/some/jail/path") -> Result<VirtualRoot<M>>`
  - Optional: `VirtualRoot::<M>::try_new_create(...)` to create directories proactively
  - Note: Using `From` cannot convey errors; prefer `TryFrom` or `try_new`.

- Produce a VirtualPath (user-facing):
  - `vroot.try_path_virtual(p) -> Result<VirtualPath<M>>`  (accepts absolute/relative; clamps as needed)
  - Optionally: `VirtualPath::new(&vroot, p) -> Result<VirtualPath<M>>` if a constructor is preferred

- Produce a JailedPath (system-facing):
  - `Jail::<M>::try_new(jail_path)?.try_path(p) -> Result<JailedPath<M>>`

Notes:
`join_virtual` on `VirtualRoot` is sugar for a virtualized validation flow (clamp -> validate -> wrap `VirtualPath`).
`Jail` exposes only `try_path` (system-facing). `VirtualRoot` exposes only virtual constructors returning `VirtualPath`.

## Method surfaces (final shape)

### JailedPath<M> (system-facing)
- Keep real/system operations only:
  - Real string: `to_string_real()` 
  - Real comparisons: `starts_with_real()`, `ends_with_real()`
  - External integration: `unjail()` (PathBuf ownership)
  - File I/O helpers: `read_*`, `write_*`, `metadata`, etc.
- Remove/deprecate user-facing/virtual manipulation:
  - Remove: `join_virtual`, `parent_virtual`, `with_file_name_virtual`, `with_extension_virtual`, `to_string_virtual`.
- Display/Debug behavior (proposed):
  - change `Display` impl show actual path. Keep `Debug` for diagnostics.
  - Turn to a VirtualPath, where the inner Jail represents the Virtual Root path `into_virtual()`


### VirtualPath<M> (user-facing)
- Natural, explicitly suffixed virtual operations:
  - `join_virtual(&self, p) -> Result<VirtualPath<M>>` (clamped)
  - `parent_virtual(&self) -> Result<Option<VirtualPath<M>>>`
  - `with_file_name_virtual(&self, name) -> Result<VirtualPath<M>>`
  - `with_extension_virtual(&self, ext) -> Result<VirtualPath<M>>`
- Strings and display:
  - `to_string_virtual() -> String`
  - `Display` shows virtual path (forward slashes; jail is `/`)
  - `Debug` includes type name and the inner `JailedPath` for diagnostics
- Escape hatch:
  - `into_jailed(self) -> JailedPath<M>` (when you need system-facing behavior)
  - Cannot return PathBuf. This would require to downgrade into Jailed

## Virtualization/clamping semantics (unchanged core behavior)

- `virtualize_to_jail` strips root components and clamps upward traversal at the virtual root.
- After virtual normalization, paths are joined to the jail and canonicalized.
- Symlinks are resolved; final containment verified against jail boundary.
- Windows hardening: early rejection of non-existent components that look like 8.3 short names.

## Naming conventions

- User-facing: `_virtual` suffixes on `VirtualPath` methods for explicit clarity in mixed-usage scenarios.
- System-facing: explicit suffixes like `_real` for clarity on `JailedPath`.
- Display conventions:
  - `VirtualPath`: `Display` = virtual path (never leak real FS structure)
  - `JailedPath`: `Display` shows real path (explicit system-facing), `Debug` shows diagnostic info

### VirtualRoot ergonomics

Patterns:
- `let vroot = VirtualRoot::<M>::try_new("/some/jail/path")?;`
- `let vp = vroot.join_virtual("hello/world")?;  // VirtualPath<M>`

Note: While `VirtualRoot::from("/some/jail/path")` reads nicely, `From` cannot fail. Prefer `try_new`/`TryFrom` to convey errors. If a `from_unchecked` is ever introduced, it must be clearly documented as internal/testing-only.

## Migration guidance (breaking; staged)

1. Add `VirtualPath<M>` newtype wrapping `JailedPath<M>` with virtual operations and display.
2. Introduce `VirtualRoot<M>` (holds the same canonicalized jail root data as `Jail<M>` but exposes only virtual constructors):
  - `try_new` / `try_new_create`
  - `join(&self, p) -> Result<VirtualPath<M>>`
  - `try_path(&self, p) -> Result<VirtualPath<M>>` (clamps absolute/relative as needed)
3. Keep `Jail<M>` focused on system-facing validation:
  - `try_new` / `try_new_create`
  - `try_path(&self, p) -> Result<JailedPath<M>>`
  - Remove `try_virtual_path` from `Jail`
4. Deprecate virtual operations on `JailedPath` with guidance to use `VirtualPath`:
   - `#[deprecated(note = "Use VirtualPath::<M>::... instead")]`
5. Consider removing `Display` from `JailedPath` to avoid UX leakage. If removal is deferred, document that `Display` will be removed in the next breaking release.
6. Update examples, tests, and docs to use `VirtualPath`/`VirtualRoot` for any user-facing work; use `Jail` strictly for system-facing validation.

Compatibility window suggestion:
- Keep deprecated `*_virtual` methods for 1–2 minor pre-1.0 releases to ease migration.
- Offer mechanical migration tips (search/replace):
  - `jailed.join_virtual(x)` -> `jailed.into_virtual().join_virtual(x)` or `vroot.join_virtual(x)`
  - `format!("{}", jailed)` -> `format!("{}", jailed.into_virtual())`

## Example flows (illustrative)

User-facing (virtual):
- `let vroot = VirtualRoot::<M>::try_new("/app/storage")?;`
- `let vp = vroot.join_virtual("users/alice/report.pdf")?;`
- `println!("{}", vp); // "/users/alice/report.pdf"`
- `let parent = vp.parent_virtual()?;`

System-facing (real):
- `let jail = Jail::<M>::try_new("/app/storage")?;`
- `let jp = jail.try_path("users/alice/report.pdf")?;`
- `assert!(jp.starts_with_real(vroot.path()));`
- `let bytes = jp.read_bytes()?;`
- `external_api(jp.into_jailed()); // ownership when needed`

Note: The above use-cases exist today with `JailedPath`; the change is moving the virtual ergonomics to `VirtualPath` so there’s no ambiguity.

## Security and UX outcomes

- Safer by default: any code destined for UI naturally uses `VirtualPath` where display is correct by construction.
- Reduced cognitive load: no `_virtual` suffix scanning on `JailedPath`.
- Fewer leaks: `JailedPath` no longer encourages or enables accidental user-facing display.

## Open questions (to finalize in PR)

1. `JailedPath::Display` removal vs behavior change to real-path display? Recommendation: remove `Display` and keep `Debug` only.
2. Keep `Jail::try_virtual_path` name or shorten to `try_path_virtual` for consistency with docs? (currently exists as `try_virtual_path`)
3. Introduce `VirtualRoot::try_from<P: AsRef<Path>>` or stick with `try_new`/`try_new_create`?
4. Provide a convenience `to_virtual(&self) -> VirtualPath<M>` on `JailedPath`?
5. Any additional built-in I/O on `VirtualPath` (delegation to inner) or keep `VirtualPath` strictly about UX? Current proposal: strictly UX; IO via `JailedPath`.

## Implementation sketch (incremental)

- New type `VirtualPath<M>` in `src/virtual_path.rs`:
  - Fields: `inner: JailedPath<M>`
  - Methods: `join_virtual`, `parent_virtual`, `with_file_name_virtual`, `with_extension_virtual`, `to_string_virtual`, `into_jailed`
  - Traits: `Display` (virtual), `Debug`
  - Conversions: `From<JailedPath<M>>`, `From<VirtualPath<M>> for JailedPath<M>`

- `Jail<M>`:
  - Change `try_virtual_path` -> return `VirtualPath<M>`
  - Add `join<P: AsRef<Path>>(...) -> Result<VirtualPath<M>>` delegating to virtualization+validation
  - Alias: `pub type VirtualRoot<M = ()> = Jail<M>`

- `JailedPath<M>`:
  - Mark virtual-manipulation methods as deprecated; later remove
  - Consider removing `Display`

- Docs/tests:
  - Update README/lib.rs examples to feature `VirtualPath` for user-facing behavior
  - Keep security examples with `JailedPath` for real operations

## Closing

This design restores simplicity: user-facing logic is clean and intuitive on `VirtualRoot` + `VirtualPath`, while `Jail` + `JailedPath` become precise, system-facing tools. The separation reduces mistakes, clarifies intent at call sites, and preserves the crate’s strong security guarantees without sacrificing ergonomics.
