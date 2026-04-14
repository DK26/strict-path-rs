# Coding Standards

Rust coding rules for the `strict-path` crate. Security-critical crate — correctness over cleverness.

## `#[must_use]` Annotations

Every public method/type with security or correctness significance gets `#[must_use]`.

| Category | Annotation |
|---|---|
| Core validated types (`StrictPath`, `VirtualPath`, `PathBoundary`, `VirtualRoot`) | `#[must_use = "guidance"]` |
| Error enums | `#[must_use = "guidance"]` |
| Validation/join methods (return `Result`) | `#[must_use = "guidance"]` |
| Consuming methods (take `self`) | `#[must_use = "...consumes self..."]` |
| Security-critical accessors (`interop_path`, display helpers) | `#[must_use = "guidance"]` |
| Sugar constructors (return `Result`) | `#[must_use = "guidance"]` |
| Pure query methods (return `bool`, `Option`) | `#[must_use]` (no message) |
| I/O methods returning `io::Result` | **No `#[must_use]`** — `Result` already has it |
| Side-effect methods (`io::Result<()>`) | **No `#[must_use]`** |
| Builder chain methods (return `Self` on `#[must_use]` struct) | **No `#[must_use]`** — avoids `double_must_use` |

Messages must be actionable: tell the caller what to do next, not just "returns a value".

## Safe Indexing — No Direct Indexing in Production Code

Never use direct indexing (`parts[i]`, `data[start..end]`, `line[pos..]`) in
production code. Panics on OOB = denial-of-service vector.

| Banned | Replacement |
|---|---|
| `parts[i]` | `parts.get(i).ok_or(…)?` |
| `data[start..end]` | `data.get(start..end).ok_or(…)?` |
| `slice[i..]` | `slice.get(i..).unwrap_or_default()` |
| `value.as_bytes()[0]` | `value.as_bytes().first()` |

Prior bounds checks do not exempt direct indexing — safety must be self-evident
at the call site. Prefer iterators (`.iter()`, `.enumerate()`, `.windows()`,
`.chunks()`) over index-based loops. Test code may use direct indexing.

## No Unsafe Code

Never use `unsafe` blocks, `unsafe fn`, or `unsafe impl`. If a dependency
requires unsafe, wrap it in a separate crate.

## Type Safety

- Prefer `Option`/`Result` over sentinel values (empty strings, `-1`, null-equivalents).
- Prefer `match` over `if let` for enums — new variants produce compile errors.
- Keep struct fields private when invariants must be enforced.

## Lifetime Naming

Use meaningful names (`'boundary`, `'path`, `'input`), not generic `'a`.
Single-letter lifetimes acceptable only in very small local scopes.

## Module Independence

- One concept per file; independently understandable.
- DAG dependencies only — no circular imports.
- Extract pure logic from side-effectful functions for isolated testing.

## RAG / LLM-Friendly File Size

Keep files under ~600 lines. Split large files into focused submodules.
Stable top-to-bottom layout: module docs → imports → constants → types → impl → functions → tests.

## Heap Allocation Awareness

Avoid unnecessary allocations in hot paths. Use `Vec::with_capacity()`,
`extend_from_slice()`, iterators, and streaming operations where practical.

## Defensive Programming

- Prefer non-panicking APIs; return `Result`. Never `unwrap()`/`expect()` in library code or examples.
- Fail closed: reject input on ambiguity.
- Validate invariants at module boundaries; keep normalization centralized in PathHistory.
- Guard platform specifics with targeted tests.
- Add regression tests for every bugfix.
- Treat Display/string conversions as sensitive — use explicit `*_display()` helpers.

## String Formatting (Rust 1.58+)

Prefer captured identifiers: `format!("{value}")` over bare `format!("{}", value)`.
Bind locals for repeated or long expressions.

## Commenting Style

### Why > What > How

Every non-trivial block must carry comments answering (in order):
1. **Why** — design decision or constraint that motivated this code
2. **What** — plain-language summary
3. **How** (when non-obvious) — algorithm steps, domain mechanics

Rules:
- `///` doc comments on every public item.
- `//!` module-level comment stating why the module exists.
- Don't restate type signatures in English.
- Constants/magic numbers must document origin and meaning.
- Safety-critical paths: inline comment explaining what attack the check prevents.
- Use `// ── Section name ───` headers in long functions.
- Imperative style in summaries ("Join child onto strict path").
- At least one compilable example in doc comments; add failure case if common.

## Doctest and Lint Suppression Policy (Non-Negotiable)

**Forbidden:**
- `no_run`, `ignore`, `should_panic` fence flags (unless demonstrating panic as API semantics)
- `doctest: false` in manifests
- `#[allow(...)]` — sole exception: `#[allow(clippy::type_complexity)]` for verbose type expressions

**Instead:** Make doctests runnable with hidden scaffolding. Use `compile_fail` for
compile-time failures. Assert on error values for runtime failures.
