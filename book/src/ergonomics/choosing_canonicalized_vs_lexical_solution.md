# Choosing Canonicalized vs Lexical Solution

Scope: strict-path always uses canonicalized path security. There is no “lexical mode” in this crate. When we say “lexical,” we mean using a different crate that only does string/segment checks. This page helps you decide when to use strict-path (canonicalized) versus when a lexical-only crate might be acceptable.

New here? This page helps you pick the right approach without security footguns.

In one sentence: Prefer the “canonicalized” approach unless you 100% control the environment and have tests proving your assumptions. Lexical (in other crates) is for rare, performance‑critical hot paths with strong guarantees.

## First: What do these words mean?

- Canonicalized (what strict-path does): We ask the OS to resolve the real, absolute path before deciding if it’s safe. This resolves symlinks/junctions and normalizes platform‑specific quirks (like Windows 8.3 short names, UNC, ADS). That way, sneaky inputs can’t trick simple string checks.
- Lexical (other crates): We treat the path like plain text and only do string/segment checks (no OS resolution). It can be fast, but it doesn’t see what’s really on disk.

## Why you probably want canonicalized (i.e., strict-path)

- Defends against real‑world attacks: directory traversal (../../../), symlink swaps, aliasing (8.3 short names like `PROGRA~1`), UNC/verbatim forms, ADS, Unicode normalization tricks.
- Works across platforms the same way.
- Matches “zero‑trust” handling for inputs from HTTP, config files, databases, archives, and LLMs.

Trade‑off: a bit more I/O work to ask the filesystem what’s actually there.

## When lexical (other crates) can be OK

Only consider lexical if ALL of these are true:
- No symlinks/junctions/mounts in the relevant tree
- Inputs are already normalized (no weird separators or encodings)
- You own the environment (e.g., an internal tool in a sealed container)
- You have tests that enforce the above (so a future change doesn’t silently break safety)

If you’re unsure, use strict-path (canonicalized).

## Fast decision guide

- Is the input from users, files, network, LLMs, or archives? → Use strict-path (canonicalized: `StrictPath`/`VirtualPath`).
- Is this a perf‑critical inner loop on paths you generate yourself and you’ve proven there are no symlinks? → A lexical-only crate might be acceptable.
- Mixed or uncertain? → Use strict-path (canonicalized).

## Concrete examples

- “User uploads a file named `../../etc/passwd`”
    - strict-path (canonicalized): Rejected or clamped safely; cannot escape the root.
    - lexical-only crate: Traversal may be blocked, but symlinks or platform quirks can still break containment.

- “Windows machine with `C:\Program Files` also visible as `C:\PROGRA~1`”
    - strict-path (canonicalized): Treats both as the same real place; escape attempts fail.
    - lexical-only crate: A clever alias or hidden symlink may trick a simple prefix check—even if traversal is blocked.

## Short recipes

- strict-path (canonicalized, default):
	- Validate via a boundary/root, then operate through `StrictPath`/`VirtualPath` methods.
	- Accept `&StrictPath<_>`/`&VirtualPath<_>` in helpers, or accept a `&PathBoundary/_VirtualRoot` plus the untrusted segment.

- If you intentionally use a lexical-only crate (advanced):
	- Keep lexical checks isolated and documented; add tests that assert “no symlinks / normalized inputs”.
	- If the situation changes later, migrate back to strict-path with minimal refactors because your signatures stayed explicit.

See also:
- Ergonomics → Interop vs Display
- README → “Where This Makes Sense”

> "Lexical checks aren't just about traversal—symlinks and platform quirks are the real troublemakers."
