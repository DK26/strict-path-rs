# Escape Hatches

Use escape hatches sparingly and deliberately.

- Borrow strict view from virtual: `vpath.as_unvirtual()` (preferred for shared helpers).
- Ownership conversions:
  - `StrictPath::virtualize()` → `VirtualPath`
  - `VirtualPath::unvirtual()` → `StrictPath`
  - `StrictPath::unstrict()` → `PathBuf` (avoid unless you truly need an owned `PathBuf`)
- Avoid chaining escape hatches in application code. If you must own a `PathBuf`, isolate it in a clearly-marked narrow scope.
