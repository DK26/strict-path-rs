# Interop vs Display

- Interop (AsRef<Path>): use `interop_path()` on `StrictPath`, `VirtualPath`, `PathBoundary`, and `VirtualRoot`. It borrows the underlying OS path without allocations.
- Display to users:
  - System paths: use `strictpath_display()` (on `StrictPath`/`PathBoundary`).
  - Virtual UI paths: use `virtualpath_display()` (on `VirtualPath`).
- Never use `interop_path().to_string_lossy()` for display—mixes concerns and may leak internals.
- Do not wrap secure types with `Path::new` or `PathBuf::from`.
- Directory discovery vs validation:
  - Discover children via `read_dir(root.interop_path())` or root helpers.
  - Re-validate names with `strict_join()`/`virtual_join()` before any I/O.
