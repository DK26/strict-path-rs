# Equality & Ordering

- `StrictPath` and `VirtualPath` equality/ordering are based on their underlying system paths (within the same restriction).
- Do not compare display strings. Use the types’ built-in Eq/Ord/Hash.
- When you need system-path equality in virtual flows, compare via `as_unvirtual()`.
- Avoid lossy or normalization-prone string conversions for comparisons.
