# Using strict-path with archive extractors

Archive formats (ZIP, TAR, etc.) embed file names provided by untrusted sources. Treat each entry name as hostile and validate it through VirtualRoot or PathBoundary before any filesystem I/O.

## Recommended patterns

- Prefer VirtualRoot for extraction pipelines: it accepts any input and clamps it to the path boundary. This makes batch extraction resilient and user-friendly.
- Use create_parent_dir_all() before writes to avoid TOCTOU-style parent creation races in your own code. Our operations re-validate boundaries internally.
- Do not concatenate paths manually. Always join via vroot.virtual_join(name) or path_boundary.strict_join(name).
- Treat absolute, UNC, drive-relative, or namespace-prefixed paths as untrusted inputs. The virtual join will clamp these to the virtual root.
- On Windows, NTFS Alternate Data Streams (ADS) like "file.txt:stream" are handled safely. Writes remain within the path boundary or are cleanly rejected by the OS.

## Minimal example (ZIP-like flow)

```rust
use strict_path::VirtualRoot;

fn extract_all<M: Default>(dest: &std::path::Path, entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
    let vroot: VirtualRoot<M> = VirtualRoot::try_new_create(dest)?;

    for (name, data) in entries {
        // 1) Safely map entry name to a strict path (clamped on escape attempts)
        let vpath = match vroot.virtual_join(&name) {
            Ok(v) => v,
            Err(_) => continue, // cleanly reject this entry, log if needed
        };

        // 2) Ensure parent directories exist (inside the path boundary)
        vpath.create_parent_dir_all()?;

        // 3) Perform the write safely
        vpath.write_bytes(&data)?;
    }
    Ok(())
}
```

## Anti-patterns (don’t do this)

- Building paths with format!/push/join on std::path::Path without validation
- Stripping "../" by string replacement
- Allowing absolute paths through to the OS
- Treating encoded/unicode tricks (URL-encoded, dot lookalikes) as pre-sanitized

## Testing advice

- Add corpus entries with: "../", "..\\", absolute paths, UNC/\\?\ prefixes, drive-relative ("C:..\\foo"), unicode lookalikes, long paths.
- On Windows, include ADS cases like "decoy.txt:..\\..\\evil.exe" and reserved names.
- Assert that successful joins produce paths contained within the path boundary and failed joins are clean, with no creation outside the path boundary.

## Notes on behavior

- Virtual joins clamp traversal lexically to the virtual root; system-facing escapes (e.g., via symlinks/junctions) are rejected during resolution.
- We do not normalize Unicode; you can store/display NFC or NFD forms as-is. Both are contained safely.
- Hard links and privileged mount tricks are outside the scope of path-level protections (see README limitations).
