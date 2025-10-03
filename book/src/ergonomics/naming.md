# Naming

Prefer domain-based names; avoid type-based names.

- Good: `config_dir`, `uploads_root`, `archive_src`, `user_vroot`, `system_root`.
- Avoid: `boundary`, `jail`, `source_` prefixes, or one-letter variables.
- Keep names consistent with the directory they represent and convey intent in code review.

### Marker Types

- Name markers after the storage domain (`struct PublicAssets;`, `struct BrandEditorWorkspace;`). Reviewers should understand the filesystem contents from the type alone.
- Skip suffixes like `Marker`, `Type`, or `Root`; they repeat what Rust already communicates. `struct MediaLibrary;` is clearer than `struct MediaLibraryMarker;`.
- Tuples that pair storage with authorization should keep the resource first and the capability second: `StrictPath<(BrandDirectorArchive, FullControlCapability)>`.
- Focus on what's stored, not who uses it. A marker like `BrandAssets` tells you the directory contains brand materials, while `EditorFiles` only tells you someone called "Editor" uses it. The marker describes the filesystem contents and access policy, not the caller's identity.
