# strict-path demos

This crate hosts real-world demo binaries that show how to apply strict-path in situations where paths come from untrusted or external sources. Demos are not API unit tests — they model end-to-end flows, default to offline behavior, and keep heavy dependencies feature-gated.

## When To Use strict-path (in demos)

Use strict-path only when the path string did not originate from you and may have been influenced by a third party or a different trust domain:

- HTTP/web inputs: route params, form fields, JSON bodies
- Archive metadata: ZIP/TAR entry names (zip-slip/tar-slip)
- Database records: stored paths that could have been modified externally
- Manifest/config files: lists of paths provided by external systems
- LLM/automation output: generated file names/paths
- Inter-service messages: queue/event payloads that contain paths

Use std `Path`/`PathBuf` for trusted, local-only sources:

- CLI arguments for the top-level source/destination directories
- Environment variables for base locations
- Hard-coded constants you control

Rule of thumb: validate the untrusted part right at the boundary, then pass `&StrictPath<_>` / `&VirtualPath<_>` in function signatures to encode guarantees.

## What Each Demo Demonstrates

- security/archive_extractor, …_mixed, …_with_config (feature `with-zip`)
  - Validates untrusted archive entry names via `VirtualRoot::virtual_join` or `PathBoundary::strict_join` before extraction.
- web/file_upload_api, web/file_upload_service
  - Validates HTTP path inputs and encodes guarantees in handler signatures.
- cli/secure_file_copy_cli
  - Ingests an untrusted manifest of relative paths; validates to jails (staging → workspace) and blocks traversal attempts.
- data/user_data_manager
  - Discovers files from an ingest area (external source) and stores processed outputs safely in a separate jail.
- tools/docker_volume_manager
  - Walks real volume directories, reads metadata, backs up/restores data with validated subpaths.
- cloud/s3_mirror (feature `with-aws`)
  - Demonstrates mapping validated local paths to object keys derived from a VirtualRoot.
- web/static_site_generator
  - Shows a site build pipeline using strict-path joins and built-in I/O. If all inputs are local and trusted, strict-path isn’t required for safety, but the demo keeps the API usage consistent for boundary-aware I/O.
- config/*, filesystem/*
  - Examples of using OS directories and app-relative locations; focus on correct boundary setup and display/interop practices.

## Anti‑Pattern Checklist (what we avoid)

- No `strict_join(".")` — validating constants adds no value.
- No `Path::new(...)`/`PathBuf::from(...)` around secure types.
- No `as_unvirtual().interop_path()` when `interop_path()` exists directly.
- No `interop_path().as_ref()` — `interop_path()` already implements `AsRef<Path>`.
- No `*_to_string_lossy()` for display of secure types — use `strictpath_display()` / `virtualpath_display()`.
- Prefer `impl AsRef<Path>` in helper signatures; accept `&StrictPath/_` or `&VirtualPath/_` where safety must be encoded.

## Running Demos

- Many demos run fully offline by default; some require features:
  - `with-zip`: archive extractors
  - `with-aws`: S3 mirror (mock unless `EXAMPLES_S3_RUN=1`)
  - `with-app-path`, `with-dirs`, `with-tempfile`: integration features

Example:

- `cd demos && cargo run --bin archive_extractor --features with-zip -- --archive ./test.zip --output ./out`
- `cd demos && cargo run --bin secure_file_copy_cli` (runs offline demo)

## Notes

- Demos are intentionally not part of the main workspace to avoid MSRV lock coupling.
- Demos prefer real flows and external inputs over contrived examples. If a demo doesn’t involve an external/untrusted path anywhere in the flow, we avoid using strict-path unnecessarily.
