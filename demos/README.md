# strict-path demos

Real-world demo binaries showing strict-path in production scenarios. Demos model end-to-end flows, default to offline behavior, and keep heavy dependencies feature-gated.

## Quick Start

```bash
cd demos

# Basic demos (no features needed)
cargo run --bin error_handling
cargo run --bin virtualpath_only_server
cargo run --bin config_includes
cargo run --bin multi_jail_server

# Ecosystem integration
cargo run --bin dirs_demo --features with-dirs
cargo run --bin tempfile_demo --features with-tempfile
cargo run --bin portable_app_demo --features "with-app-path,virtual-path"

# Feature-gated demos
cargo run --bin archive_extractor --features with-zip -- --archive test.zip --output ./out
cargo run --bin mcp_file_service_rmcp --features with-rmcp -- --mode virtual --root ./project
```

## Demo Categories

### CLI Tools (`cli/`)
| Demo                       | Features       | Description                                      |
| -------------------------- | -------------- | ------------------------------------------------ |
| `cli_backup_tool`          | —              | Backup utility with validated source/destination |
| `secure_file_copy_cli`     | —              | Manifest-based file copy with traversal blocking |
| `tenant_user_virtual_root` | `virtual-path` | Per-user VirtualRoot isolation pattern           |

### Configuration (`config/`)
| Demo                        | Features                        | Description                                                     |
| --------------------------- | ------------------------------- | --------------------------------------------------------------- |
| `config_includes`           | —                               | Safe include directive resolution with VirtualPath              |
| `config_management_example` | `virtual-path`                  | Full config loading: hierarchy, raw→validated, multiple formats |
| `portable_app_demo`         | `with-app-path`, `virtual-path` | Interactive QuickNotes app with portable storage                |

### Ecosystem Integration (`filesystem/`, `io/`)
| Demo                | Features        | Description                                                         |
| ------------------- | --------------- | ------------------------------------------------------------------- |
| `dirs_demo`         | `with-dirs`     | **OS standard directories** - config, data, cache with PathBoundary |
| `tempfile_demo`     | `with-tempfile` | **Temporary files with RAII** - upload staging, build pipelines     |
| `temp_file_manager` | —               | Temp file processing with secure boundaries                         |

### Security (`security/`)
| Demo                | Features   | Description                                       |
| ------------------- | ---------- | ------------------------------------------------- |
| `archive_extractor` | `with-zip` | CLI tool with progress bar, zip-slip prevention   |
| `error_handling`    | —          | Error chain patterns and StrictPathError handling |

### Servers (`server/`)
| Demo                      | Features | Description                                                   |
| ------------------------- | -------- | ------------------------------------------------------------- |
| `static_file_server`      | —        | Raw TCP server with VirtualRoot validation                    |
| `virtualpath_only_server` | —        | Minimal VirtualPath-only I/O pattern                          |
| `multi_jail_server`       | —        | **Multiple security contexts** - public assets + user uploads |

### Web Services (`web/`)
| Demo                       | Features       | Description                                                          |
| -------------------------- | -------------- | -------------------------------------------------------------------- |
| `axum_static_server`       | `virtual-path` | Axum static file serving with VirtualRoot                            |
| `tenant_workspace_service` | —              | Multi-tenant with tuple markers for resource+permission              |
| `document_vault_service`   | —              | **Tuple marker authorization** - confidential docs vs public reports |
| `static_site_generator`    | —              | Complete build tool with StrictPath boundaries                       |
| `rbac_portal_service`      | —              | Role hierarchy (guest/user/moderator/admin)                          |
| `jwt_token_auth_service`   | `with-jwt`     | Real JWT validation with typed capabilities                          |

### LLM/MCP Integration (`llm/`)
| Demo                    | Features    | Description                                                       |
| ----------------------- | ----------- | ----------------------------------------------------------------- |
| `llm_workspace`         | —           | LLM file workspace simulation                                     |
| `mcp_file_service`      | —           | MCP file service (manual protocol)                                |
| `mcp_file_service_rmcp` | `with-rmcp` | Official MCP runtime with tools: file.read, file.write, file.list |

### Tools (`tools/`)
| Demo                    | Description                                    |
| ----------------------- | ---------------------------------------------- |
| `docker_volume_manager` | Volume backup/restore with validated paths     |
| `archive_builder`       | Archive creation with safe path assembly       |
| `migrations_runner`     | Database migration runner with path validation |

### Cloud (`cloud/`)
| Demo        | Features   | Description                                        |
| ----------- | ---------- | -------------------------------------------------- |
| `s3_mirror` | `with-aws` | S3 sync with local VirtualRoot paths → object keys |

### Data (`data/`)
| Demo                | Description                                            |
| ------------------- | ------------------------------------------------------ |
| `user_data_manager` | Ingest→process→store pipeline with separate boundaries |

---

## Extension Ideas

These patterns are documented in mdBook but not implemented as standalone demos. Use them as starting points for your own implementations:

### File Upload Patterns
- **Multi-tenant file upload API** — Per-tenant VirtualRoot with `tenant_id` isolation, simulating HTTP file upload endpoints with path validation
- **File upload service** — Axum/Actix handlers accepting multipart uploads, staging to temp, validating filenames, moving to permanent storage

### Authorization & Capabilities
- **Capability-based asset service** — Traits like `HasCapability<CanWrite>` gate operations at compile-time; agency reviewers (read-only), brand editors (read/write), brand directors (full control)
- **Database-backed auth service** — SQLite/Postgres user store, token validation, mapping DB users to marker-based permissions
- **Advanced capability patterns** — Hierarchical capabilities, capability delegation, time-limited access tokens

### Backup & Sync
- **User home backup service** — Axum API authenticating per-user tokens, issuing typed backup capabilities with `StrictPath<UserHome>` boundaries
- **Incremental sync** — Track file changes, validate new paths, sync only modified files

### Configuration Loaders
- **Simple config loader** — Basic `PathBoundary` for config directory, load single config file
- **Secure config with markers** — `StrictPath<AppConfig>` vs `StrictPath<UserConfig>` separation
- **OS directories config** — Combine `dirs` crate with PathBoundary for platform-appropriate config locations

### Archive Variants
- **Archive with config validation** — Load extraction config from JSON/TOML, validate base_dir paths before extraction
- **Safe archive extractor** — Simpler version of archive_extractor for embedding in libraries

---

## When To Use strict-path

**Use strict-path for untrusted paths from:**
- HTTP inputs: route params, form fields, JSON bodies
- Archive metadata: ZIP/TAR entry names (zip-slip)
- Database records: stored paths that could be modified
- Config files: paths from external systems
- LLM output: generated file names/paths

**Use std Path/PathBuf for trusted sources:**
- CLI args for base directories
- Environment variables
- Hard-coded constants

## Features

```toml
with-zip        # Archive demos (zip, flate2)
with-aws        # S3 integration (aws-config, aws-sdk-s3)
with-app-path   # Portable app demos (app-path)
with-dirs       # OS standard directories (dirs)
with-tempfile   # Temporary file handling (tempfile)
with-rmcp       # MCP server runtime (rmcp)
with-jwt        # JWT auth demos (hmac, sha2, base64)
virtual-path    # VirtualRoot/VirtualPath support
```

## Key Patterns to Learn

| Pattern                    | Best Demo                  | What You'll Learn                              |
| -------------------------- | -------------------------- | ---------------------------------------------- |
| **Zip-slip prevention**    | `archive_extractor`        | Validate archive entry names before extraction |
| **Multi-tenant isolation** | `tenant_workspace_service` | Per-user VirtualRoot, tuple markers            |
| **Tuple marker auth**      | `document_vault_service`   | `StrictPath<(Resource, Permission)>` patterns  |
| **OS directories**         | `dirs_demo`                | Platform-appropriate config/data/cache         |
| **Tempfile RAII**          | `tempfile_demo`            | Automatic cleanup, upload staging              |
| **Multiple boundaries**    | `multi_jail_server`        | Separate contexts for different trust levels   |
| **MCP/LLM sandboxing**     | `mcp_file_service_rmcp`    | Validate LLM-generated paths                   |
| **RBAC roles**             | `rbac_portal_service`      | Guest/user/moderator/admin hierarchy           |
| **Portable apps**          | `portable_app_demo`        | Executable-relative paths with app-path        |

## Notes

- Demos are **not part of the main workspace** to avoid MSRV lock coupling
- All demos pass clippy with `-D warnings` (no `#[allow(..)]`)
- See mdBook documentation (`.docs/`) for comprehensive tutorials
- Demos prefer real flows with actual external dependencies over mocks
