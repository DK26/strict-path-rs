# strict-path

[![Crates.io](https://img.shields.io/crates/v/strict-path.svg)](https://crates.io/crates/strict-path)
[![Documentation](https://docs.rs/strict-path/badge.svg)](https://docs.rs/strict-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![CI](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/audit.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

**Prevent directory traversal with type-safe virtual path jails and safe symlinks**

## Security Foundation

Built on [`soft-canonicalize`](https://github.com/DK26/soft-canonicalize-rs) with protection against documented CVEs including CVE-2025-8088 (NTFS ADS attacks), CVE-2022-21658 (TOCTOU), Windows 8.3 short name vulnerabilities, and more. This isn't simple string comparison—paths are fully canonicalized and boundary-checked against real-world attack patterns.

## Full Documentation

For complete documentation, examples, and API reference, see the [repository README](../README.md).

## Quick Start

```rust
use jailed_path::Jail;

// Create a jail and validate any external path
let jail = Jail::try_new_create("safe_directory")?;
let safe_path = jail.jailed_join("user/input/file.txt")?;
safe_path.write_string("content")?; // Guaranteed safe
```

## License

MIT OR Apache-2.0
