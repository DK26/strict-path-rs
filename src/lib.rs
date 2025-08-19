//! # jailed-path
//!
//! **Prevent directory traversal with a type-safe, virtualized filesystem API.**
//!
//! This crate provides two complementary sets of types for handling filesystem paths securely:
//!
//! 1.  **User-Facing (`VirtualRoot` and `VirtualPath`)**: Designed for all user-facing interactions.
//!     Paths are displayed relative to a virtual root (e.g., `/downloads/file.txt`), preventing
//!     any leakage of the underlying filesystem structure. Use these for UI, logging, and user input.
//!
//! 2.  **System-Facing (`Jail` and `JailedPath`)**: Designed for direct filesystem operations.
//!     Paths are real, canonicalized paths (e.g., `/var/app/storage/downloads/file.txt`). Use
//!     these for file I/O or when interfacing with other system APIs.
//!
//! The core security guarantee is that all paths are **mathematically proven** to stay within their
//! designated boundaries, neutralizing traversal attacks like `../../../etc/passwd`.
//!
//! ## Quickstart: User-Facing Virtual Paths
//!
//! ```rust
//! use jailed_path::VirtualRoot;
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a virtual root, which corresponds to a real directory.
//! fs::create_dir_all("user_data")?;
//! let vroot = VirtualRoot::<()>::try_new("user_data")?;
//!
//! // 2. Create a virtual path from user input. Traversal attacks are neutralized.
//! let virtual_path = vroot.try_path_virtual("documents/report.pdf")?;
//! let attack_path = vroot.try_path_virtual("../../../etc/hosts")?;
//!
//! // 3. Displaying the path is always safe and shows the virtual view.
//! assert_eq!(virtual_path.to_string(), "/documents/report.pdf");
//! assert_eq!(attack_path.to_string(), "/etc/hosts"); // Clamped, not escaped
//!
//! // 4. For file I/O, convert to a system-facing JailedPath.
//! let jailed_path = virtual_path.unvirtual();
//! jailed_path.create_dir_all()?; // create the directory if needed
//!
//! assert!(jailed_path.exists());
//!
//! fs::remove_dir_all("user_data")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Features
//!
//! 🔒 **Separation of Concerns**: `VirtualPath` for UX, `JailedPath` for I/O.
//! 🏛️ **Mathematical Guarantees**: Rust's type system proves security at compile time.
//! 🛡️ **Zero Attack Surface**: No `Deref` to `Path`, validation cannot be bypassed.
//! 📁 **Built-in Safe I/O**: `JailedPath` provides safe file operations.
//! 🎯 **Multi-Jail Safety**: Marker types prevent cross-jail contamination at compile time.
//! 🔗 **Type-History Design**: Internal pattern ensures paths carry proof of validation stages.
//! 🧪 **Comprehensive Testing**: High test coverage with attack scenario simulation.
//! 🌍 **Cross-Platform**: Works on Windows, macOS, and Linux.
//!
//! ## When to Use Which Type
//!
//! | Use Case                               | Correct Type      | Example                                        |
//! | -------------------------------------- | ----------------- | ---------------------------------------------- |
//! | Displaying a path in a UI or log       | `VirtualPath`     | `println!("File: {}", virtual_path);`          |
//! | Manipulating a path based on user view | `VirtualPath`     | `virtual_path.parent_virtual()`                |
//! | Reading or writing a file              | `JailedPath`      | `jailed_path.read_bytes()?`                    |
//! | Integrating with an external API       | `JailedPath`      | `external_api(jailed_path.unjail())`           |
//!
//! ## Multi-Jail Type Safety
//!
//! Use marker types to prevent paths from different jails from being used interchangeably.
//!
//! ```rust
//! use jailed_path::{Jail, JailedPath, VirtualRoot, VirtualPath};
//! use std::fs;
//!
//! struct StaticAssets;
//! struct UserUploads;
//!
//! fn serve_asset(asset: &JailedPath<StaticAssets>) -> Result<Vec<u8>, std::io::Error> {
//!     asset.read_bytes()
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # fs::create_dir_all("assets")?; fs::create_dir_all("uploads")?;
//! # fs::write("assets/style.css", "body{}")?;
//! let assets_vroot: VirtualRoot<StaticAssets> = VirtualRoot::try_new("assets")?;
//! let uploads_vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new("uploads")?;
//!
//! let css_file: VirtualPath<StaticAssets> = assets_vroot.try_path_virtual("style.css")?;
//! let user_file: VirtualPath<UserUploads> = uploads_vroot.try_path_virtual("avatar.jpg")?;
//!
//! serve_asset(&css_file.unvirtual())?; // ✅ Correct type
//! // serve_asset(&user_file.unvirtual())?; // ❌ Compile error: wrong marker type!
//! # fs::remove_dir_all("assets").ok(); fs::remove_dir_all("uploads").ok();
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Guarantees
//!
//! All `..` components are clamped, symbolic links are resolved, and the final real path is
//! mathematically validated against the jail boundary. Path traversal attacks are impossible.
//!
//! ### Windows-only hardening: DOS 8.3 short names
//!
//! On Windows, paths like `PROGRA~1` are DOS 8.3 short-name aliases. To prevent ambiguity,
//! this crate rejects paths containing non-existent components that look like 8.3 short names
//! with a dedicated error, `JailedPathError::WindowsShortName`.
//!
//! ## Installation
//!
//! Add `jailed-path` to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! jailed-path = "0.1.0" # Replace with the latest version
//! ```

#![forbid(unsafe_code)]

// Public modules
pub mod error;
pub mod jailed_path;
pub mod validator;
pub mod virtual_path;
pub mod virtual_root;

#[cfg(test)]
mod tests;

// Public exports
pub use error::JailedPathError;
pub use jailed_path::JailedPath;
pub use validator::jail::Jail;
pub use virtual_path::VirtualPath;
pub use virtual_root::VirtualRoot;

/// Result type alias for this crate's operations.
pub type Result<T> = std::result::Result<T, JailedPathError>;
