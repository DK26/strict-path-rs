# Axum Web Service Tutorial

This tutorial demonstrates **key security patterns** for web services using **Axum** and **strict-path**. We focus on the essential integration points where path validation prevents vulnerabilities.

> **Quick Start**: If you want a framework-agnostic example first, see [Web File Upload Service](../examples/web_upload_service.md) for the basic concepts without web framework complexity.

## What You'll Learn

How to integrate `strict-path` into an Axum web service:
- **Static file serving** with `PathBoundary` to prevent directory traversal
- **Per-user file storage** with `VirtualRoot` for user isolation
- **Type-safe contexts** with marker types to prevent mixing boundaries

## Why This Matters

Without `strict-path`, common mistakes lead to vulnerabilities:

```rust
// ❌ UNSAFE: User can access any file
let file_path = format!("./uploads/{}", user_input);
std::fs::read_to_string(file_path)?

// ✅ SAFE: Validated path, guaranteed within boundary
let file = uploads_root.virtual_join(user_input)?;
file.read_to_string()?
```

## Tutorial Structure

Short, focused chapters showing essential patterns:

### [Chapter 1: Project Setup](./chapter1_setup.md)
Basic project structure, marker types, and boundary initialization.

### [Chapter 2: Static Assets](./chapter2_static_assets.md)
Serve static files safely with `StrictPath<WebAssets>`.

### [Chapter 3: Per-User Storage](./chapter3_user_storage.md)
Isolate user files with `VirtualRoot<UserUploads>`.

### [Chapter 3: User Authentication](./chapter3_authentication.md)
Add user authentication and create per-user storage isolation.

**What you'll learn:**
- Simple session-based authentication
- Creating VirtualRoot per user
- Authorization markers with change_marker()
- Protecting routes with middleware

### [Chapter 4: File Upload System](./chapter4_uploads.md)
Build a secure file upload system with per-user isolation.

## Prerequisites

- **Rust**: 1.71.0 or later
- **Basic Axum knowledge**: Understanding handlers and state

---

**Ready to start?** → [Chapter 1: Project Setup](./chapter1_setup.md)
