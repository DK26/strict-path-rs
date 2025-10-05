# Stage 4: Authorization with `change_marker()` — Compile-Time Authorization Proofs

> *"The compiler can mathematically prove that authorization happened first."*

In Stage 3, you learned how markers prevent domain mix-ups. Now you'll learn how to **encode authorization** in markers using `change_marker()`, so the compiler can mathematically prove that authorization checks weren't forgotten.

## The Authorization Problem

Markers prevent domain confusion. But what about **permissions**? How do we encode "this user is authorized to write to this directory"?

### Traditional Approach: Runtime Checks Everywhere

```rust
use strict_path::StrictPath;

struct UserFiles;

// ❌ Problem: Authorization check inside every operation
fn write_user_file(path: &StrictPath<UserFiles>, user_id: &str, data: &[u8]) 
    -> std::io::Result<()> 
{
    if !is_authorized(user_id) {  // Runtime check (can forget!)
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied, 
            "Unauthorized"
        ));
    }
    path.write(data)
}

fn delete_user_file(path: &StrictPath<UserFiles>, user_id: &str) 
    -> std::io::Result<()> 
{
    if !is_authorized(user_id) {  // Repeated check (can forget!)
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied, 
            "Unauthorized"
        ));
    }
    path.remove_file()
}

fn read_user_file(path: &StrictPath<UserFiles>, user_id: &str) 
    -> std::io::Result<Vec<u8>> 
{
    // Oops! Forgot the authorization check here! 🚨
    path.read()
}

fn is_authorized(user_id: &str) -> bool {
    user_id == "alice"
}
```

**Problems:**
- ❌ Authorization checks scattered everywhere
- ❌ Easy to forget a check (see `read_user_file`)
- ❌ No compile-time guarantee that authorization happened
- ❌ Code review has to catch missing checks (humans are fallible)

### Better Approach: Encode Authorization in the Type

Instead of **checking** authorization repeatedly, we **encode** it in the type once:

```rust
use strict_path::StrictPath;

// Resource marker: describes WHAT directory
struct UserFiles;

// Permission markers: describe LEVEL of access
struct ReadOnly;
struct ReadWrite;

// Authorization gate: validates token → returns authorized marker
fn authenticate_user_access(
    token: &str,
    path: StrictPath<(UserFiles, ReadOnly)>
) -> Option<StrictPath<(UserFiles, ReadWrite)>> {
    // ✅ Authorization: Token validated (checked once here!)
    if validate_token(token) {
        // Transform marker to encode proven authorization
        Some(path.change_marker::<(UserFiles, ReadWrite)>())
    } else {
        None
    }
}

fn validate_token(token: &str) -> bool {
    token == "valid-token-12345"  // Real apps: JWT validation, database lookup, etc.
}

// Functions accept paths that already prove authorization
fn write_user_file(path: &StrictPath<(UserFiles, ReadWrite)>, data: &[u8]) 
    -> std::io::Result<()> 
{
    // No authorization check needed! Type proves it already happened.
    path.write(data)
}

fn delete_user_file(path: &StrictPath<(UserFiles, ReadWrite)>) 
    -> std::io::Result<()> 
{
    // No authorization check needed! Type proves it already happened.
    path.remove_file()
}

fn read_user_file(path: &StrictPath<(UserFiles, ReadOnly)>) 
    -> std::io::Result<Vec<u8>> 
{
    // ReadOnly access is sufficient for reading
    path.read()
}
```

## Understanding `change_marker()`

### What `change_marker()` Is NOT

```rust
// ❌ WRONG way to think about it:
// "change_marker() grants permissions"
// "change_marker() does authorization"
```

### What `change_marker()` Actually Does

```rust
// ✅ RIGHT way to think about it:
// "change_marker() ENCODES proven authorization in the type"
// "change_marker() transforms the marker AFTER authorization passed"
```

**The pattern:**
1. ✅ **Check authorization** (token validation, capability check, etc.)
2. ✅ **If authorized:** call `change_marker()` to encode that fact in the type
3. ✅ **Pass the new type** to functions that require authorization
4. ✅ **The compiler proves** authorization happened (can't get the marker any other way!)

## Using It: Complete Example

```rust
use strict_path::StrictPath;

struct UserFiles;
struct ReadOnly;
struct ReadWrite;

fn handle_request(token: &str, filename: &str, data: Option<&[u8]>) 
    -> Result<(), Box<dyn std::error::Error>> 
{
    // Start with read-only access (no authorization yet)
    let user_files_dir: StrictPath<(UserFiles, ReadOnly)> = 
        StrictPath::with_boundary_create("user_files")?;
    
    let file_path = user_files_dir.strict_join(filename)?;

    // Anyone can read with ReadOnly marker
    let _content = read_user_file(&file_path)?;
    println!("✅ Read succeeded (no authorization needed)");

    // Try to upgrade to ReadWrite by authenticating
    if let Some(writable_path) = authenticate_user_access(token, file_path) {
        // ✅ Token validated! Now we have ReadWrite access
        println!("✅ Authorization succeeded");
        
        if let Some(data) = data {
            write_user_file(&writable_path, data)?;
            println!("✅ Write succeeded (authorization proven by type)");
        }
        
        delete_user_file(&writable_path)?;
        println!("✅ Delete succeeded (authorization proven by type)");
    } else {
        println!("❌ Authorization failed — cannot write or delete");
    }

    Ok(())
}

fn authenticate_user_access(
    token: &str,
    path: StrictPath<(UserFiles, ReadOnly)>
) -> Option<StrictPath<(UserFiles, ReadWrite)>> {
    if validate_token(token) {
        Some(path.change_marker())
    } else {
        None
    }
}

fn validate_token(token: &str) -> bool {
    token == "valid-token-12345"
}

fn read_user_file(path: &StrictPath<(UserFiles, ReadOnly)>) -> std::io::Result<Vec<u8>> {
    path.read()
}

fn write_user_file(path: &StrictPath<(UserFiles, ReadWrite)>, data: &[u8]) -> std::io::Result<()> {
    path.write(data)
}

fn delete_user_file(path: &StrictPath<(UserFiles, ReadWrite)>) -> std::io::Result<()> {
    path.remove_file()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Valid token — authorization succeeds
    handle_request("valid-token-12345", "notes.txt", Some(b"New content"))?;
    
    // Invalid token — authorization fails
    handle_request("invalid-token", "notes.txt", Some(b"Hack attempt"))?;
    
    Ok(())
}
```

## Tuple Markers: Composing Resources and Permissions

Notice we're using **tuple markers**: `(UserFiles, ReadOnly)` and `(UserFiles, ReadWrite)`.

```rust
struct UserFiles;      // First element: WHAT resource
struct ReadOnly;       // Second element: WHAT permission level
struct ReadWrite;

// Composed together:
// StrictPath<(UserFiles, ReadOnly)>   = User files with read-only access
// StrictPath<(UserFiles, ReadWrite)>  = User files with read-write access
```

**Why tuples?**
- ✅ **Flexible composition:** Mix and match resources with permissions
- ✅ **Easy to transform:** `change_marker()` can swap out permission levels
- ✅ **Standard Rust idiom:** No need to learn special syntax

## Try It Yourself: Capability-Based Authorization

Here's a more sophisticated example with multiple capability levels:

```rust
use strict_path::StrictPath;

struct ProjectFiles;
struct CanRead;
struct CanWrite;
struct CanDelete;

// Check user role and return appropriate marker
fn grant_project_access(
    user_role: &str,
    path: StrictPath<ProjectFiles>
) -> Option<StrictPath<(ProjectFiles, CanRead, CanWrite, CanDelete)>> {
    // ✅ Authorization: Role checked
    if user_role == "admin" {
        // Admin gets full access (read + write + delete)
        Some(path.change_marker::<(ProjectFiles, CanRead, CanWrite, CanDelete)>())
    } else {
        None
    }
}

fn grant_editor_access(
    user_role: &str,
    path: StrictPath<ProjectFiles>
) -> Option<StrictPath<(ProjectFiles, CanRead, CanWrite)>> {
    // ✅ Authorization: Role checked
    if user_role == "editor" || user_role == "admin" {
        // Editors can read and write (but not delete)
        Some(path.change_marker::<(ProjectFiles, CanRead, CanWrite)>())
    } else {
        None
    }
}

fn grant_readonly_access(
    user_role: &str,
    path: StrictPath<ProjectFiles>
) -> Option<StrictPath<(ProjectFiles, CanRead)>> {
    // ✅ Authorization: Role checked
    if user_role == "viewer" || user_role == "editor" || user_role == "admin" {
        Some(path.change_marker::<(ProjectFiles, CanRead)>())
    } else {
        None
    }
}

// Functions require specific capabilities in their signature
fn read_project(path: &StrictPath<(ProjectFiles, CanRead)>) -> std::io::Result<String> {
    path.read_to_string()
}

fn update_project(path: &StrictPath<(ProjectFiles, CanRead, CanWrite)>) -> std::io::Result<()> {
    path.write(b"Updated project data")
}

fn delete_project(path: &StrictPath<(ProjectFiles, CanRead, CanWrite, CanDelete)>) -> std::io::Result<()> {
    path.remove_file()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let projects_dir: StrictPath<ProjectFiles> = 
        StrictPath::with_boundary_create("projects")?;
    
    let project = projects_dir.strict_join("proposal.md")?;

    // Viewer can only read
    if let Some(readonly_path) = grant_readonly_access("viewer", project.clone()) {
        read_project(&readonly_path)?;
        println!("✅ Viewer: read succeeded");
        // update_project(&readonly_path)?;  // ❌ Won't compile: missing CanWrite
    }

    // Editor can read and write
    if let Some(editor_path) = grant_editor_access("editor", project.clone()) {
        read_project(&editor_path)?;      // ✅ Has CanRead
        update_project(&editor_path)?;    // ✅ Has CanRead + CanWrite
        println!("✅ Editor: read and write succeeded");
        // delete_project(&editor_path)?; // ❌ Won't compile: missing CanDelete
    }

    // Admin can do everything
    if let Some(admin_path) = grant_project_access("admin", project) {
        read_project(&admin_path)?;      // ✅ Has CanRead
        update_project(&admin_path)?;    // ✅ Has CanRead + CanWrite
        delete_project(&admin_path)?;    // ✅ Has CanRead + CanWrite + CanDelete
        println!("✅ Admin: full access succeeded");
    }

    Ok(())
}
```

## Head First Moment: Passport Stamps

Think of `change_marker()` like **stamping a passport**:

1. **You apply for a visa** (submit token for validation)
2. **Visa office checks credentials** (authorization function validates token)
3. **If approved, they stamp your passport** (call `change_marker()`)
4. **Guards at checkpoints check your stamp** (functions check marker type)

The stamp doesn't grant permission — **the visa office did that**. The stamp just **proves** permission was granted.

**Functions check your stamp (marker), not your visa application (token).**

This means:
- ✅ Authorization happens **once** (at the visa office)
- ✅ Every checkpoint trusts the stamp (no re-checking)
- ✅ Can't forge a stamp (only way to get marker is through auth function)
- ✅ Compiler ensures you have the right stamp for each checkpoint

## The Authorization Pattern Summary

```rust
// 1️⃣ Define resource and permission markers
struct Resource;
struct ReadOnly;
struct ReadWrite;

// 2️⃣ Create authorization gate
fn authorize(token: &str, path: StrictPath<(Resource, ReadOnly)>) 
    -> Option<StrictPath<(Resource, ReadWrite)>> 
{
    if validate(token) {                        // ✅ Check authorization
        Some(path.change_marker())              // ✅ Encode in type
    } else {
        None                                    // ❌ Authorization failed
    }
}

// 3️⃣ Functions require authorized marker
fn protected_operation(path: &StrictPath<(Resource, ReadWrite)>) {
    // No authorization check needed!
    // Type proves authorization already happened.
}
```

## Real-World Example: Web API

Here's how you'd use this in a web server:

```rust
use strict_path::StrictPath;

struct ApiUploads;
struct AuthToken(String);
struct ReadAccess;
struct WriteAccess;

// Authorization: Validate JWT token
fn authorize_write_access(
    token: &AuthToken,
    path: StrictPath<(ApiUploads, ReadAccess)>
) -> Result<StrictPath<(ApiUploads, ReadAccess, WriteAccess)>, AuthError> {
    // ✅ Authorization: Validate JWT token
    if verify_jwt(&token.0)? {
        Ok(path.change_marker())
    } else {
        Err(AuthError::InvalidToken)
    }
}

fn verify_jwt(token: &str) -> Result<bool, AuthError> {
    // Real implementation would:
    // - Verify signature
    // - Check expiration
    // - Validate claims
    Ok(token.starts_with("Bearer "))
}

// API handlers
fn handle_read(uploads: &StrictPath<(ApiUploads, ReadAccess)>, filename: &str) 
    -> Result<Vec<u8>, ApiError> 
{
    let file = uploads.strict_join(filename)?;
    Ok(file.read()?)
}

fn handle_write(
    uploads: &StrictPath<(ApiUploads, ReadAccess, WriteAccess)>, 
    filename: &str,
    data: &[u8]
) -> Result<(), ApiError> 
{
    let file = uploads.strict_join(filename)?;
    Ok(file.write(data)?)
}

#[derive(Debug)]
enum AuthError {
    InvalidToken,
}

#[derive(Debug)]
enum ApiError {
    PathError(strict_path::StrictPathError),
    IoError(std::io::Error),
}

impl From<strict_path::StrictPathError> for ApiError {
    fn from(e: strict_path::StrictPathError) -> Self {
        ApiError::PathError(e)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::IoError(e)
    }
}
```

## Key Takeaways

✅ **`change_marker()` encodes proven authorization** (doesn't grant it)  
✅ **Tuple markers compose resources and permissions**  
✅ **Authorization happens once** — type system enforces it everywhere  
✅ **Impossible to bypass** — only way to get the marker is through auth gate  
✅ **Compiler catches missing authorization** — won't compile without proper marker  

## The Complete Guarantee So Far

> **If a function accepts `StrictPath<(Resource, Permission)>`, the compiler mathematically proves that:**
> 1. ✅ The path cannot escape its boundary (Stage 1)
> 2. ✅ The path is in the correct domain (Stage 3)
> 3. ✅ Authorization was granted for that permission level (Stage 4)

**This is compile-time authorization.** Forget a check? Won't compile. Use the wrong permission level? Won't compile. Bypass authorization? Impossible.

## What's Next?

You've mastered authorization with markers. But what about **user-facing applications** where you want to show clean paths like `/documents/file.txt` instead of ugly system paths?

That's where `VirtualPath` comes in...

**[Continue to Stage 5: Virtual Paths →](./stage5_virtual_paths.md)**

---

**Quick Reference:**

```rust
// Define markers
struct Resource;
struct ReadOnly;
struct ReadWrite;

// Authorization gate
fn authorize(token: &str, path: StrictPath<(Resource, ReadOnly)>) 
    -> Option<StrictPath<(Resource, ReadWrite)>> 
{
    if validate(token) {
        Some(path.change_marker())  // Encode authorization
    } else {
        None
    }
}

// Protected function
fn protected(path: &StrictPath<(Resource, ReadWrite)>) {
    // No auth check needed — type proves it!
}
```
