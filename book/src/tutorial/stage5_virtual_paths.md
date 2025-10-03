# Stage 5: Virtual Paths — User-Friendly Sandboxes

> *"Give users a clean '/' view, hide the messy system paths."*

In Stage 4, you learned how to encode authorization in markers. Now you'll learn how `VirtualPath` extends `StrictPath` with **user-friendly virtual roots** — perfect for sandboxing users and showing clean paths.

## The Problem with StrictPath for User UX

`StrictPath` is perfect for system operations, but it exposes real filesystem paths:

```rust
use strict_path::StrictPath;

fn show_user_files() -> Result<(), Box<dyn std::error::Error>> {
    let uploads_dir = StrictPath::with_boundary_create("/var/app/users/alice/uploads")?;
    let file = uploads_dir.strict_join("documents/report.pdf")?;

    // User sees ugly system path
    println!("Your file: {}", file.strictpath_display());
    // Output: /var/app/users/alice/uploads/documents/report.pdf
    
    // User thinks: "Why do I need to know about /var/app/users/alice?"
    // "I just want to see: /documents/report.pdf"

    Ok(())
}
```

**Problems:**
- ❌ Users see internal directory structure
- ❌ Paths are long and confusing
- ❌ Exposes system architecture details
- ❌ Not user-friendly for file browsers, cloud storage UI, etc.

## The Solution: VirtualPath

`VirtualPath` provides a **virtual root** — users see paths starting from `/`, but the system enforces the real boundary:

```rust
use strict_path::VirtualPath;

fn show_user_files_virtually() -> Result<(), Box<dyn std::error::Error>> {
    // Create a virtual root (system boundary: /var/app/users/alice/uploads)
    let user_vroot = VirtualPath::with_root("/var/app/users/alice/uploads")?;
    
    let file = user_vroot.virtual_join("documents/report.pdf")?;

    // User sees clean virtual path
    println!("Your file: {}", file.virtualpath_display());
    // Output: /documents/report.pdf
    
    // User thinks: "Perfect! That's my file."

    // System still operates on real path
    file.write(b"File contents")?;  
    // Actually writes to: /var/app/users/alice/uploads/documents/report.pdf

    println!("System path: {}", file.as_unvirtual().strictpath_display());
    // Output: /var/app/users/alice/uploads/documents/report.pdf

    Ok(())
}
```

## Clamping vs. Rejecting

This is the **key difference** between `VirtualPath` and `StrictPath`:

### StrictPath: Rejects Escapes

```rust
use strict_path::StrictPath;

fn strict_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = StrictPath::with_boundary_create("sandbox")?;

    // Normal path works
    let file1 = boundary.strict_join("data/file.txt")?;
    println!("✅ Valid: {}", file1.strictpath_display());

    // Attack attempt: FAILS with error
    let file2 = boundary.strict_join("../../../etc/passwd");
    match file2 {
        Ok(_) => println!("✅ Valid path"),
        Err(e) => println!("❌ Error: {}", e),  // PathEscapesBoundary
    }

    Ok(())
}
```

### VirtualPath: Clamps Escapes

```rust
use strict_path::VirtualPath;

fn virtual_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let vroot = VirtualPath::with_root("sandbox")?;

    // Normal path works
    let file1 = vroot.virtual_join("data/file.txt")?;
    println!("Virtual: {}", file1.virtualpath_display());  // /data/file.txt

    // Attack attempt: CLAMPED safely
    let file2 = vroot.virtual_join("../../../etc/passwd")?;  // No error!
    println!("Virtual: {}", file2.virtualpath_display());    // /etc/passwd (clamped!)
    
    // But system path is still safe:
    println!("System: {}", file2.as_unvirtual().strictpath_display());
    // Output: sandbox/etc/passwd (still inside boundary!)

    Ok(())
}
```

**Key difference:**
- **`StrictPath`:** Escape attempt → **Error** (explicit rejection)
- **`VirtualPath`:** Escape attempt → **Clamped to boundary** (graceful containment)

## When to Use Which

| Scenario                | Use           | Why                                            |
| ----------------------- | ------------- | ---------------------------------------------- |
| **Web API validation**  | `StrictPath`  | Fail fast on invalid input                     |
| **System config files** | `StrictPath`  | Reject malformed paths explicitly              |
| **User file browser**   | `VirtualPath` | Show clean `/` paths, clamp escapes gracefully |
| **Archive extraction**  | `VirtualPath` | Hostile archive entries can't escape           |
| **Cloud storage UI**    | `VirtualPath` | Users see `/MyFiles/` instead of system paths  |
| **LLM file operations** | `StrictPath`  | LLM-generated paths validated strictly         |

**Rule of thumb:**
- **System-facing?** → `StrictPath` (explicit errors)
- **User-facing?** → `VirtualPath` (graceful clamping)

## Try It Yourself: Per-User Sandboxes

Here's a realistic example of per-user isolation:

```rust
use strict_path::{VirtualPath, VirtualRoot};

struct UserFiles;

fn create_user_workspace(user_id: u64) -> Result<VirtualRoot<UserFiles>, Box<dyn std::error::Error>> {
    // Each user gets their own virtual root
    let user_dir = format!("users/user_{}", user_id);
    Ok(VirtualRoot::try_new_create(user_dir)?)
}

fn user_file_browser(user_id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let user_workspace = create_user_workspace(user_id)?;

    // User uploads files (they see clean paths)
    let doc = user_workspace.virtual_join("Documents/report.pdf")?;
    doc.create_parent_dir_all()?;
    doc.write(b"User document content")?;

    println!("User {} sees: {}", user_id, doc.virtualpath_display());
    // Output: /Documents/report.pdf

    println!("System stores at: {}", doc.as_unvirtual().strictpath_display());
    // Output: users/user_123/Documents/report.pdf

    // Even if user tries to escape, they stay in their sandbox
    let sneaky = user_workspace.virtual_join("../../../etc/passwd")?;
    println!("Attack clamped to: {}", sneaky.virtualpath_display());
    // Output: /etc/passwd (virtual)
    
    println!("Actually safe at: {}", sneaky.as_unvirtual().strictpath_display());
    // Output: users/user_123/etc/passwd (still in their sandbox!)

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    user_file_browser(123)?;
    user_file_browser(456)?;
    Ok(())
}
```

## VirtualPath = StrictPath + Virtual View

Under the hood, `VirtualPath` **wraps a `StrictPath`** and adds a virtual display layer:

```rust
use strict_path::VirtualPath;

fn demonstrate_duality() -> Result<(), Box<dyn std::error::Error>> {
    let vpath = VirtualPath::with_root("data")?.virtual_join("file.txt")?;

    // Virtual view (user-facing)
    println!("Virtual: {}", vpath.virtualpath_display());
    // Output: /file.txt

    // System view (actual filesystem path)
    println!("System: {}", vpath.as_unvirtual().strictpath_display());
    // Output: data/file.txt

    // All StrictPath operations work
    vpath.write(b"Hello, virtual world!")?;
    let content = vpath.read_to_string()?;
    println!("Content: {}", content);

    Ok(())
}
```

**The relationship:**
```rust
VirtualPath<Marker> = StrictPath<Marker> + virtual display semantics
```

## Symlinks and Virtual Paths

**Important:** While `VirtualPath` **clamps** relative path escapes (`../../../`), it still **validates symlinks**:

```rust
use strict_path::VirtualPath;

fn symlink_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let vroot = VirtualPath::with_root("sandbox")?;

    // Relative escape: CLAMPED (no error)
    let relative_escape = vroot.virtual_join("../../../../etc/passwd")?;
    println!("✅ Clamped: {}", relative_escape.virtualpath_display());

    // Symlink escape: ERROR (same as StrictPath)
    // If "sandbox/evil_link" -> "/etc/passwd" exists:
    let symlink_escape = vroot.virtual_join("evil_link");
    match symlink_escape {
        Ok(_) => println!("Path is safe"),
        Err(e) => println!("❌ Symlink escape rejected: {}", e),
    }

    Ok(())
}
```

**Key point:** `VirtualPath` is **not** a "just accept anything" mode. It's a "clamp relative paths, but still enforce boundary through symlink resolution" mode.

## Real-World Example: Cloud File Storage

```rust
use strict_path::{VirtualPath, VirtualRoot};

struct CloudStorage;

struct UserCloudStorage {
    user_id: u64,
    vroot: VirtualRoot<CloudStorage>,
}

impl UserCloudStorage {
    fn new(user_id: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let storage_path = format!("cloud_storage/user_{}", user_id);
        let vroot = VirtualRoot::try_new_create(storage_path)?;
        Ok(Self { user_id, vroot })
    }

    fn upload_file(&self, virtual_path: &str, data: &[u8]) 
        -> Result<String, Box<dyn std::error::Error>> 
    {
        let file = self.vroot.virtual_join(virtual_path)?;
        file.create_parent_dir_all()?;
        file.write(data)?;
        
        // Return clean virtual path for UI display
        Ok(file.virtualpath_display().to_string())
    }

    fn download_file(&self, virtual_path: &str) 
        -> Result<Vec<u8>, Box<dyn std::error::Error>> 
    {
        let file = self.vroot.virtual_join(virtual_path)?;
        Ok(file.read()?)
    }

    fn list_files(&self, virtual_dir: &str) 
        -> Result<Vec<String>, Box<dyn std::error::Error>> 
    {
        let dir = self.vroot.virtual_join(virtual_dir)?;
        let mut files = Vec::new();
        
        for entry in dir.read_dir()? {
            let entry = entry?;
            let vpath = self.vroot.virtual_join(entry.file_name().to_string_lossy().as_ref())?;
            files.push(vpath.virtualpath_display().to_string());
        }
        
        Ok(files)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice_storage = UserCloudStorage::new(1001)?;

    // Upload files (user sees clean paths)
    let path1 = alice_storage.upload_file("Photos/vacation.jpg", b"photo data")?;
    let path2 = alice_storage.upload_file("Documents/report.pdf", b"document data")?;
    
    println!("Uploaded: {}", path1);  // /Photos/vacation.jpg
    println!("Uploaded: {}", path2);  // /Documents/report.pdf

    // Download files
    let data = alice_storage.download_file("/Documents/report.pdf")?;
    println!("Downloaded {} bytes", data.len());

    // User tries to escape — safely clamped
    let evil_path = alice_storage.upload_file("../../../etc/passwd", b"attack")?;
    println!("Attack clamped to: {}", evil_path);  // /etc/passwd (in user's sandbox!)

    Ok(())
}
```

## Markers Work with VirtualPath Too

Just like `StrictPath`, you can use markers with `VirtualPath`:

```rust
use strict_path::{VirtualPath, VirtualRoot};

struct UserPhotos;
struct UserDocuments;

fn organize_virtual_storage(user_id: u64) -> Result<(), Box<dyn std::error::Error>> {
    // Each domain gets its own virtual root
    let photos_vroot: VirtualRoot<UserPhotos> = 
        VirtualRoot::try_new_create(format!("users/user_{}/photos", user_id))?;
    
    let docs_vroot: VirtualRoot<UserDocuments> = 
        VirtualRoot::try_new_create(format!("users/user_{}/documents", user_id))?;

    let photo = photos_vroot.virtual_join("vacation.jpg")?;  // VirtualPath<UserPhotos>
    let doc = docs_vroot.virtual_join("report.pdf")?;        // VirtualPath<UserDocuments>

    process_photo(&photo)?;              // ✅ Correct type
    process_document(&doc)?;             // ✅ Correct type
    // process_photo(&doc)?;             // ❌ Compile error!

    Ok(())
}

fn process_photo(photo: &VirtualPath<UserPhotos>) -> std::io::Result<()> {
    println!("Processing photo: {}", photo.virtualpath_display());
    Ok(())
}

fn process_document(doc: &VirtualPath<UserDocuments>) -> std::io::Result<()> {
    println!("Processing document: {}", doc.virtualpath_display());
    Ok(())
}
```

## Head First Moment: Storefront Facade

`VirtualPath` is like a **storefront with a clean facade**:

- **Customers see:** Beautiful `/Products/Item` URLs
- **Behind the scenes:** Files stored at `/var/www/store/inventory/category-5/sku-12345/item.jpg`

The facade (virtual path) makes for better UX. The real structure (strict path) handles the actual filesystem operations.

**Best of both worlds:**
- Users see clean, understandable paths
- System operates on real, validated paths
- Security boundary enforced throughout

## Key Takeaways

✅ **`VirtualPath` = `StrictPath` + virtual `/` view**  
✅ **Clamping behavior** — escapes are contained, not rejected  
✅ **User-friendly display** — show clean paths in UIs  
✅ **Per-user sandboxes** — each user gets their own virtual root  
✅ **Markers work** — domain separation applies to virtual paths too  
✅ **Symlinks still validated** — not a "trust everything" mode  

## The Complete Guarantee

> **If you have a `VirtualPath<Marker>`, the compiler guarantees:**
> 1. ✅ The path cannot escape its boundary (Stage 1)
> 2. ✅ The path is in the correct domain (Stage 3)
> 3. ✅ Virtual display is always rooted at `/` (Stage 5)
> 4. ✅ System operations use the validated real path (Stage 5)

## What's Next?

You now understand both `StrictPath` and `VirtualPath`. But how do you integrate with **external ecosystem crates** like OS directories, temp files, and app-specific paths?

That's where **feature-gated constructors** come in...

**[Continue to Stage 6: Feature Integration →](./stage6_features.md)**

---

**Quick Reference:**

```rust
// Create virtual root
let vroot = VirtualPath::with_root("path")?;

// Validate and clamp
let vpath = vroot.virtual_join(untrusted_input)?;

// Display
println!("Virtual: {}", vpath.virtualpath_display());      // /file.txt
println!("System: {}", vpath.as_unvirtual().strictpath_display());  // path/file.txt

// I/O operations
vpath.write(data)?;
let content = vpath.read_to_string()?;
```
