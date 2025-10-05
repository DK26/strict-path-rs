# Web File Upload Service

Let's build a simple file upload service that allows users to upload files safely. This example demonstrates per-user isolation using `VirtualRoot`.

## The Problem

Web applications need to accept file uploads from users, but must prevent:
- ❌ Path traversal attacks (`../../../etc/passwd`)
- ❌ Users accessing other users' files
- ❌ Absolute path injections (`/var/www/html/shell.php`)

## The Solution

Use `VirtualRoot` to create isolated storage for each user. Each user operates in their own sandboxed environment.

## Complete Example

```rust
use strict_path::{StrictPath, VirtualPath, VirtualRoot};
use std::io;

struct FileUploadService;

impl FileUploadService {
    // Multi-user: each user operates under their own VirtualRoot
    fn upload_file(
        &self,
        user_uploads_root: &VirtualRoot,
        upload_file_name: &str,
        upload_file_content: &[u8],
    ) -> Result<VirtualPath, Box<dyn std::error::Error>> {
        // Validate the untrusted filename at the user's virtual root
        let uploaded_file: VirtualPath = user_uploads_root.virtual_join(upload_file_name)?;
        // Reuse strict-typed helper when needed
        self.save_uploaded(uploaded_file.as_unvirtual(), upload_file_content)?;
        println!("✅ File uploaded safely to: {}", uploaded_file.virtualpath_display());
        Ok(uploaded_file)
    }

    // Internal helper: signature encodes guarantee (accepts only &StrictPath)
    fn save_uploaded(&self, file: &StrictPath, content: &[u8]) -> io::Result<()> {
        file.create_parent_dir_all()?;
        file.write(content)
    }

    fn list_files(
        &self,
        user_uploads_root: &VirtualRoot,
    ) -> Result<Vec<VirtualPath>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();
        for entry in user_uploads_root.read_dir()? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let file: VirtualPath = user_uploads_root.virtual_join(entry.file_name())?;
                files.push(file);
            }
        }
        Ok(files)
    }

    fn download_file(&self, file: &VirtualPath) -> io::Result<Vec<u8>> {
        // Read and return the file content — type ensures safety
        file.read()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FileUploadService;

    // Per-user virtual roots
    let alice_uploads_root: VirtualRoot = VirtualRoot::try_new_create("user_uploads/alice")?;
    let bob_uploads_root: VirtualRoot = VirtualRoot::try_new_create("user_uploads/bob")?;

    // Simulate user uploads - these are all SAFE and isolated
    service.upload_file(&alice_uploads_root, "document.txt", b"Hello, world!")?;
    service.upload_file(&alice_uploads_root, "reports/january.pdf", b"PDF content here")?;
    service.upload_file(&bob_uploads_root, "images/photo.jpg", b"JPEG data")?;

    // These would be clamped/blocked by validation:
    // service.upload_file(&alice_uploads_root, "../../../etc/passwd", b"attack")?;  // ❌ Blocked!
    // service.upload_file(&alice_uploads_root, "..\\windows\\system32\\evil.exe", b"malware")?;  // ❌ Blocked!

    // List Alice's uploaded files (virtual paths)
    println!("📁 Alice's files:");
    for file in service.list_files(&alice_uploads_root)? {
        println!("  - {}", file.virtualpath_display());
    }

    // Download a file using VirtualPath
    let document_file = alice_uploads_root.virtual_join("document.txt")?;
    let content = service.download_file(&document_file)?;
    println!("📄 Downloaded: {}", String::from_utf8_lossy(&content));

    Ok(())
}
```

## Key Security Features

### 1. Per-User Isolation
Each user gets their own `VirtualRoot`. Alice can't access Bob's files and vice versa.

### 2. Automatic Path Validation
```rust
let uploaded_file = user_uploads_root.virtual_join(upload_file_name)?;
```
This validates the filename and ensures it stays within the user's boundary. Attacks are automatically blocked.

### 3. Type-Safe Helpers
```rust
fn save_uploaded(&self, file: &StrictPath, content: &[u8]) -> io::Result<()>
```
By accepting `&StrictPath`, the function signature guarantees the path has been validated.

### 4. Virtual Path Display
```rust
uploaded_file.virtualpath_display()  // Shows "/document.txt" to the user
uploaded_file.strictpath_display()   // Shows "user_uploads/alice/document.txt" (system path)
```
Users see clean paths starting from `/`, while the system knows the real location.

## Attack Scenarios Prevented

| Attack                            | Result                                   |
| --------------------------------- | ---------------------------------------- |
| `../../../etc/passwd`             | ❌ Clamped to user's root                 |
| `..\\windows\\system32\\evil.exe` | ❌ Clamped to user's root                 |
| `/var/www/html/shell.php`         | ❌ Treated as relative, stays in boundary |
| `alice/../bob/secret.txt`         | ❌ Normalized and clamped                 |

## Sharing Common Logic

If you need to share logic between strict and virtual paths:

```rust
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use std::io;

// One helper that works with any marker
fn process_common<M>(file: &StrictPath<M>) -> io::Result<Vec<u8>> {
    file.read()
}

// Prepare one strict file and one virtual file
let public_assets_root = PathBoundary::try_new("./assets")?;
let css_file: StrictPath = public_assets_root.strict_join("style.css")?;

let alice_uploads_root = VirtualRoot::try_new("./uploads/alice")?;
let avatar_file: VirtualPath = alice_uploads_root.virtual_join("avatar.jpg")?;

// Call with either type
let _ = process_common(&css_file)?;                   // StrictPath
let _ = process_common(avatar_file.as_unvirtual())?; // Borrow strict view from VirtualPath
```

## Integration Tips

### With Web Frameworks
```rust
// Example with axum/actix-web
async fn upload_handler(
    user_id: String,
    filename: String,
    content: Vec<u8>,
) -> Result<String, AppError> {
    let user_root = get_user_root(&user_id)?;
    let file = user_root.virtual_join(&filename)?;
    file.write(&content)?;
    Ok(file.virtualpath_display().to_string())
}
```

### With Async Runtimes
All file operations work with `tokio::fs` or `async-std` - just use `.interop_path()` when needed:
```rust
tokio::fs::write(file.interop_path(), content).await?;
```

## Next Steps

- **For Axum users**: See the [Axum Web Service Tutorial](../axum_tutorial/overview.md) for a complete 3-chapter guide with project setup, static assets, and per-user storage
- See [Multi-User Document Storage](./multi_user_storage.md) for a more complex user isolation example
- See [Type-Safe Context Separation](./type_safe_contexts.md) to learn about using markers to prevent context mixing
