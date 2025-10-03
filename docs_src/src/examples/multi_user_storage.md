# Multi-User Document Storage

Build a document storage system where each user feels like they have their own filesystem, complete with directory traversal prevention and user isolation.

## The Problem

Multi-user applications need to provide isolated storage where:
- ❌ Users can't access other users' files
- ❌ Path traversal attacks don't work
- ❌ Users see clean paths (like `/reports/january.pdf`) instead of system paths

## The Solution

Use `VirtualRoot` per user. Each user operates in their own sandboxed environment with clean virtual paths.

## Complete Example

```rust
use strict_path::{VirtualRoot, VirtualPath};
use std::fs;
use std::collections::HashMap;

struct DocumentStore {
    user_roots: HashMap<String, VirtualRoot>,
}

impl DocumentStore {
    fn new() -> Self {
        Self {
            user_roots: HashMap::new(),
        }
    }
    
    fn get_user_root(&mut self, username: &str) -> Result<&VirtualRoot, Box<dyn std::error::Error>> {
        if !self.user_roots.contains_key(username) {
            // Each user gets their own isolated storage
            let user_dir = format!("user_data_{}", username);
            let vroot = VirtualRoot::try_new_create(&user_dir)?;
            self.user_roots.insert(username.to_string(), vroot);
            println!("🏠 Created virtual root for user: {}", username);
        }
        
        Ok(self.user_roots.get(username).unwrap())
    }
    
    fn save_document(&mut self, username: &str, virtual_path: &str, content: &str) -> Result<VirtualPath, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        
        // User thinks they're saving to their own filesystem starting from "/"
        let doc_path = user_root.virtual_join(virtual_path)?;
        
        // Create parent directories and save
        doc_path.create_parent_dir_all()?;
        doc_path.write(content)?;
        
        println!("📝 User {username} saved document to: {}", doc_path.virtualpath_display());
        println!("    (Actually stored at: {})", doc_path.as_unvirtual().strictpath_display());
        
        Ok(doc_path)
    }
    
    fn load_document(&mut self, username: &str, virtual_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let doc_path = user_root.virtual_join(virtual_path)?;
        
        let content = doc_path.read_to_string()?;
        println!("📖 User {} loaded document from: {}", username, virtual_path);
        
        Ok(content)
    }
    
    fn list_user_documents(&mut self, username: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let mut docs = Vec::new();
        
        fn collect_files(dir: impl AsRef<std::path::Path>, base: impl AsRef<std::path::Path>, docs: &mut Vec<String>) -> std::io::Result<()> {
            let dir = dir.as_ref();
            let base = base.as_ref();
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    if let Ok(relative) = path.strip_prefix(base) {
                        if let Some(path_str) = relative.to_str() {
                            docs.push(format!("/{}", path_str.replace("\\", "/")));
                        }
                    }
                } else if path.is_dir() {
                    collect_files(&path, base, docs)?;
                }
            }
            Ok(())
        }
        
        collect_files(user_root.interop_path(), user_root.interop_path(), &mut docs)?;
        Ok(docs)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = DocumentStore::new();
    
    // Alice saves some documents
    store.save_document("alice", "/reports/quarterly.txt", "Q1 revenue was strong")?;
    store.save_document("alice", "/notes/meeting.md", "# Meeting Notes\n- Discuss new features")?;
    store.save_document("alice", "/drafts/proposal.doc", "Project proposal draft")?;
    
    // Bob saves his documents (completely separate from Alice)
    store.save_document("bob", "/code/main.rs", "fn main() { println!(\"Hello!\"); }")?;
    store.save_document("bob", "/docs/readme.txt", "My awesome project")?;
    
    // Charlie tries to access Alice's files - this is blocked at the path level
    // store.save_document("charlie", "/../alice/reports/quarterly.txt", "hacked")?;  // ❌ Blocked!
    
    // Each user can access their own files
    println!("📄 Alice's quarterly report: {}", store.load_document("alice", "/reports/quarterly.txt")?);
    println!("💻 Bob's code: {}", store.load_document("bob", "/code/main.rs")?);
    
    // List each user's documents
    println!("📁 Alice's documents: {:?}", store.list_user_documents("alice")?);
    println!("📁 Bob's documents: {:?}", store.list_user_documents("bob")?);
    
    Ok(())
}
```

## Key Security Features

### 1. Lazy User Root Creation
```rust
fn get_user_root(&mut self, username: &str) -> Result<&VirtualRoot, ...>
```
Each user gets their own `VirtualRoot` created on first access. Users are completely isolated from each other.

### 2. Virtual Path Display
```rust
doc_path.virtualpath_display()    // Shows: "/reports/quarterly.txt"
doc_path.strictpath_display()     // Shows: "user_data_alice/reports/quarterly.txt"
```
Users see clean paths starting from `/`, while the system maintains real paths.

### 3. Automatic Isolation
```rust
store.save_document("charlie", "/../alice/reports/quarterly.txt", "hacked")?;
```
This is automatically blocked because `/../alice/...` gets clamped to Charlie's root.

### 4. Cross-User Access Prevention
Even if you try:
```rust
let alice_root = store.get_user_root("alice")?;
let bob_root = store.get_user_root("bob")?;

// These are completely separate - no way to cross boundaries
let alice_doc = alice_root.virtual_join("/secret.txt")?;
let bob_doc = bob_root.virtual_join("/secret.txt")?;

// alice_doc and bob_doc point to different physical files
```

## Attack Scenarios Prevented

| Attack                                             | Result                     |
| -------------------------------------------------- | -------------------------- |
| `save_document("alice", "/../bob/data.txt", ...)`  | ❌ Clamped to alice's root  |
| `save_document("alice", "/../../etc/passwd", ...)` | ❌ Clamped to alice's root  |
| `load_document("bob", "/../alice/secret.txt")`     | ❌ Clamped to bob's root    |
| Symlink to another user's directory                | ❌ Resolved within boundary |

## System Path vs Virtual Path

Understanding the difference:

```rust
let alice_root = VirtualRoot::try_new_create("user_data_alice")?;
let doc = alice_root.virtual_join("/reports/january.pdf")?;

// What the user sees:
println!("{}", doc.virtualpath_display());
// Output: /reports/january.pdf

// What the system uses:
println!("{}", doc.as_unvirtual().strictpath_display());
// Output: user_data_alice/reports/january.pdf

// Both point to the same file, just different representations
```

## Integration Tips

### With Databases
Store virtual paths in the database:
```rust
struct Document {
    id: i64,
    user_id: i64,
    virtual_path: String,  // "/reports/january.pdf"
    created_at: DateTime,
}

// When retrieving:
let user_root = get_user_root(user_id)?;
let doc_path = user_root.virtual_join(&doc.virtual_path)?;
let content = doc_path.read()?;
```

### With Web Frameworks
```rust
async fn get_document(
    user_id: String,
    path: String,
) -> Result<Vec<u8>, AppError> {
    let user_root = get_user_root(&user_id)?;
    let doc = user_root.virtual_join(&path)?;
    Ok(doc.read()?)
}

async fn save_document(
    user_id: String,
    path: String,
    content: Vec<u8>,
) -> Result<String, AppError> {
    let user_root = get_user_root(&user_id)?;
    let doc = user_root.virtual_join(&path)?;
    doc.create_parent_dir_all()?;
    doc.write(&content)?;
    Ok(doc.virtualpath_display().to_string())
}
```

### With Shared Helpers
Share logic between users by accepting `&StrictPath`:
```rust
fn analyze_document<M>(path: &StrictPath<M>) -> Result<DocumentStats, Error> {
    let content = path.read_to_string()?;
    Ok(DocumentStats {
        lines: content.lines().count(),
        words: content.split_whitespace().count(),
    })
}

// Works for any user:
let alice_doc = alice_root.virtual_join("/report.txt")?;
let bob_doc = bob_root.virtual_join("/notes.txt")?;

let alice_stats = analyze_document(alice_doc.as_unvirtual())?;
let bob_stats = analyze_document(bob_doc.as_unvirtual())?;
```

## Advanced: Quota Management

Track storage per user:
```rust
impl DocumentStore {
    fn get_user_storage_size(&self, username: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let user_root = self.user_roots.get(username)
            .ok_or("User not found")?;
        
        let mut total_size = 0u64;
        for entry in walkdir::WalkDir::new(user_root.interop_path()) {
            let entry = entry?;
            if entry.file_type().is_file() {
                total_size += entry.metadata()?.len();
            }
        }
        
        Ok(total_size)
    }
    
    fn check_quota(&self, username: &str, quota: u64) -> Result<bool, Box<dyn std::error::Error>> {
        let used = self.get_user_storage_size(username)?;
        Ok(used < quota)
    }
}
```

## Performance Considerations

1. **Cache user roots** - Store `VirtualRoot` instances to avoid repeated creation
2. **Lazy initialization** - Only create directories when first accessed
3. **Batch operations** - Group multiple file operations together
4. **Use async I/O** - All paths work with `tokio::fs` via `.interop_path()`

## Best Practices

1. **One root per user** - Never share `VirtualRoot` between users
2. **Store virtual paths** - Save virtual paths in your database, not system paths
3. **Display virtual paths** - Show users virtual paths (starting with `/`)
4. **Use system paths for I/O** - Use `.as_unvirtual()` when calling file operations

## Next Steps

- See [Web Upload Service](./web_upload_service.md) for a simpler upload-only example
- See [Type-Safe Context Separation](./type_safe_contexts.md) to learn about using markers for different document types
