# Chapter 3: Markers to the Rescue — Compile-Time Domain Separation

> *"Give each boundary a name the compiler understands."*

In Chapter 2, you saw how multiple boundaries create confusion — all `StrictPath` values look identical to the compiler. Now you'll learn how **markers** solve this problem by encoding domain information in the type system.

## Introducing Markers

A **marker** is a zero-cost compile-time label. It's like writing "THIS IS USER UPLOADS" directly on the type:

```rust
use strict_path::StrictPath;

// Define markers (zero runtime cost!)
struct UserUploads;
struct PublicAssets;
struct SystemConfig;
```

That's it! Three simple structs. But now watch what happens when we use them:

```rust
use strict_path::StrictPath;

struct UserUploads;
struct PublicAssets;
struct SystemConfig;

fn file_server_with_markers() -> Result<(), Box<dyn std::error::Error>> {
    // Now each boundary has a distinct type
    let uploads_dir: StrictPath<UserUploads> = 
        StrictPath::with_boundary_create("./data/user_uploads")?;
    
    let assets_dir: StrictPath<PublicAssets> = 
        StrictPath::with_boundary_create("./public/assets")?;
    
    let config_dir: StrictPath<SystemConfig> = 
        StrictPath::with_boundary_create("./config/system")?;

    // Paths inherit their marker
    let user_file = uploads_dir.strict_join("document.pdf")?;  // StrictPath<UserUploads>
    let css_file = assets_dir.strict_join("style.css")?;      // StrictPath<PublicAssets>
    let config_file = config_dir.strict_join("database.toml")?; // StrictPath<SystemConfig>

    // ✅ Correct usage
    serve_public_asset(&css_file)?;
    save_user_upload(&user_file)?;

    // ❌ Compiler errors — wrong domain!
    // serve_public_asset(&user_file)?;     // Won't compile!
    // save_user_upload(&config_file)?;     // Won't compile!

    Ok(())
}

// Functions now express their requirements in the type system
fn serve_public_asset(path: &StrictPath<PublicAssets>) -> std::io::Result<Vec<u8>> {
    path.read()  // Guaranteed: path is in public_assets/
}

fn save_user_upload(path: &StrictPath<UserUploads>) -> std::io::Result<()> {
    path.write(b"user data")  // Guaranteed: path is in user_uploads/
}
```

## What Just Happened?

1. **Zero-cost labels:** `struct UserUploads;` — empty struct, **no fields**, no runtime overhead
2. **Type-level tracking:** `StrictPath<UserUploads>` vs `StrictPath<PublicAssets>` are **different types**
3. **Compiler enforcement:** Can't pass the wrong marker to a function — **compile error**
4. **Self-documenting:** Function signatures show exactly what paths they accept

**The New Guarantee:** Not only is the path safe (Chapter 1), but the compiler **proves it's in the correct domain** (Chapter 3).

## The Compiler as Security Guard

Let's see the compiler catch mistakes:

```rust
use strict_path::StrictPath;

struct SensitiveData;
struct PublicWebsite;

fn demonstrate_compiler_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    let sensitive_dir: StrictPath<SensitiveData> = 
        StrictPath::with_boundary_create("./data/sensitive")?;
    
    let public_dir: StrictPath<PublicWebsite> = 
        StrictPath::with_boundary_create("./public")?;

    let secret_file = sensitive_dir.strict_join("passwords.txt")?;
    let css_file = public_dir.strict_join("styles.css")?;

    // ✅ This compiles — correct domain
    serve_public_file(&css_file)?;

    // ❌ This fails at compile time — wrong domain!
    // serve_public_file(&secret_file)?;
    //                   ^^^^^^^^^^^^ 
    // ERROR: expected `&StrictPath<PublicWebsite>`, 
    //        found `&StrictPath<SensitiveData>`

    Ok(())
}

fn serve_public_file(path: &StrictPath<PublicWebsite>) -> std::io::Result<()> {
    println!("Serving public file: {}", path.strictpath_display());
    Ok(())
}
```

**Before markers:** Mistake ships to production → security incident.  
**After markers:** Mistake caught at compile time → fix before commit.

## Try It Yourself

Here's a realistic example you can run:

```rust
use strict_path::StrictPath;

struct Documents;
struct Photos;
struct Music;

fn organize_media() -> Result<(), Box<dyn std::error::Error>> {
    // Create distinct boundaries
    let docs_dir: StrictPath<Documents> = StrictPath::with_boundary_create("./media/docs")?;
    let photos_dir: StrictPath<Photos> = StrictPath::with_boundary_create("./media/photos")?;
    let music_dir: StrictPath<Music> = StrictPath::with_boundary_create("./media/music")?;

    // Create files in each domain
    let report = docs_dir.strict_join("quarterly_report.pdf")?;
    let vacation = photos_dir.strict_join("beach_2024.jpg")?;
    let song = music_dir.strict_join("favorite_song.mp3")?;

    // Correct domain usage
    archive_document(&report)?;           // ✅ Works
    backup_photo(&vacation)?;             // ✅ Works
    transcode_audio(&song)?;              // ✅ Works

    // Wrong domain usage — won't compile!
    // archive_document(&vacation)?;      // ❌ Compile error
    // backup_photo(&song)?;              // ❌ Compile error
    // transcode_audio(&report)?;         // ❌ Compile error

    Ok(())
}

fn archive_document(doc: &StrictPath<Documents>) -> std::io::Result<()> {
    println!("Archiving document: {}", doc.strictpath_display());
    Ok(())
}

fn backup_photo(photo: &StrictPath<Photos>) -> std::io::Result<()> {
    println!("Backing up photo: {}", photo.strictpath_display());
    Ok(())
}

fn transcode_audio(audio: &StrictPath<Music>) -> std::io::Result<()> {
    println!("Transcoding audio: {}", audio.strictpath_display());
    Ok(())
}
```

## Markers Are Zero-Cost

Let's verify that markers have **zero runtime overhead**:

```rust
use strict_path::StrictPath;
use std::mem;

struct MyMarker;

fn demonstrate_zero_cost() {
    // Size of StrictPath with and without marker
    let size_without = mem::size_of::<StrictPath<()>>();
    let size_with = mem::size_of::<StrictPath<MyMarker>>();

    println!("StrictPath<()>: {} bytes", size_without);
    println!("StrictPath<MyMarker>: {} bytes", size_with);
    
    // They're identical! The marker is compile-time only.
    assert_eq!(size_without, size_with);
}
```

**The marker is erased at compile time.** It exists only in the type system. No runtime memory, no runtime checks, no performance cost.

## Naming Markers: Best Practices

Markers should describe **what resource is stored under the boundary**, not who accesses it:

### ✅ Good Marker Names (What is stored)

```rust
struct UserUploads;        // Stores: user-uploaded files
struct ProductImages;      // Stores: product catalog images
struct SystemLogs;         // Stores: application log files
struct ConfigFiles;        // Stores: configuration files
struct TempWorkspace;      // Stores: temporary processing files
```

### ❌ Bad Marker Names (Who accesses it)

```rust
struct AdminMarker;        // ❌ Describes user role, not storage
struct GuestAccess;        // ❌ Describes permission, not content
struct AuthorizedPath;     // ❌ Describes state, not resource
```

**Why?** Markers describe **boundaries** (physical storage locations), not **permissions** (authorization levels). We'll add permissions in Chapter 4.

## Real-World Example: Web Server

Here's how you'd structure a real web server with markers:

```rust
use strict_path::StrictPath;

// Define domains
struct StaticAssets;     // CSS, JS, images served to browsers
struct UserUploads;      // Files uploaded by users
struct TemplateFiles;    // HTML templates for rendering
struct AppLogs;          // Application logs

struct WebServer {
    static_dir: StrictPath<StaticAssets>,
    uploads_dir: StrictPath<UserUploads>,
    templates_dir: StrictPath<TemplateFiles>,
    logs_dir: StrictPath<AppLogs>,
}

impl WebServer {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            static_dir: StrictPath::with_boundary_create("./public/static")?,
            uploads_dir: StrictPath::with_boundary_create("./data/uploads")?,
            templates_dir: StrictPath::with_boundary_create("./templates")?,
            logs_dir: StrictPath::with_boundary_create("./logs")?,
        })
    }

    fn serve_static(&self, filename: &str) -> std::io::Result<Vec<u8>> {
        let asset_path = self.static_dir.strict_join(filename)?;
        serve_to_client(&asset_path)  // Type-safe: only StaticAssets
    }

    fn save_upload(&self, filename: &str, data: &[u8]) -> std::io::Result<()> {
        let upload_path = self.uploads_dir.strict_join(filename)?;
        store_user_file(&upload_path, data)  // Type-safe: only UserUploads
    }

    fn render_template(&self, template: &str) -> std::io::Result<String> {
        let tmpl_path = self.templates_dir.strict_join(template)?;
        load_template(&tmpl_path)  // Type-safe: only TemplateFiles
    }

    fn write_log(&self, entry: &str) -> std::io::Result<()> {
        let log_path = self.logs_dir.strict_join("app.log")?;
        append_log_entry(&log_path, entry)  // Type-safe: only AppLogs
    }
}

// Type-safe helper functions
fn serve_to_client(asset: &StrictPath<StaticAssets>) -> std::io::Result<Vec<u8>> {
    asset.read()
}

fn store_user_file(upload: &StrictPath<UserUploads>, data: &[u8]) -> std::io::Result<()> {
    upload.write(data)
}

fn load_template(tmpl: &StrictPath<TemplateFiles>) -> std::io::Result<String> {
    tmpl.read_to_string()
}

fn append_log_entry(log: &StrictPath<AppLogs>, entry: &str) -> std::io::Result<()> {
    let mut content = log.read_to_string().unwrap_or_default();
    content.push_str(entry);
    content.push('\n');
    log.write(content.as_bytes())
}
```

## Head First Moment

Markers are like **colored wristbands at a conference**:

- 🔵 Blue wristband → Speaker (can access speaker lounge)
- 🟢 Green wristband → Attendee (can access general sessions)
- 🔴 Red wristband → Staff (can access backstage)

**The compiler checks your wristband at every function door:**
- Function requires 🔵 blue? You need `StrictPath<Speaker>`.
- Try to enter with 🟢 green? Compile error: "Sorry, speakers only."
- Wrong color? **Access denied at compile time.**

You can't fake a wristband, and you can't sneak into the wrong area. The type system physically prevents it.

## Comparison: Before and After

### Before Markers (Chapter 2)

```rust
// ❌ All paths look the same
let user_file: StrictPath = ...;
let config_file: StrictPath = ...;
let log_file: StrictPath = ...;

// ❌ Functions can't distinguish
fn process(path: &StrictPath) { ... }

// ❌ Easy to mix up — compiler can't help
process(&config_file);  // Oops, wrong file!
```

### After Markers (Chapter 3)

```rust
// ✅ Each path has its domain encoded
let user_file: StrictPath<UserUploads> = ...;
let config_file: StrictPath<ConfigFiles> = ...;
let log_file: StrictPath<AppLogs> = ...;

// ✅ Functions express requirements
fn process_user_file(path: &StrictPath<UserUploads>) { ... }

// ✅ Compiler catches mistakes
process_user_file(&user_file);     // ✅ Correct
process_user_file(&config_file);   // ❌ Compile error!
```

## Key Takeaways

✅ **Markers = Zero-cost compile-time labels**  
✅ **`StrictPath<Marker>` = Path + domain information**  
✅ **Compiler enforces domain separation** — wrong marker = compile error  
✅ **Self-documenting code** — function signatures show requirements  
✅ **No runtime overhead** — markers are erased after compilation

## The Updated Guarantee

> **If you have a `StrictPath<Marker>`, the compiler guarantees:**
> 1. ✅ The path cannot escape its boundary (Chapter 1)
> 2. ✅ The path is in the correct domain (Chapter 3)

## What's Next?

You now know how to prevent domain mix-ups with markers. But what about **authorization**? How do you encode "this user is authorized to access this path" in the type system?

That's where things get really powerful...

**[Continue to Chapter 4: Authorization with change_marker() →](./chapter4_authorization.md)**

---

**Quick Reference:**

```rust
// Define markers
struct MyDomain;

// Create typed boundary
let boundary: StrictPath<MyDomain> = 
    StrictPath::with_boundary_create("./path")?;

// Paths inherit marker
let file = boundary.strict_join("file.txt")?;  // StrictPath<MyDomain>

// Functions enforce domain
fn process(path: &StrictPath<MyDomain>) { ... }
```
