# "One Small Generic for Marker, One Giant Leap for StrictPath"
## Unlocking Extra Security Powers

Let’s build this up the way real apps grow: start with “one safe folder,” add a second one, teach the compiler the difference with markers, fold in auth, and finish with clean virtual sandboxes. Short, practical, and copy‑pasteable.

Tip: When a folder may not exist yet, use `with_boundary_create` / `with_root_create`. When you know it exists, `with_boundary` / `with_root` is fine.

## 1) The humble beginning: one safe folder

```rust
use strict_path::StrictPath;
use std::io::Result;

fn basic_file_server() -> Result<()> {
    let uploads = StrictPath::with_boundary_create("./uploads")?;

    let file = uploads.strict_join("document.txt")?;
    file.create_parent_dir_all()?;
    file.write("Hello, secure world!")?;

    println!("{}", file.strictpath_display());
    Ok(())
}
```

## 2) Growing pains: now you have two

```rust
use strict_path::StrictPath;
use std::io::Result;

fn multi_area() -> Result<()> {
    let user_uploads = StrictPath::with_boundary_create("./uploads")?;
    let system_config = StrictPath::with_boundary_create("./config")?;

    let user_file = user_uploads.strict_join("user_document.txt")?;
    let config_file = system_config.strict_join("app.toml")?;

    // Oops risk: both are StrictPath<()> — easy to mix up.
    // process_user_file(&config_file)?; // would compile with a loose signature
    Ok(())
}

fn process_user_file(file: &StrictPath) -> Result<()> {
    file.write("User data")?;
    Ok(())
}
```

## 3) Markers to the rescue: give folders a name the compiler understands

```rust
use strict_path::StrictPath;
use std::io::Result;

struct UserUploads;
struct SystemConfig;

fn safer_multi_area() -> Result<()> {
    let user_uploads: StrictPath<UserUploads> = StrictPath::with_boundary_create("./uploads")?;
    let system_config: StrictPath<SystemConfig> = StrictPath::with_boundary_create("./config")?;

    let user_file = user_uploads.strict_join("user_document.txt")?;
    let config_file = system_config.strict_join("app.toml")?;

    handle_user_file(&user_file)?;            // ✅ OK
    // handle_user_file(&config_file)?;      // ❌ Won’t compile
    Ok(())
}

fn handle_user_file(file: &StrictPath<UserUploads>) -> Result<()> {
    file.write("User data")
}
```

The wrong path in the wrong place is now a compile error, not a code review comment.

## 4) Make it official: require auth to get certain paths

```rust
use strict_path::StrictPath;
use std::io::Result;
use std::path::Path;

struct PublicAssets;
struct AdminConfig; // must be authenticated to obtain

impl AdminConfig {
    pub fn create_boundary<P: AsRef<Path>>(p: P, _token: ValidatedAdminToken) -> Result<StrictPath<AdminConfig>> {
        StrictPath::with_boundary_create(p)
    }
}

struct ValidatedAdminToken { user_id: String }

impl ValidatedAdminToken {
    pub fn authenticate(u: &str, p: &str) -> Option<Self> {
        (u == "admin" && p == "secret").then(|| Self { user_id: u.into() })
    }
}

fn auth_flow() -> Result<()> {
    let _public: StrictPath<PublicAssets> = StrictPath::with_boundary_create("./public")?;

    let token = ValidatedAdminToken::authenticate("admin", "secret")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "auth failed"))?;

    let admin_root = AdminConfig::create_boundary("./admin", token)?;
    read_admin(&admin_root)?;
    write_admin(&admin_root)?;
    Ok(())
}

fn read_admin(root: &StrictPath<AdminConfig>) -> Result<String> {
    root.strict_join("settings.toml")?.read_to_string()
}

fn write_admin(root: &StrictPath<AdminConfig>) -> Result<()> {
    root.strict_join("system.toml")?.write("debug=true")
}
```

If a function takes `&StrictPath<AdminConfig>`, the caller must have authenticated earlier. Simple.

## 5) Permissions as types: combining domain + permission

```rust
use strict_path::StrictPath;
use std::io::Result;

struct UserFiles;
struct SystemFiles;
struct ReadOnly;       // Can only read
struct ReadWrite;      // Can read and write (supersedes ReadOnly)
struct AdminAccess;    // Full control (supersedes ReadWrite)

fn view_profile(p: &StrictPath<(UserFiles, ReadOnly)>) -> Result<String> {
    p.strict_join("profile.json")?.read_to_string()
}

fn update_settings(p: &StrictPath<(UserFiles, ReadWrite)>) -> Result<()> {
    p.strict_join("settings.json")?.write("{\"theme\":\"dark\"}")
}

fn edit_system(p: &StrictPath<(SystemFiles, AdminAccess)>) -> Result<()> {
    p.strict_join("system.conf")?.write("safe=true")
}
```

Use tuples to combine domain (what's stored) with permission level (what's allowed). The tuple `(Domain, Permission)` makes your security model explicit in the type signature.

## 6) Rebranding and sub‑roots: “this folder is now its own root”

```rust
use strict_path::{PathBoundary, StrictPath};
use std::io::Result;

struct MainStorage;
struct UserData;
struct ProjectFiles;

fn marker_transformation() -> Result<()> {
    let storage: PathBoundary<MainStorage> = PathBoundary::try_new_create("./storage")?;

    // Create a new boundary for the same directory with different marker
    let users_area: PathBoundary<UserData> = PathBoundary::try_new("./storage")?;

    // Turn a subfolder into its own boundary
    let alice: StrictPath<UserData> = users_area.strict_join("users/alice")?;
    alice.create_dir_all()?;
    
    // After authorization check, change the marker on the path, then convert to boundary
    let alice_authorized: StrictPath<ProjectFiles> = alice.change_marker();
    let projects: PathBoundary<ProjectFiles> = alice_authorized.try_into_boundary()?;

    projects.strict_join("README.md")?.write("# Project")?;
    Ok(())
}
```

Use `change_marker()` after authorization to attach a new marker to an already-validated path.

## 7) Virtual views: clean “/” for users, same safety underneath

```rust
use strict_path::VirtualPath;
use std::io::Result;

struct TenantWorkspace;

fn virtual_space() -> Result<()> {
    let root: VirtualPath<TenantWorkspace> = VirtualPath::with_root_create("./tenants/acme/workspace")?;

    let doc = root.virtual_join("/projects/app/src/main.rs")?;
    doc.create_parent_dir_all()?;
    doc.write("fn main() { println!(\"hi\"); }")?;

    println!("User sees: {}", doc.virtualpath_display());
    println!("Stored at: {}", doc.as_unvirtual().strictpath_display());
    Ok(())
}
```

Great for multi‑tenant storage, per‑user sandboxes, and container filesystems.

## 8) One helper, two worlds (`as_unvirtual()`)

Write helpers for `&StrictPath<M>` and call them with either a `StrictPath` or a borrowed view from a `VirtualPath`.

```rust
use strict_path::{StrictPath, VirtualPath};
use std::io::{Read, Result};

struct MediaLibrary;

fn sniff(file: &StrictPath<MediaLibrary>) -> Result<String> {
    let meta = file.metadata()?;
    let mut fh = file.open_file()?;
    let mut header = [0u8; 4];
    let _ = (&mut fh).read(&mut header)?;
    Ok(format!("{} bytes, magic: {:x?}", meta.len(), &header))
}

fn demo() -> Result<()> {
    let strict: StrictPath<MediaLibrary> = StrictPath::with_boundary_create("./storage/media")?;
    let input = strict.strict_join("in/video.mp4")?;

    let vroot: VirtualPath<MediaLibrary> = VirtualPath::with_root_create("./public/media")?;
    let pretty = vroot.virtual_join("processed/out.mp3")?;

    println!("{}", sniff(&input)?);                 // StrictPath
    println!("{}", sniff(pretty.as_unvirtual())?);  // VirtualPath -> borrow strict view
    Ok(())
}
```

Short, clear, and hard to misuse.

---

## Marker chapter (at a glance)

- Name by domain: `struct PublicAssets;`, `struct UserUploads;` — functions take `&StrictPath<Domain>`.
- Put auth in the constructor: return a domain type only after validation.
- Model permissions with small, flat tuples: `(Domain, ReadOnly)` or `(Domain, AdminAccess)`.
- Use `change_marker()` on paths after authorization to attach new markers. Conversions preserve markers automatically.

---

That’s it: one small generic for Marker, one giant leap for StrictPath.

