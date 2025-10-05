# Stage 2: The Mix-Up Problem — When You Have Multiple Boundaries

> *"Wait, which uploads folder is this again?"*

In Stage 1, you learned that `StrictPath` guarantees paths can't escape their boundaries. Perfect! But real applications need **multiple** safe directories. That's where a new problem emerges...

## Real-World Complexity

As your app grows, you need multiple safe directories:

```rust
use strict_path::StrictPath;

fn file_server() -> Result<(), Box<dyn std::error::Error>> {
    // User uploads
    let uploads_dir = StrictPath::with_boundary_create("user_uploads")?;
    
    // Public web assets (CSS, JS, images)
    let assets_dir = StrictPath::with_boundary_create("public_assets")?;
    
    // System configuration files
    let config_dir = StrictPath::with_boundary_create("system_config")?;

    // Now we have paths from different domains...
    let user_file = uploads_dir.strict_join("document.pdf")?;
    let css_file = assets_dir.strict_join("style.css")?;
    let config_file = config_dir.strict_join("database.toml")?;

    // But they're all the same type!
    // let _: StrictPath = user_file;
    // let _: StrictPath = css_file;
    // let _: StrictPath = config_file;

    // 🚨 DANGER: Easy to mix them up!
    serve_public_asset(&user_file)?;      // Oops! Serving user upload as public asset
    save_user_upload(&config_file)?;      // Double oops! User overwrites config

    Ok(())
}

fn serve_public_asset(path: &StrictPath) -> std::io::Result<Vec<u8>> {
    path.read()  // Should only serve public assets!
}

fn save_user_upload(path: &StrictPath) -> std::io::Result<()> {
    path.write(b"user data")  // Should only write to user uploads!
}
```

## The Problem

All `StrictPath` values look the same to the compiler:
- User uploads → `StrictPath`
- Public assets → `StrictPath`
- System config → `StrictPath`

**The compiler can't help you** catch domain mix-ups. Code review is your only defense. And humans make mistakes.

## What Could Go Wrong?

Let's see the concrete dangers:

### 1. Security Leak: Private Files Exposed

```rust
use strict_path::StrictPath;

fn security_leak_example() -> Result<(), Box<dyn std::error::Error>> {
    let private_uploads = StrictPath::with_boundary_create("private_uploads")?;
    let public_site = StrictPath::with_boundary_create("public_site")?;

    // User uploads a private document
    let tax_return = private_uploads.strict_join("tax_return_2024.pdf")?;
    tax_return.write(b"Sensitive financial data")?;

    // Oops! Developer accidentally serves it from the public site handler
    serve_to_internet(&tax_return)?;  // 🚨 Private file now publicly accessible!

    Ok(())
}

fn serve_to_internet(path: &StrictPath) -> std::io::Result<()> {
    // This function should only receive public site files
    // But the compiler can't enforce that!
    println!("Serving {} to the internet...", path.strictpath_display());
    Ok(())
}
```

### 2. Data Corruption: Wrong Directory Modified

```rust
use strict_path::StrictPath;

fn data_corruption_example() -> Result<(), Box<dyn std::error::Error>> {
    let user_data = StrictPath::with_boundary_create("user_data")?;
    let system_logs = StrictPath::with_boundary_create("system_logs")?;

    let user_note = user_data.strict_join("notes.txt")?;
    let system_log = system_logs.strict_join("audit.log")?;

    // Oops! Passed the wrong path to the wrong function
    append_user_content(&system_log, "User's random thoughts")?;  // 🚨 Corrupting system log!
    append_audit_entry(&user_note, "ADMIN LOGIN")?;              // 🚨 Audit data in user file!

    Ok(())
}

fn append_user_content(path: &StrictPath, content: &str) -> std::io::Result<()> {
    // Should only receive user_data paths
    let mut existing = path.read_to_string().unwrap_or_default();
    existing.push_str(content);
    path.write(existing.as_bytes())
}

fn append_audit_entry(path: &StrictPath, entry: &str) -> std::io::Result<()> {
    // Should only receive system_logs paths
    let mut log = path.read_to_string().unwrap_or_default();
    log.push_str(&format!("[AUDIT] {}\n", entry));
    path.write(log.as_bytes())
}
```

### 3. Authorization Bypass: Wrong Permissions Applied

```rust
use strict_path::StrictPath;

fn authorization_bypass_example() -> Result<(), Box<dyn std::error::Error>> {
    let admin_files = StrictPath::with_boundary_create("admin_files")?;
    let guest_files = StrictPath::with_boundary_create("guest_files")?;

    let sensitive_config = admin_files.strict_join("secrets.toml")?;
    let public_readme = guest_files.strict_join("README.md")?;

    // Oops! Applied wrong permission check to wrong path
    allow_guest_access(&sensitive_config)?;  // 🚨 Guest can access admin secrets!
    require_admin_access(&public_readme)?;   // 🚨 Admin required for public file!

    Ok(())
}

fn allow_guest_access(path: &StrictPath) -> std::io::Result<()> {
    println!("Guest can access: {}", path.strictpath_display());
    Ok(())
}

fn require_admin_access(path: &StrictPath) -> std::io::Result<()> {
    println!("Admin required for: {}", path.strictpath_display());
    Ok(())
}
```

## Why This Happens

The problem is **type erasure**. Once you create paths from different boundaries, they all collapse to the same type:

```rust
use strict_path::StrictPath;

fn demonstrate_type_erasure() -> Result<(), Box<dyn std::error::Error>> {
    let uploads = StrictPath::with_boundary_create("uploads")?;
    let config = StrictPath::with_boundary_create("config")?;
    let cache = StrictPath::with_boundary_create("cache")?;

    let file1 = uploads.strict_join("a.txt")?;  // Type: StrictPath
    let file2 = config.strict_join("b.txt")?;   // Type: StrictPath
    let file3 = cache.strict_join("c.txt")?;    // Type: StrictPath

    // The compiler sees them all as identical
    // You can accidentally swap them and nothing will complain
    let paths = vec![file1, file2, file3];
    
    // Which path is which? The compiler doesn't know!
    for path in paths {
        // Is this uploads, config, or cache? 🤷
        println!("{}", path.strictpath_display());
    }

    Ok(())
}
```

## The Defense: Human Code Review (Fragile!)

Without compiler help, you rely on:
- ✍️ **Careful naming** — Hope developers use descriptive variable names
- 👀 **Code review** — Hope reviewers catch the mix-ups
- 📝 **Documentation** — Hope everyone reads and remembers it
- 🧪 **Testing** — Hope tests cover the edge cases

**Problem:** Humans are fallible. Mistakes slip through. Security bugs ship to production.

## Head First Moment

Imagine a hospital where **every door key looks identical**. The keys work — they're genuine hospital keys — but there's no way to know which key opens which door.

- 🔑 Operating room key? Looks like every other key.
- 🔑 Medicine cabinet key? Looks like every other key.
- 🔑 Patient records room key? Looks like every other key.

Sure, you *intend* to use the right key for the right door. But mistakes happen:
- Tired nurse grabs the wrong key ❌
- New employee doesn't know the system ❌
- Emergency situation, grab the nearest key ❌

**We need keys that physically can't open the wrong doors.**

## The Real-World Impact

These mix-ups cause real security incidents:

- **CVE-2021-XXXXX:** Web framework served user uploads from static asset handler → RCE
- **CVE-2020-XXXXX:** Config parser wrote user data to system directory → Privilege escalation
- **CVE-2019-XXXXX:** Admin dashboard mixed up user ID directories → Data leak

The pattern is always the same: **Path from Domain A used in Domain B**.

## What We Need

We need the **compiler** to distinguish between paths from different domains:

```rust
// This should compile:
serve_public_asset(&public_css_file)?;      // ✅ Correct domain

// This should NOT compile:
serve_public_asset(&private_user_file)?;    // ❌ Wrong domain — should be compile error!
```

But how? `StrictPath` already gives us boundary safety. We just need a way to teach the compiler **which boundary** a path came from...

## The Solution Preview

What if we could **label** each boundary? Give it a **name** the compiler understands?

```rust
// Pseudocode (not real syntax yet)
let uploads: StrictPath<"UserUploads"> = ...;
let assets: StrictPath<"PublicAssets"> = ...;
let config: StrictPath<"SystemConfig"> = ...;

// Now the compiler can see they're different!
fn serve_public_asset(path: &StrictPath<"PublicAssets">) { ... }

serve_public_asset(&assets)?;   // ✅ Compiles
serve_public_asset(&uploads)?;  // ❌ Compiler error: expected PublicAssets, found UserUploads
```

This is exactly what **markers** do. And that's what you'll learn in the next stage.

## Key Takeaways

🚨 **Multiple boundaries → same type → mix-ups possible**  
🚨 **Mix-ups cause security bugs** (data leaks, corruption, auth bypass)  
🚨 **Code review is fragile** — humans make mistakes  
🚨 **We need compiler enforcement** — catch errors at compile time  

## What's Next?

You've seen the problem: multiple boundaries create confusion and risk.

Now you're ready for the solution: **markers** that make the compiler your security guard.

**[Continue to Stage 3: Markers to the Rescue →](./stage3_markers.md)**
