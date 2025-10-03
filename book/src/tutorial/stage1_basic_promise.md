# Stage 1: The Basic Promise — Paths That Can't Escape

> *"Give me one untrusted filename, and I'll show you a safe filesystem operation."*

## The Problem

You're building a web service. Users upload files. Simple, right? **Wrong.**

```rust
// ❌ DISASTER WAITING TO HAPPEN
fn save_user_upload(filename: &str, data: &[u8]) -> std::io::Result<()> {
    let path = format!("uploads/{}", filename);
    std::fs::write(path, data)?;  // filename could be "../../../etc/passwd"
    Ok(())
}
```

**What just happened?** If `filename = "../../../etc/passwd"`, you just gave an attacker write access to your entire filesystem. Game over.

## The Solution: StrictPath

`StrictPath` makes escapes **mathematically impossible**. Here's the same code, but safe:

```rust
use strict_path::StrictPath;

fn save_user_upload(filename: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Create a boundary — the perimeter fence
    let uploads_boundary = StrictPath::with_boundary_create("uploads")?;

    // Validate the untrusted filename
    let safe_path = uploads_boundary.strict_join(filename)?;  // ✅ Attack = Error

    // Now we can safely write
    safe_path.write(data)?;

    Ok(())
}
```

## What Changed?

1. **`with_boundary_create("uploads")`** — Sets up a security perimeter at `./uploads/`
2. **`strict_join(filename)`** — Validates that `filename` stays inside the boundary
   - Valid: `"report.txt"` → `./uploads/report.txt` ✅
   - Valid: `"docs/report.txt"` → `./uploads/docs/report.txt` ✅
   - Attack: `"../../../etc/passwd"` → **Error** ❌
3. **`safe_path.write(data)`** — Built-in I/O helpers that work directly on `StrictPath`

**The guarantee:** If you have a `StrictPath`, it's **impossible** for it to reference anything outside its boundary. Not "we validated it" — **impossible by construction**.

## Try It Yourself

```rust
use strict_path::StrictPath;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the boundary
    let data_dir = StrictPath::with_boundary_create("user_data")?;

    // These all work fine
    let file1 = data_dir.strict_join("notes.txt")?;
    let file2 = data_dir.strict_join("projects/rust/main.rs")?;
    let file3 = data_dir.strict_join("deeply/nested/structure/file.json")?;

    println!("✅ Safe: {}", file1.strictpath_display());
    println!("✅ Safe: {}", file2.strictpath_display());
    println!("✅ Safe: {}", file3.strictpath_display());

    // This would fail at runtime with an error
    // let evil = data_dir.strict_join("../../../etc/passwd")?;  // ❌ PathEscapesBoundary

    Ok(())
}
```

## The Core Promise

> **If you have a `StrictPath`, it is impossible for it to escape its boundary.**

This isn't validation — it's a **type-level guarantee**. The security is in the types, enforced by Rust's compiler.

## Understanding the Boundary

Think of a `StrictPath` like a **smart pointer with memory** of where it came from:

```rust
use strict_path::StrictPath;

fn demonstrate_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let uploads = StrictPath::with_boundary_create("uploads")?;
    
    // Every path remembers its boundary
    let doc = uploads.strict_join("document.pdf")?;
    let img = uploads.strict_join("images/photo.jpg")?;
    
    // Both carry a mathematical proof: "I'm inside uploads/"
    // The compiler enforces this guarantee
    
    Ok(())
}
```

**Head First Moment:** Think of `StrictPath` like a smart pointer that remembers its boundary. Once created, it carries a mathematical proof: "I'm inside the fence." The compiler won't let you break that promise.

## What About Edge Cases?

**Q: What if the user provides `"../../etc/passwd"`?**  
A: `strict_join()` returns an error. The path is never created.

**Q: What about symlinks that escape?**  
A: `strict-path` resolves symlinks during validation. If a symlink points outside the boundary, you get an error.

**Q: What about Windows 8.3 short names (`PROGRA~1`)?**  
A: Caught and rejected. We validate against all known path aliasing attacks.

**Q: What about NTFS Alternate Data Streams (`file.txt:hidden`)?**  
A: Normalized and handled safely. No escapes possible.

**Q: Is this just string validation?**  
A: No! This is full canonicalization with filesystem resolution. We handle symlinks, junctions, mounts, and all platform quirks.

See [Security Methodology](../security_methodology.md) for the complete list of 19+ CVEs we've tested against.

## Common Operations

Once you have a `StrictPath`, you can perform filesystem operations directly:

```rust
use strict_path::StrictPath;

fn file_operations() -> Result<(), Box<dyn std::error::Error>> {
    let storage = StrictPath::with_boundary_create("storage")?;
    let file = storage.strict_join("data.txt")?;

    // Write
    file.write(b"Hello, world!")?;

    // Read
    let content = file.read_to_string()?;
    println!("Content: {}", content);

    // Check metadata
    let metadata = file.metadata()?;
    println!("Size: {} bytes", metadata.len());

    // Create parent directories
    let nested = storage.strict_join("deep/nested/file.txt")?;
    nested.create_parent_dir_all()?;
    nested.write(b"Nested content")?;

    // Remove file
    file.remove_file()?;

    Ok(())
}
```

## Key Takeaways

✅ **`StrictPath` = Mathematical boundary guarantee**  
✅ **Attack paths fail explicitly at validation time**  
✅ **Works with any untrusted input** (user input, config files, LLM output, archive entries)  
✅ **Built-in I/O helpers** — no need to convert to `Path` for common operations  
✅ **Handles edge cases** — symlinks, Windows quirks, encoding tricks, etc.

## What's Next?

You now understand the **basic promise**: paths cannot escape their boundaries.

But what happens when your app grows and you need **multiple** safe directories? That's where things get confusing...

**[Continue to Stage 2: The Mix-Up Problem →](./stage2_mixup_problem.md)**

---

**Quick Reference:**

```rust
// Create boundary
let boundary = StrictPath::with_boundary_create("safe_dir")?;

// Validate untrusted input
let safe_path = boundary.strict_join(untrusted_filename)?;

// Perform I/O
safe_path.write(data)?;
let content = safe_path.read_to_string()?;
```
