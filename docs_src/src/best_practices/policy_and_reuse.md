# Policy & Reuse Patterns

> *Why VirtualRoot and PathBoundary matter for correctness, performance, and maintainability.*

The sugar constructors (`StrictPath::with_boundary(..)`, `VirtualPath::with_root(..)`) are great for simple flows, but the root/boundary types still matter as your code grows. This chapter explains when and why to use them.

---

## The Core Insight

**Roots/boundaries represent security policy** (the restriction), while paths represent validated values within that policy.

This separation enables:
- **Policy reuse** without repeated validation
- **Clear function signatures** that encode guarantees
- **Performance optimization** through canonicalization caching
- **Better testing** with injectable boundaries
- **Explicit deserialization** with serde seeds

---

## Policy Reuse and Separation of Concerns

### Anti-Pattern: Reconstructing Policy

```rust
use strict_path::PathBoundary;

// ❌ BAD: Reconstructing boundary for every file
fn process_files(base_path: &str, filenames: &[String]) -> std::io::Result<()> {
    for name in filenames {
        let boundary = PathBoundary::try_new(base_path)?; // Repeated canonicalization!
        let file = boundary.strict_join(name)?;
        file.write(b"data")?;
    }
    Ok(())
}
```

**Problems:**
- Canonicalizes the same base path repeatedly (performance waste)
- Hides policy choice inside the helper (reviewability issue)
- Hard to test with different boundaries (testability issue)

### Better: Policy Reuse

```rust
use strict_path::PathBoundary;

// ✅ GOOD: Construct policy once, reuse everywhere
fn process_files(boundary: &PathBoundary, filenames: &[String]) -> std::io::Result<()> {
    for name in filenames {
        let file = boundary.strict_join(name)?; // Reuses canonicalized boundary
        file.write(b"data")?;
    }
    Ok(())
}

// Usage: Policy choice explicit at call site
fn main() -> std::io::Result<()> {
    let uploads = PathBoundary::try_new("./uploads")?;
    let files = vec!["a.txt".to_string(), "b.txt".to_string()];
    
    process_files(&uploads, &files)?; // Clear what boundary is being used
    Ok(())
}
```

**Benefits:**
- Canonicalizes once, reuses for all operations
- Policy choice visible at call site
- Easy to inject test boundaries
- Reviewers see security decisions explicitly

**Key insight**: Don't construct boundaries inside helpers — boundary choice is policy; encoding it at call sites improves reviewability and testing.

---

## Clear Function Signatures (Stronger Guarantees)

Two canonical patterns make intent obvious:

### Pattern 1: Accept Validated Path

**When to use**: Validation already happened at the call site.

```rust
use strict_path::StrictPath;

fn write_report(report_file: &StrictPath) -> std::io::Result<()> {
    // Guaranteed: path is already validated
    // No validation needed inside this function
    report_file.write(b"report data")
}
```

**Benefits:**
- Function signature proves validation happened
- No redundant validation inside
- Clear contract: "I only accept validated paths"

### Pattern 2: Accept Boundary + Segment

**When to use**: Validation happens inside the helper.

```rust
use strict_path::PathBoundary;

fn load_config(config_dir: &PathBoundary, name: &str) -> std::io::Result<String> {
    // Validation happens inside this function
    config_dir.strict_join(name)?.read_to_string()
}
```

**Benefits:**
- Helper performs validation explicitly
- Reuses provided boundary (no policy choice inside)
- Clear contract: "I validate against your boundary"

### Usage Example: Patterns in Context

```rust
use strict_path::{PathBoundary, StrictPath};

fn example_workflow() -> std::io::Result<()> {
    let reports_dir = PathBoundary::try_new("reports")?;
    let config_dir = PathBoundary::try_new("config")?;
    
    // Pattern 1: Validation at call site
    let report = reports_dir.strict_join("q4_2025.pdf")?;
    write_report(&report)?; // Function knows it's validated
    
    // Pattern 2: Validation inside helper
    let settings = load_config(&config_dir, "app.toml")?;
    
    Ok(())
}

fn write_report(report_file: &StrictPath) -> std::io::Result<()> {
    report_file.write(b"report data")
}

fn load_config(config_dir: &PathBoundary, name: &str) -> std::io::Result<String> {
    config_dir.strict_join(name)?.read_to_string()
}
```

**Key insight**: Signatures prevent helpers from "picking a root" silently, making security rules visible in code review.

---

## Contextual Deserialization (Serde)

`StrictPath`/`VirtualPath` **can't** implement blanket `Deserialize` safely—they need runtime context (the boundary/root) to validate.

### The Problem

```rust,no_run
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    name: String,
    // path: StrictPath, // ❌ Won't compile - no context for validation!
}
```

### Solution 1: Deserialize Then Validate

```rust,no_run
use strict_path::{PathBoundary, StrictPath};
use serde::Deserialize;

#[derive(Deserialize)]
struct RawConfig {
    name: String,
    path: String, // Deserialize as string first
}

fn load_safe_config(json: &str) -> Result<StrictPath, Box<dyn std::error::Error>> {
    let config_dir = PathBoundary::try_new("./configs")?;
    
    // 1. Deserialize raw data
    let raw: RawConfig = serde_json::from_str(json)?;
    
    // 2. Validate against boundary
    let safe_path = config_dir.strict_join(&raw.path)?;
    
    Ok(safe_path)
}
```

### Solution 2: Serde Seeds (Advanced)

```rust,no_run
#[cfg(feature = "serde")]
use strict_path::{PathBoundary, StrictPath, serde_ext};

#[cfg(feature = "serde")]
fn deserialize_with_seed(
    json: &str,
    boundary: &PathBoundary
) -> Result<StrictPath, Box<dyn std::error::Error>> {
    // Seed provides validation context
    let seed = serde_ext::WithBoundary(boundary);
    let safe_path: StrictPath = serde_json::from_str(json)?;
    Ok(safe_path)
}
```

**Key insight**: Deserialization is explicit and auditable—where did the policy come from? What are we validating against?

---

## Performance and Canonicalization

Canonicalize the root once; strict/virtual joins reuse that canonicalized state.

### Performance Anti-Pattern

```rust
use strict_path::PathBoundary;

fn slow_approach(files: &[String]) -> std::io::Result<()> {
    // ❌ SLOW: Canonicalizes base path 1000 times
    for name in files {
        let boundary = PathBoundary::try_new("./data")?; // Filesystem call every time!
        let _file = boundary.strict_join(name)?;
    }
    Ok(())
}
```

### Performance Optimization

```rust
use strict_path::PathBoundary;

fn fast_approach(files: &[String]) -> std::io::Result<()> {
    // ✅ FAST: Canonicalizes base path once, reuses for all joins
    let boundary = PathBoundary::try_new("./data")?; // Single filesystem call
    
    for name in files {
        let _file = boundary.strict_join(name)?; // Reuses canonical state
    }
    
    Ok(())
}
```

### Benchmark Comparison

```rust,no_run
use strict_path::PathBoundary;

fn benchmark_comparison() -> std::io::Result<()> {
    let files: Vec<String> = (0..1000).map(|i| format!("file{i}.txt")).collect();
    
    // Slow: ~1000 canonicalization calls
    for name in &files {
        let boundary = PathBoundary::try_new("./data")?;
        let _ = boundary.strict_join(name)?;
    }
    
    // Fast: 1 canonicalization call + 1000 cheap joins
    let boundary = PathBoundary::try_new("./data")?;
    for name in &files {
        let _ = boundary.strict_join(name)?;
    }
    
    Ok(())
}
```

**Performance benefit**: Virtual joins use anchored canonicalization to apply virtual semantics safely and consistently without repeated filesystem calls.

---

## Auditability and Testing

Centralizing policy in a root value simplifies logging, tracing, and tests.

### Testable Helper

```rust
use strict_path::PathBoundary;

// Easy to inject test boundaries
fn save_user_data(
    uploads_dir: &PathBoundary,
    filename: &str,
    data: &[u8]
) -> std::io::Result<()> {
    let file = uploads_dir.strict_join(filename)?;
    file.create_parent_dir_all()?;
    file.write(data)
}
```

### Testing with Injected Boundaries

```rust,no_run
use strict_path::PathBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_with_temp_boundary() -> std::io::Result<()> {
        // Create test boundary
        let temp_dir = std::env::temp_dir().join("test_uploads");
        std::fs::create_dir_all(&temp_dir)?;
        let boundary = PathBoundary::try_new(&temp_dir)?;
        
        // Test with injected boundary
        save_user_data(&boundary, "test.txt", b"data")?;
        
        // Verify
        let file = boundary.strict_join("test.txt")?;
        assert_eq!(file.read()?, b"data");
        
        // Cleanup
        std::fs::remove_dir_all(&temp_dir)?;
        Ok(())
    }
    
    #[test]
    fn test_rejects_escapes() {
        let boundary = PathBoundary::try_new(".").unwrap();
        
        // Verify security properties
        assert!(save_user_data(&boundary, "../../../etc/passwd", b"data").is_err());
    }
}
```

**Testing benefits:**
- Pass `&boundary` into helpers for easy mocking
- Test with different boundaries (temp dirs, test fixtures)
- Verify security properties with escape attempt tests
- No need to mock filesystem for unit tests

**Debug verbosity**: `VirtualPath::Debug` is intentionally verbose (system path + virtual view + restriction root + marker) to aid audits and troubleshooting.

---

## When Not to Use Policy Types

If your flow is small, local, and won't be reused, the sugar constructors are perfectly fine:

```rust
use strict_path::StrictPath;

// ✅ Fine for simple, one-off operations
fn quick_write() -> std::io::Result<()> {
    let file = StrictPath::with_boundary_create("./temp")?
        .strict_join("quick.txt")?;
    file.write(b"data")
}
```

**Rule of thumb**: Start with sugar; upgrade to `PathBoundary`/`VirtualRoot` when you need:
- Policy reuse across multiple operations
- Performance optimization (many joins against same root)
- Serde integration with contextual deserialization
- Testability with injectable boundaries
- Shared helpers that accept boundaries

---

## Summary: When to Use What

| Scenario                         | Use Sugar Constructor       | Use Policy Type              |
| -------------------------------- | --------------------------- | ---------------------------- |
| **One-off file operation**       | ✅ `with_boundary()`         | Optional                     |
| **Multiple joins against root**  | ⚠️ Suboptimal                | ✅ `PathBoundary`             |
| **Reusable helper functions**    | ❌ Hidden policy choice      | ✅ Accept `&PathBoundary`     |
| **Performance-critical loops**   | ❌ Repeated canonicalization | ✅ Canonicalize once          |
| **Serde deserialization**        | ❌ No validation context     | ✅ Use serde seeds            |
| **Testing with mock boundaries** | ❌ Hard to inject            | ✅ Pass `&PathBoundary` param |
| **Simple scripts/prototypes**    | ✅ Quick and ergonomic       | Optional                     |

---

## Learn More

- **[Best Practices Overview →](../best_practices.md)** - Core guidelines and decision matrices
- **[Real-World Patterns →](./real_world_patterns.md)** - Production examples showing policy reuse
- **[Common Operations →](./common_operations.md)** - How to use paths after validation
- **[Authorization Patterns →](./authorization_architecture.md)** - Markers for compile-time authorization

