# Generic Functions and Marker Patterns

Learn how to write reusable functions that work with any marker type using Rust's generics.

## The `<M>` Pattern

When you write `<M>`, you're saying "this function works with paths of **any** marker type."

```rust
use strict_path::StrictPath;

// ✅ Generic: works with any marker
fn get_size<M>(path: &StrictPath<M>) -> std::io::Result<u64> {
    Ok(path.metadata()?.len())
}

// Can call with any marker type
let config: StrictPath<ConfigDir> = ...;
let uploads: StrictPath<UserUploads> = ...;

let config_size = get_size(&config)?;   // M = ConfigDir
let upload_size = get_size(&uploads)?;  // M = UserUploads
```

## When to Use Generic Functions

**Use `<M>` when:**
- Function logic doesn't care about the specific marker
- You're building reusable utilities
- The operation applies to any path type

**Use specific markers when:**
- Function requires specific authorization level
- Business logic depends on path context
- Type safety prevents mixing different domains

## Common Generic Patterns

### Pattern 1: Generic Helpers

```rust
/// Read and parse JSON from any path
fn read_json<M, T: serde::de::DeserializeOwned>(
    path: &StrictPath<M>
) -> Result<T, Box<dyn std::error::Error>> {
    let contents = path.read_to_string()?;
    Ok(serde_json::from_str(&contents)?)
}

// Works with any marker
let config: Config = read_json(&config_path)?;
let data: UserData = read_json(&user_path)?;
```

### Pattern 2: Generic Validation

```rust
/// Ensure path exists and is a file
fn validate_file<M>(path: &StrictPath<M>) -> std::io::Result<()> {
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", path.strictpath_display())
        ));
    }
    
    if !path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Path is not a file"
        ));
    }
    
    Ok(())
}
```

### Pattern 3: Generic Logging

```rust
use tracing::info;

/// Log path access for audit trail
fn log_access<M>(path: &StrictPath<M>, operation: &str) {
    info!(
        operation = operation,
        path = %path.strictpath_display(),
        "Path accessed"
    );
}

// Use in your code
log_access(&user_file, "read");
```

### Pattern 4: Generic Directory Processing

```rust
/// Count files in directory
fn count_files<M>(dir: &StrictPath<M>) -> std::io::Result<usize> {
    let mut count = 0;
    
    for entry in dir.read_dir()? {
        let entry = entry?;
        if entry.metadata()?.is_file() {
            count += 1;
        }
    }
    
    Ok(count)
}
```

## Specific Marker Functions

Sometimes you want **exactly** the right marker type:

```rust
struct UserData;
struct ConfigDir;

// ✅ Only accepts UserData paths
fn process_user_file(file: &StrictPath<UserData>) -> Result<(), Box<dyn std::error::Error>> {
    let contents = file.read_to_string()?;
    // Process user-specific data
    Ok(())
}

// ✅ Only accepts ConfigDir paths
fn load_config(config: &StrictPath<ConfigDir>) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let contents = config.read_to_string()?;
    Ok(toml::from_str(&contents)?)
}

// ❌ Won't compile: wrong marker type
let user_file: StrictPath<UserData> = ...;
load_config(&user_file); // ERROR: expected ConfigDir, found UserData
```

## Generic VirtualPath Functions

The same patterns work for `VirtualPath`:

```rust
use strict_path::VirtualPath;

/// Generic file writer
fn write_log<M>(path: &VirtualPath<M>, message: &str) -> std::io::Result<()> {
    path.create_parent_dir_all()?;
    path.write(format!("[{}] {}\n", chrono::Utc::now(), message))
}

/// Generic directory validator
fn ensure_directory<M>(path: &VirtualPath<M>) -> std::io::Result<()> {
    if !path.exists() {
        path.create_dir_all()?;
    } else if !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Path exists but is not a directory"
        ));
    }
    Ok(())
}
```

## Passing Paths Through Call Chains

### Generic Chain

```rust
// Generic all the way down
fn read_data<M>(path: &StrictPath<M>) -> std::io::Result<Vec<u8>> {
    validate_file(path)?;           // Generic
    log_access(path, "read");        // Generic
    path.read()                      // Read the file
}
```

### Specific Chain

```rust
struct TenantData;

// Specific markers maintained through chain
fn load_tenant_data(path: &StrictPath<TenantData>) -> Result<Data, Error> {
    validate_tenant_path(path)?;     // Takes StrictPath<TenantData>
    parse_tenant_data(path)?;        // Takes StrictPath<TenantData>
    decrypt_tenant_data(path)        // Takes StrictPath<TenantData>
}

// Each function in chain requires TenantData marker
fn validate_tenant_path(path: &StrictPath<TenantData>) -> Result<(), Error> { ... }
fn parse_tenant_data(path: &StrictPath<TenantData>) -> Result<(), Error> { ... }
fn decrypt_tenant_data(path: &StrictPath<TenantData>) -> Result<Data, Error> { ... }
```

## Returning Generic Paths

You can return paths with preserved markers:

```rust
use strict_path::PathBoundary;

/// Find config file in directory
fn find_config<M>(dir: &PathBoundary<M>) -> Option<StrictPath<M>> {
    for entry in dir.read_dir().ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        
        if name.to_string_lossy().ends_with(".conf") {
            return dir.strict_join(&name).ok();
        }
    }
    None
}

// Marker type flows through
let config_dir: PathBoundary<ConfigDir> = ...;
let found: Option<StrictPath<ConfigDir>> = find_config(&config_dir);
```

## Generic with Constraints

You can constrain markers with trait bounds:

```rust
/// Marker must implement Send + Sync
fn parallel_process<M: Send + Sync>(
    paths: Vec<StrictPath<M>>
) -> Vec<std::io::Result<String>> {
    use rayon::prelude::*;
    
    paths.par_iter()
        .map(|p| p.read_to_string())
        .collect()
}

/// Marker must implement custom trait
trait Auditable {
    fn audit_log_name() -> &'static str;
}

fn audit_access<M: Auditable>(path: &StrictPath<M>) {
    println!("Accessing {} path: {}", 
        M::audit_log_name(), 
        path.strictpath_display()
    );
}
```

## Common Mistakes

### ❌ Unnecessary Generic Constraint

```rust
// Bad: overly restrictive
fn read_size<M: Sized>(path: &StrictPath<M>) -> std::io::Result<u64> {
    Ok(path.metadata()?.len())
}

// Good: no constraint needed
fn read_size<M>(path: &StrictPath<M>) -> std::io::Result<u64> {
    Ok(path.metadata()?.len())
}
```

### ❌ Mixing Markers Unsafely

```rust
// Bad: forces marker type conversion
fn bad_mix<M1, M2>(src: &StrictPath<M1>, dst: &StrictPath<M2>) {
    // Won't compile: can't copy between different marker types
    src.strict_copy(dst); // ERROR: marker type mismatch
}

// Good: require same marker
fn good_copy<M>(src: &StrictPath<M>, dst: &StrictPath<M>) {
    src.strict_copy(dst); // ✅ OK: both have marker M
}
```

### ❌ Losing Marker Type

```rust
// Bad: loses type information
fn process(path: &StrictPath<()>) { ... }

// Good: preserve marker
fn process<M>(path: &StrictPath<M>) { ... }
```

## Best Practices

### ✅ Start Generic, Add Constraints as Needed

```rust
// Start here
fn process<M>(path: &StrictPath<M>) { ... }

// Add trait bounds only if needed
fn process<M: Send + Sync>(path: &StrictPath<M>) { ... }

// Use specific markers only when required for business logic
fn process_user(path: &StrictPath<UserData>) { ... }
```

### ✅ Document Marker Expectations

```rust
/// Process any file in any boundary.
///
/// Generic over marker type `M` because the operation
/// doesn't depend on specific authorization or context.
fn process_file<M>(file: &StrictPath<M>) -> std::io::Result<()> {
    // ...
}

/// Load user-specific configuration.
///
/// Requires `UserData` marker to enforce that only
/// user-scoped paths can be processed here.
fn load_user_config(file: &StrictPath<UserData>) -> Result<Config> {
    // ...
}
```

### ✅ Use Generic for Utilities, Specific for Domain Logic

```rust
// ✅ Generic utility
fn file_size<M>(path: &StrictPath<M>) -> std::io::Result<u64> { ... }

// ✅ Specific domain logic
fn charge_storage_fees(path: &StrictPath<BillingData>) -> Result<Amount> { ... }
```

## Summary

- **`<M>` means "works with any marker"**
- **Use generics for reusable utilities**
- **Use specific markers for domain-specific logic**
- **The compiler prevents marker type mismatches**
- **Marker types flow through call chains automatically**
- **Add trait bounds only when needed**
