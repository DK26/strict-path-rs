# Type-History Design Pattern

## The Problem We're Solving

Imagine you're writing code that needs to safely process data through multiple steps. You need to:

1. Take raw input from an untrusted source
2. Clean/sanitize it
3. Validate it meets requirements
4. Transform it to final form
5. Only then use it for critical operations

The problem? It's really easy to forget a step, or do them in the wrong order. And if you mess up, you might have bugs, security vulnerabilities, or data corruption.

**What if the compiler could remember which steps you've completed and enforce the correct order?**

That's exactly what the Type-History pattern does.

## Type-History in Simple Terms

The Type-History pattern is like having a checklist that follows your data around. Each time you complete a step, you get a new "stamp" on your checklist. Functions can then require that certain stamps are present before they'll work with your data.

Here's a simple example with strings:

```rust
// These are our "stamps"
struct Raw;          // Just created, no processing yet
struct Trimmed;      // Whitespace has been removed
struct Validated;    // Content has been checked

// This is our wrapper that carries both data and stamps
struct ProcessedString<History> {
    content: String,
    _stamps: std::marker::PhantomData<History>, // Invisible stamps
}

// Start with a raw string
impl ProcessedString<Raw> {
    fn new(s: String) -> Self {
        ProcessedString { 
            content: s, 
            _stamps: std::marker::PhantomData 
        }
    }
}

// Any string can be trimmed, adding a "Trimmed" stamp
impl<H> ProcessedString<H> {
    fn trim(self) -> ProcessedString<(H, Trimmed)> {
        ProcessedString {
            content: self.content.trim().to_string(),
            _stamps: std::marker::PhantomData,
        }
    }
}

// Only trimmed strings can be validated
impl<H> ProcessedString<(H, Trimmed)> {
    fn validate(self) -> Result<ProcessedString<((H, Trimmed), Validated)>, &'static str> {
        if self.content.is_empty() {
            Err("String cannot be empty")
        } else {
            Ok(ProcessedString {
                content: self.content,
                _stamps: std::marker::PhantomData,
            })
        }
    }
}

// This function only accepts fully processed strings
fn save_to_database(s: &ProcessedString<((Raw, Trimmed), Validated)>) {
    // We know this string has been trimmed AND validated
    println!("Safely saving: {}", s.content);
}
```

Now look what happens when you use it:

```rust
// This works - we follow the correct steps
let s = ProcessedString::new("  hello world  ".to_string())
    .trim()           // Now has (Raw, Trimmed) stamps
    .validate()?;     // Now has ((Raw, Trimmed), Validated) stamps

save_to_database(&s); // ✅ Compiles fine

// This won't compile - we skipped trimming!
let bad = ProcessedString::new("hello".to_string())
    .validate()?;     // This line itself won't compile!

// This won't compile either - missing validation
let also_bad = ProcessedString::new("hello".to_string())
    .trim();
save_to_database(&also_bad); // ❌ Compilation error
```

## Other Applications of Type-History

The Type-History pattern is useful anywhere you have multi-step data processing that must be done correctly:

### Network Request Processing
```rust
struct Raw;
struct Authenticated;
struct RateLimited;
struct Validated;

struct Request<H> {
    data: RequestData,
    _history: PhantomData<H>,
}

// Must authenticate, then rate-limit, then validate
fn handle_request(req: &Request<(((Raw, Authenticated), RateLimited), Validated)>) {
    // We know this request is safe to process
}
```

### Financial Transaction Processing
```rust
struct Raw;
struct AmountValidated;
struct FundsChecked;
struct Authorized;

struct Transaction<H> {
    amount: Decimal,
    from: AccountId,
    to: AccountId,
    _history: PhantomData<H>,
}

// Critical: must validate amount, check funds, get authorization
fn execute_transfer(tx: &Transaction<(((Raw, AmountValidated), FundsChecked), Authorized)>) {
    // Guaranteed to be safe for execution
}
```

### Database Query Building
```rust
struct Raw;
struct Sanitized;
struct Parameterized;
struct Validated;

struct Query<H> {
    sql: String,
    params: Vec<Value>,
    _history: PhantomData<H>,
}

// Must sanitize inputs, parameterize query, validate syntax
fn execute_query(q: &Query<(((Raw, Sanitized), Parameterized), Validated)>) {
    // Safe from SQL injection
}
```

## How This Applies to strict-path

For file paths, security is critical. We need to ensure that every path goes through the right checks in the right order:

1. **Canonicalize**: Resolve `.`, `..`, symlinks, etc.
2. **Boundary Check**: Make sure the path is within our jail
3. **Existence Check**: Verify the path actually exists (if needed)

Using Type-History, we can make it impossible to use a path that hasn't been properly validated:

```rust
// These are the stamps for paths
struct Raw;               // Fresh from user input
struct Canonicalized;     // Cleaned up and resolved
struct BoundaryChecked;   // Verified to be within jail bounds
struct Exists;           // Confirmed to exist on filesystem

// Our internal path wrapper (you rarely see this directly)
struct PathHistory<History> {
    path: PathBuf,
    _stamps: std::marker::PhantomData<History>,
}

// Only canonicalized AND boundary-checked paths can be used for I/O
fn safe_file_operation(path: &PathHistory<((Raw, Canonicalized), BoundaryChecked)>) {
    // We KNOW this path is safe to use
    std::fs::read_to_string(&path.path).unwrap();
}
```

## Reading the Type Signatures

The stamp history is written as nested tuples. Read them left-to-right to see the sequence:

- `PathHistory<Raw>` = Just created, no processing
- `PathHistory<(Raw, Canonicalized)>` = Created, then canonicalized  
- `PathHistory<((Raw, Canonicalized), BoundaryChecked)>` = Created, then canonicalized, then boundary-checked

It's like reading a receipt that shows every step that was completed.

## Why Not Just Use Booleans?

You might wonder: "Why not just have a struct with boolean fields like `is_canonicalized` and `is_boundary_checked`?"

The problem with booleans is that they can lie:

```rust
// ❌ With booleans, you can fake it
struct UnsafePath {
    path: PathBuf,
    is_canonicalized: bool,    // I can set this to `true`
    is_boundary_checked: bool, // even if I never actually did the checks!
}

let fake_safe = UnsafePath {
    path: PathBuf::from("../../../etc/passwd"),
    is_canonicalized: true,    // Lies!
    is_boundary_checked: true, // More lies!
};
```

With Type-History, you literally cannot create a value with the wrong stamps unless you actually performed the operations. The type system enforces honesty.

## The Public API Hides the Complexity

Users of strict-path never see `PathHistory` directly. Instead, they work with simple types like `StrictPath` and `VirtualPath`. But internally, these types contain properly stamped paths:

```rust
// What users see
pub struct StrictPath<Marker> {
    // What's hidden inside: a path that's been through the full validation pipeline
    inner: PathHistory<((Raw, Canonicalized), BoundaryChecked)>,
    // ... other fields
}

// Users just call simple methods
let safe_dir = PathBoundary::try_new_create("./safe_dir")?;
let safe_user_file = safe_dir.strict_join("user_file.txt")?; // Returns StrictPath

// But the type system guarantees this path is safe to use
```

## Benefits of This Approach

1. **Impossible to Forget Steps**: The compiler prevents you from skipping required processing
2. **Self-Documenting Code**: Function signatures clearly show what processing is required
3. **Refactor-Safe**: If you change the processing pipeline, the compiler finds all places that need updates
4. **Zero Runtime Cost**: All the type checking happens at compile time - no performance overhead
5. **Audit-Friendly**: Security reviewers can see exactly what guarantees each function requires

## When to Use Type-History

This pattern is overkill for simple cases, but it's valuable when:

- Security is critical (like file path validation)
- You have a multi-step process that must be done in order
- Skipping steps could cause bugs or vulnerabilities
- You want to encode important guarantees in the type system
- Multiple functions need different combinations of processing steps

## Wrapping Up

The Type-History pattern might seem complex at first, but it's really just a way to make the compiler remember what you've done and enforce what you need to do. It turns potential runtime errors into compile-time guarantees.

In strict-path, this means that once you have a `StrictPath` or `VirtualPath`, you can be 100% confident it's safe to use - the type system guarantees it went through all the necessary security checks.

For most users of strict-path, you don't need to understand these internals. Just know that the library uses advanced type system features to make it impossible to accidentally create security vulnerabilities. The compiler has your back!
