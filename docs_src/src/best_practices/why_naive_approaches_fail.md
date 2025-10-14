# Why Every "Simple" Solution Fails

> *The path security rabbit hole is deeper than you think.*

Every developer's first instinct: "I'll just validate the path with a simple check." But path security isn't simple—it's a problem class with dozens of interacting edge cases. Here's why every naive approach creates new vulnerabilities.

---

## Approach 1: "Just check for `../`"

```rust
if path.contains("../") { 
    return Err("Invalid path"); 
}
```

**What it blocks:**
- ✅ Basic traversal: `"../../../etc/passwd"`

**What bypasses it:**
- ❌ URL encoding: `"..%2F..%2F..%2Fetc%2Fpasswd"`
- ❌ Double encoding: `"....//....//etc//passwd"` → `"..//..//etc//passwd"` after one replacement
- ❌ Windows separators: `"..\\..\\..\etc\passwd"`
- ❌ Mixed separators: `"../\\../etc/passwd"`

**Verdict:** String matching is insufficient. Attackers use encoding tricks.

---

## Approach 2: "Use canonicalize() then check"

```rust
let canonical = fs::canonicalize(path)?;
if !canonical.starts_with("/safe/") { 
    return Err("Escape attempt"); 
}
```

**What it blocks:**
- ✅ Most directory traversal attempts
- ✅ Resolves symlinks correctly

**What it misses:**
- ❌ **CVE-2022-21658**: Race condition (TOCTOU) - symlink created between `canonicalize()` and the check
- ❌ **CVE-2019-9855**: Windows 8.3 short names (`"PROGRA~1"` → `"Program Files"`) bypass string checks
- ❌ Fails on non-existent files (can't canonicalize paths that don't exist yet)
- ❌ Requires filesystem access for every validation (performance cost)

**Verdict:** Race conditions and platform quirks make this dangerous.

---

## Approach 3: "Normalize the path first"

```rust
let normalized = path.replace("\\", "/").replace("../", "");
```

**What it blocks:**
- ✅ Basic traversal patterns

**What bypasses it:**
- ❌ Recursive patterns: `"....//....//etc//passwd"` → `"..\\..\\etc\\passwd"` after one replacement
- ❌ **CVE-2020-12279**: Unicode normalization attacks (`"..∕..∕etc∕passwd"` - different Unicode slashes)
- ❌ **CVE-2017-17793**: NTFS Alternate Data Streams (`"file.txt:hidden:$DATA"`)
- ❌ Absolute path replacement: `"/etc/passwd"` completely replaces the base path
- ❌ UNC paths on Windows: `"\\\\?\\C:\\Windows\\..\\..\\.."` 

**Verdict:** String replacement creates new attack vectors.

---

## Approach 4: "Use an allowlist of safe characters"

```rust
if !path.chars().all(|c| c.is_alphanumeric() || c == '/') { 
    return Err("Invalid"); 
}
```

**What it blocks:**
- ✅ Most special characters and encoding tricks

**What it misses:**
- ❌ Absolute path replacement: `"/etc/passwd"` (all valid chars!)
- ❌ Too restrictive: blocks legitimate files like `"report-2025.pdf"`, `"user_data.json"`
- ❌ **CVE-2025-8088**: Misses platform-specific issues (Windows device names: `"CON"`, `"PRN"`, `"NUL"`)
- ❌ Doesn't handle Unicode properly (internationalized filenames)

**Verdict:** Either too restrictive (breaks legitimate use) or still vulnerable.

---

## Approach 5: "Combine multiple checks"

```rust
// Check for ../, canonicalize, validate prefix, sanitize chars, check length...
fn validate_path(path: &str) -> Result<PathBuf, Error> {
    if path.contains("../") { return Err("traversal"); }
    if path.contains("\\") { return Err("backslash"); }
    if path.starts_with("/") { return Err("absolute"); }
    // ... 20 more checks ...
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with("/safe/") { return Err("escape"); }
    Ok(canonical)
}
```

**What it blocks:**
- ✅ Many known attack vectors
- ✅ Shows defensive programming

**What it misses:**
- ❌ **Complexity = Bugs**: 20+ edge cases means maintenance nightmare
- ❌ **Platform gaps**: Windows behavior ≠ Unix behavior ≠ Web behavior
- ❌ **Performance cost**: Multiple filesystem calls per validation
- ❌ **Future CVEs**: New attack vectors require updating every check
- ❌ **False sense of security**: Hard to verify you've covered everything

**Verdict:** Complex validation logic is error-prone and incomplete.

---

## The Fundamental Problem

> **Each "fix" creates new attack surface.**

Path security isn't a single problem—it's a **problem class** with complex interactions:

### The 5 Core Challenges

1. **Encoding Normalization**
   - Must handle URL encoding, Unicode, platform-specific encodings
   - Can't break legitimate international filenames
   - Attackers exploit normalization edge cases

2. **Symlink Resolution**
   - Must follow symlinks safely
   - Prevent race conditions (TOCTOU attacks)
   - Handle symlink cycles and bombs
   - Validate symlink targets stay within boundaries

3. **Platform Consistency**
   - Windows ≠ Unix ≠ Web
   - Case sensitivity differences
   - Path separator differences
   - Platform-specific features (8.3 names, UNC paths, Alternate Data Streams, device names)

4. **Boundary Enforcement**
   - Must be mathematical, not string-based
   - Resist all encoding and normalization tricks
   - Work for both existing and non-existent paths
   - Handle absolute vs. relative path semantics correctly

5. **Future-Proof Design**
   - Resistant to new attack vectors
   - Doesn't require updating for every new CVE
   - Compositional security properties
   - No "clever hacks" that break later

### Why This Is Hard

Each validation approach fixes one or two challenges while introducing new vulnerabilities in the others. You'd need:
- Deep filesystem expertise across all platforms
- Knowledge of dozens of path-related CVEs
- Months of testing edge cases
- Ongoing maintenance as new attacks emerge

**This is why strict-path exists.**

---

## The Solution: Solve the Problem Class Once

Instead of patching individual vulnerabilities, **strict-path solves the entire problem class**:

- **Built on `soft-canonicalize`**: Battle-tested against 19+ real CVEs
- **Mathematical boundary proofs**: Type system guarantees paths stay within bounds
- **Platform-aware**: Handles Windows 8.3 names, UNC paths, symlinks, junctions
- **Future-proof**: Architectural design resists entire classes of attacks
- **Composable**: Safe by construction, not by validation

```rust
use strict_path::PathBoundary;

// One line replaces all the complexity above
let boundary = PathBoundary::try_new("./safe")?;
let safe_path = boundary.strict_join(user_input)?; // ✅ All attacks blocked
```

**The trade-off**: Learn one crate's API vs. implementing (and maintaining) dozens of validation checks.

---

## Learn More

- **[Best Practices Overview →](../best_practices.md)** - How to use strict-path correctly
- **[Security Methodology →](../security_methodology.md)** - Our complete security approach
- **[Real-World Patterns →](./real_world_patterns.md)** - Production-ready examples
- **[Common Operations →](./common_operations.md)** - How to use validated paths safely

