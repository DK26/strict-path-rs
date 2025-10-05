# Proposal: Fix `anchored_canonicalize` Symlink Clamping Behavior

**Status:** Recommendation for `soft-canonicalize` crate  
**Issue Type:** Bug / Incomplete Implementation  
**Priority:** High (Security & Consistency)  
**Date:** October 5, 2025  
**Target Crate:** `soft-canonicalize` v0.3.6+  
**Affected Downstream:** `strict-path` v0.1.0-beta.2+

---

## Executive Summary

The `anchored_canonicalize()` function in `soft-canonicalize` is designed for "correct s### References

- **soft-canonicalize Repository:** https://github.com/DK26/soft-canonicalize-rs
- **strict-path Repository:** https://github.com/DK26/strict-path-rs
- **strict-path Issue #13:** Virtual symlink clamping behavior
- **Design Principle:** Virtual filesystem semantics (container/chroot model)
- **Python Inspiration:** `pathlib.Path.resolve(strict=False)` - but with virtual space extension
- **Documentation Updates:** 
  - `strict-path/src/lib.rs` - "When to Use Which Type" section enhanced with symlink behavior explanation
  - `README.md` - Decision guide updated with critical distinction and At-a-glance table expandedresolution within virtual/constrained directory spaces" but currently **rejects** symlinks pointing outside the anchor instead of **clamping** them. This creates inconsistent behavior where user input paths are clamped but symlink targets are rejected, breaking the virtual filesystem semantics.

**Current Behavior:**
- User input: `virtual_join("../../../etc/passwd")` → ✅ Clamped to `anchor/etc/passwd`
- Symlink target: `mylink -> /etc/passwd` → ❌ Rejected with boundary escape error

**Proposed Behavior:**
- User input: `virtual_join("../../../etc/passwd")` → ✅ Clamped to `anchor/etc/passwd`
- Symlink target: `mylink -> /etc/passwd` → ✅ Clamped to `anchor/etc/passwd`

---

## Virtual Filesystem Model

### What is a Virtual Filesystem?

In a virtual filesystem, **all absolute paths are relative to the virtual root**, not the system root. This is similar to how containers (Docker, chroot) work:

```
Virtual root: /home/user_id
Virtual path: /etc/config
System path: /home/user_id/etc/config
```

In this model, when a user or application references `/etc/config`, they mean "etc/config within my virtual space," not "the system's /etc/config."

### Why Clamping is Essential

**For consistency:** All absolute paths must be treated uniformly:
- User provides: `/etc/passwd` → Clamped to `vroot/etc/passwd`
- Symlink points to: `/etc/passwd` → Must also clamp to `vroot/etc/passwd`

**For security:** Clamping is more secure than rejection:
- ❌ Rejection: Creates a confusing failure mode, tempts workarounds
- ✅ Clamping: Symlinks automatically stay in bounds, no escape possible

**For usability:** Users expect virtual filesystem semantics:
- Archives with absolute symlinks work automatically
- No manual rewriting or special handling needed
- Intuitive behavior matching container environments

---

## Problem Statement

### Design Intent vs Implementation Gap

According to `soft-canonicalize` documentation:

> **Anchored Canonicalization**  
> For correct symlink resolution within virtual/constrained directory spaces, use `anchored_canonicalize`. This function ensures symlinks resolve properly relative to an anchor directory, making it ideal for virtual filesystems, containerized environments, and chroot-like scenarios.

The documentation explicitly states:
```rust
let resolved_path = anchored_canonicalize(&anchor, "../../../etc/passwd")?;
// Result: /tmp/workspace_root/etc/passwd (lexical .. clamped to anchor)
```

**Key features listed:**
- ✅ "Virtual space symlink resolution: Ensures correct symlink behavior within bounded directory trees"
- ✅ "Anchor-relative canonicalization: Resolves paths relative to a specific anchor directory"
- ✅ "Symlink resolution: Follows symlinks to their actual targets with **proper virtual space semantics**"

### Current Implementation Problem

The current implementation only clamps **lexical traversal** (`../../../`) in user input but does **NOT** clamp **absolute symlink targets** during resolution. This creates:

1. **Inconsistent semantics**: Same absolute path behaves differently depending on source
2. **Broken virtual filesystem model**: Symlinks can "escape" by pointing to absolute paths
3. **Security gaps**: Archive extraction scenarios fail instead of being safely contained
4. **User-hostile behavior**: Legitimate archives with absolute symlinks are rejected

### Real-World Use Case: Multi-Tenant File Storage

**Scenario:**
```
User A uploads archive containing: mylink -> /etc/config
Archive extracted to: /storage/userA/uploads/

User A tries to access: vroot.virtual_join("uploads/mylink")
```

**Current Behavior:**
```
Error: PathEscapesBoundary("/etc/config")
```
User's legitimate file access fails because the symlink points to an absolute path.

**Expected Behavior (Virtual Space Semantics):**
```
Success: Resolves to /storage/userA/etc/config
```
The absolute symlink target `/etc/config` is reinterpreted as `vroot/etc/config`, staying safely within the jail. If that file exists in User A's space, it's accessible. If not, it's a normal 404.

**Security Guarantee:** User A can never access:
- User B's files (different vroot)
- System files (outside their vroot)
- Files outside their boundary (clamped to their space)

---

## Root Cause Analysis

### Architecture Overview

```
strict-path (user-facing)
    └─> PathHistory::canonicalize_anchored()
        └─> soft-canonicalize::anchored_canonicalize()
            ├─> Lexically normalize ".." in input ✅ (works)
            ├─> Follow symlinks via OS calls
            └─> Return resolved absolute path
    └─> boundary_check() 
        └─> if !resolved_path.starts_with(anchor): ❌ REJECT
```

**The problem:** When `anchored_canonicalize()` follows a symlink with an absolute target:
1. OS call returns the real absolute path (e.g., `/etc/config`)
2. Function returns this path as-is
3. `strict-path` boundary check sees it's outside the anchor
4. **Rejection** instead of **clamping**

### Why This Is Wrong

The function is called `anchored_canonicalize` - the "anchored" part implies that **all paths are relative to the anchor**, including symlink targets. In virtual filesystem semantics:

- `/` means "the root of the virtual space" (the anchor)
- `/etc/passwd` means `anchor/etc/passwd`
- This should apply **uniformly** to all absolute paths, regardless of source

---

## Proposed Solution

### Design Principle

**Absolute paths in virtual space are ALWAYS relative to the anchor.**

This creates a simple, consistent rule:
- ✅ Easy to understand and reason about
- ✅ No special cases for different path sources
- ✅ Matches container/chroot semantics
- ✅ User-friendly (paths "just work" safely)
- ✅ Security maintained through clamping, not rejection

### Implementation Strategy

When `anchored_canonicalize()` follows a symlink and the target is absolute:

1. **Detect absolute path:** Check if symlink target starts with `/` (Unix) or has drive letter (Windows)
2. **Strip root prefix:** Remove the leading `/` or `C:\`
3. **Join to anchor:** Treat the stripped path as relative to the anchor
4. **Continue resolution:** Process the clamped path normally

### Pseudo-code

```rust
fn resolve_symlink_target(anchor: &Path, symlink_target: &Path) -> PathBuf {
    if symlink_target.is_absolute() {
        // Clamp absolute symlink target to anchor
        let relative = strip_root_prefix(symlink_target);
        anchor.join(relative)
    } else {
        // Relative symlink - resolve normally from symlink's parent
        symlink_parent.join(symlink_target)
    }
}

fn strip_root_prefix(path: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        // Unix: /etc/passwd -> etc/passwd
        path.strip_prefix("/").unwrap_or(path).to_path_buf()
    }
    
    #[cfg(windows)]
    {
        // Windows: C:\Windows\System32 -> Windows/System32
        // Handle: C:\, \\?\C:\, \\server\share
        // ... platform-specific logic ...
    }
}
```

---

## Verification Test Cases

### Test 1: Absolute Unix Symlink Clamping

```rust
#[test]
#[cfg(unix)]
fn anchored_canonicalize_clamps_absolute_symlink_targets() {
    use std::os::unix::fs::symlink;
    use soft_canonicalize::anchored_canonicalize;
    
    let anchor_td = tempfile::tempdir().unwrap();
    let anchor = anchor_td.path();
    
    // Create external target OUTSIDE anchor
    let external_td = tempfile::tempdir().unwrap();
    let external_file = external_td.path().join("external_secret.txt");
    std::fs::write(&external_file, b"external data").unwrap();
    
    // Create symlink INSIDE anchor pointing to absolute external path
    let symlink_path = anchor.join("link_to_external");
    symlink(&external_file, &symlink_path).unwrap();
    
    // Access the symlink through anchored_canonicalize
    let result = anchored_canonicalize(anchor, "link_to_external").unwrap();
    
    // Expected: Should clamp to anchor, not follow to external location
    assert!(result.starts_with(anchor), 
        "Symlink target should be clamped to anchor. Got: {:?}, Anchor: {:?}", 
        result, anchor);
    
    // The clamped path should be: anchor + external_file's absolute path
    // e.g., /tmp/anchor/tmp/abc123/external_secret.txt
    let expected_suffix = external_file.strip_prefix("/").unwrap();
    assert!(result.ends_with(expected_suffix),
        "Should preserve the symlink target path structure within anchor");
}
```

### Test 2: Absolute Root Path Symlink

```rust
#[test]
#[cfg(unix)]
fn anchored_canonicalize_clamps_root_symlink() {
    use std::os::unix::fs::symlink;
    use soft_canonicalize::anchored_canonicalize;
    
    let anchor_td = tempfile::tempdir().unwrap();
    let anchor = anchor_td.path();
    
    // Create symlink pointing to /etc/passwd (absolute root path)
    let symlink_path = anchor.join("passwd_link");
    symlink("/etc/passwd", &symlink_path).unwrap();
    
    // Access through anchored_canonicalize
    let result = anchored_canonicalize(anchor, "passwd_link").unwrap();
    
    // Should clamp /etc/passwd to anchor/etc/passwd
    assert!(result.starts_with(anchor));
    assert!(result.ends_with("etc/passwd"),
        "Should clamp /etc/passwd to anchor/etc/passwd. Got: {:?}", result);
    
    let expected = anchor.join("etc/passwd");
    assert_eq!(result, expected);
}
```

### Test 3: Windows Junction Clamping

```rust
#[test]
#[cfg(windows)]
fn anchored_canonicalize_clamps_windows_junction() {
    use std::process::Command;
    use soft_canonicalize::anchored_canonicalize;
    
    let anchor_td = tempfile::tempdir().unwrap();
    let anchor = anchor_td.path();
    
    // Create external directory
    let external_td = tempfile::tempdir().unwrap();
    let external_dir = external_td.path().join("external_data");
    std::fs::create_dir(&external_dir).unwrap();
    std::fs::write(external_dir.join("file.txt"), b"external").unwrap();
    
    // Create junction inside anchor pointing outside
    let junction_path = anchor.join("external_link");
    let output = Command::new("cmd")
        .args(&["/C", "mklink", "/J", 
            &junction_path.to_string_lossy(), 
            &external_dir.to_string_lossy()])
        .output()
        .unwrap();
    
    assert!(output.status.success(), "Failed to create junction");
    
    // Access file through junction
    let result = anchored_canonicalize(anchor, "external_link/file.txt").unwrap();
    
    // Should be clamped within anchor
    assert!(result.starts_with(anchor),
        "Junction target should be clamped. Got: {:?}, Anchor: {:?}",
        result, anchor);
}
```

### Test 4: Relative Symlinks Continue Working

```rust
#[test]
#[cfg(unix)]
fn anchored_canonicalize_preserves_relative_symlink_behavior() {
    use std::os::unix::fs::symlink;
    use soft_canonicalize::anchored_canonicalize;
    
    let anchor_td = tempfile::tempdir().unwrap();
    let anchor = anchor_td.path();
    
    // Create target file inside anchor
    let target = anchor.join("data/target.txt");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, b"target content").unwrap();
    
    // Create relative symlink
    let link_dir = anchor.join("links");
    std::fs::create_dir(&link_dir).unwrap();
    let symlink_path = link_dir.join("relative_link");
    symlink("../data/target.txt", &symlink_path).unwrap();
    
    // Access through anchored_canonicalize
    let result = anchored_canonicalize(anchor, "links/relative_link").unwrap();
    
    // Should resolve to the actual target location
    assert_eq!(result, target.canonicalize().unwrap());
}
```

### Test 5: Chained Symlinks with Mixed Absolute/Relative

```rust
#[test]
#[cfg(unix)]
fn anchored_canonicalize_handles_chained_symlinks() {
    use std::os::unix::fs::symlink;
    use soft_canonicalize::anchored_canonicalize;
    
    let anchor_td = tempfile::tempdir().unwrap();
    let anchor = anchor_td.path();
    
    // Create: link1 -> /absolute/path (should clamp)
    // Create: link2 -> link1 (relative)
    let link1 = anchor.join("link1");
    symlink("/absolute/target", &link1).unwrap();
    
    let link2 = anchor.join("link2");
    symlink("link1", &link2).unwrap();
    
    // Access link2
    let result = anchored_canonicalize(anchor, "link2").unwrap();
    
    // Should clamp to anchor/absolute/target
    assert!(result.starts_with(anchor));
    assert!(result.ends_with("absolute/target"));
}
```

---

## Behavior Matrix: Before vs After

| Scenario                        | Input                    | Current Behavior                  | Proposed Behavior                 |
| ------------------------------- | ------------------------ | --------------------------------- | --------------------------------- |
| User input with `..`            | `../../../etc/passwd`    | ✅ Clamped to `anchor/etc/passwd`  | ✅ Clamped to `anchor/etc/passwd`  |
| Symlink to absolute path        | `mylink -> /etc/passwd`  | ❌ Rejected: `PathEscapesBoundary` | ✅ Clamped to `anchor/etc/passwd`  |
| Junction to absolute path (Win) | `junction -> C:\Windows` | ❌ Rejected: `PathEscapesBoundary` | ✅ Clamped to `anchor/C/Windows`   |
| Relative symlink                | `link -> ../data/file`   | ✅ Resolves normally               | ✅ Resolves normally               |
| Symlink chain                   | `link1 -> link2 -> /abs` | ❌ Rejected at `/abs`              | ✅ Clamped final target            |
| Non-existing symlink target     | `link -> /future/file`   | ❌ Rejected                        | ✅ Clamped to `anchor/future/file` |

---

## Impact Analysis

### Breaking Changes

**None.** This is a bug fix that makes behavior match the documented intent.

**Rationale:**
1. Documentation explicitly promises "virtual space symlink resolution"
2. Current rejection behavior is inconsistent with design goals
3. Users relying on rejection are using the function incorrectly for their use case
4. Standard `soft_canonicalize` (without anchor) remains unchanged for non-virtual scenarios

### Downstream Impact: `strict-path`

**Positive impact only:**
- ✅ Virtual paths work correctly with symlinks
- ✅ Archive extraction scenarios succeed
- ✅ No code changes needed in `strict-path`
- ✅ Existing tests continue to pass
- ✅ New test cases (already written) will pass

### Migration Path for Existing Users

If any users depend on rejection behavior (unlikely, given the design intent):

**Alternative 1:** Use standard `soft_canonicalize` + manual boundary check
```rust
// For strict rejection of symlink escapes:
let resolved = soft_canonicalize(path)?;
if !resolved.starts_with(anchor) {
    return Err("Path escapes boundary");
}
```

**Alternative 2:** Add environment variable / feature flag (not recommended)
```rust
// If absolutely necessary for backward compat (not recommended):
#[cfg(feature = "strict-anchor-rejection")]
const ANCHOR_MODE: AnchorMode = AnchorMode::Reject;
#[cfg(not(feature = "strict-anchor-rejection"))]
const ANCHOR_MODE: AnchorMode = AnchorMode::Clamp;
```

---

## Implementation Checklist

For LLM implementing this fix:

- [ ] **Read current `anchored_canonicalize` implementation**
  - Location: `soft-canonicalize-rs/src/lib.rs` or similar
  - Understand current symlink resolution logic
  
- [ ] **Identify symlink resolution point**
  - Find where `std::fs::read_link()` or equivalent is called
  - Locate where resolved target path is used
  
- [ ] **Implement `strip_root_prefix` helper**
  - Unix: Strip leading `/`
  - Windows: Handle `C:\`, `\\?\C:\`, `\\server\share\`
  - Preserve rest of path structure
  
- [ ] **Add clamping logic in symlink resolution**
  - Check if target is absolute: `path.is_absolute()`
  - If absolute: `anchor.join(strip_root_prefix(target))`
  - If relative: existing logic (resolve from parent)
  
- [ ] **Add comprehensive tests**
  - Copy test cases from this document
  - Verify all scenarios in behavior matrix
  - Test on Unix and Windows
  
- [ ] **Update documentation**
  - Add explicit example showing symlink clamping
  - Clarify that ALL absolute paths are clamped
  - Update "Security Considerations" section
  
- [ ] **Run full test suite**
  - Ensure no regressions
  - Verify 301+ existing tests still pass
  
- [ ] **Update CHANGELOG.md**
  - Category: Bug Fix
  - Describe: "Fix anchored_canonicalize to clamp absolute symlink targets"

---

## Validation Steps for LLM

To verify this fix is correct:

1. **Check design intent**: Read `soft-canonicalize` README anchored section
2. **Verify inconsistency**: Run tests showing rejection vs clamping difference
3. **Confirm security**: Ensure clamped paths never escape anchor boundary
4. **Test edge cases**: Symlink chains, mixed absolute/relative, non-existing targets
5. **Validate downstream**: Confirm `strict-path` tests pass with fix
6. **Review documentation**: Ensure examples match new behavior

---

## References

- **soft-canonicalize Repository:** https://github.com/DK26/soft-canonicalize-rs
- **strict-path Repository:** https://github.com/DK26/strict-path-rs
- **strict-path Issue #13:** Virtual symlink clamping behavior
- **Design Principle:** Virtual filesystem semantics (container/chroot model)
- **Python Inspiration:** `pathlib.Path.resolve(strict=False)` - but with virtual space extension

---

## Conclusion

This fix transforms `anchored_canonicalize` from a partial virtual filesystem implementation (lexical clamping only) into a complete one (lexical + symlink clamping). It aligns implementation with documented intent, resolves user-facing issues, and maintains security through consistent clamping rather than inconsistent rejection.

**The virtual filesystem model requires that all absolute paths, regardless of source (user input or symlink target), are interpreted relative to the anchor. This is fundamental to providing consistent, secure, and usable virtual filesystem semantics.**

**Recommendation:** Implement this fix in `soft-canonicalize` v0.4.0 as a bug fix with comprehensive test coverage.

---

**Document Prepared For:** LLM Tool-Calling Agent  
**Action Required:** Analyze, verify, and implement fix in `soft-canonicalize` crate  
**Success Criteria:** All proposed test cases pass, `strict-path` benefits from fix, virtual filesystem semantics are complete and consistent
