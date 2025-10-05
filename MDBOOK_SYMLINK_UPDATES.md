# mdBook Symlink Clamping Documentation Updates

This document tracks all mdBook documentation updates related to the symlink target clamping feature for `VirtualPath`.

## ⚠️ IMPORTANT: Correct Location

The mdBook sources are located in `.docs/docs_src/src/` (on the `docs` branch via worktree), NOT in `book/src/` (which is a stale copy on `main` branch).

All updates below reference the CORRECT files in `.docs/docs_src/src/`.

## Executive Summary

Updated mdBook documentation to explain that `VirtualPath` implements **true virtual filesystem semantics** where absolute paths (from user input OR symlink targets) are clamped to the virtual root. This distinguishes it from `StrictPath` which validates and rejects paths that escape the boundary.

## Files Updated (6 total)

All files are in `.docs/docs_src/src/` directory (docs branch via worktree).

### 1. **.docs/docs_src/src/getting_started.md**
**Location:** Lines 120-145 (new section added)

**Changes:**
- Added "The Critical Difference: Symlink Behavior" section
- Explains StrictPath rejects escapes vs VirtualPath clamps them
- Shows behavior for both user input and symlink targets
- Lists use cases: archive extraction, multi-tenant systems, containers
- Provides rule of thumb for choosing between types

**Key Message:** VirtualPath = virtual filesystem with clamping, StrictPath = system filesystem with validation

---

### 2. **.docs/docs_src/src/tutorial/stage5_virtual_paths.md**
**Location:** Lines 210-260 (replaced existing symlink section)

**Changes:**
- **Replaced** old "Symlinks and Virtual Paths" section with comprehensive explanation
- Added comparison: StrictPath validates symlink targets vs VirtualPath clamps them
- Included detailed code examples for both types
- Added "The Key Insight" explaining virtual filesystem semantics
- Created comparison table showing behavior differences
- Listed use cases for symlink clamping

**Old Message:** VirtualPath validates symlinks (same as StrictPath)
**New Message:** VirtualPath clamps absolute symlink targets to virtual root (true virtual FS)

---

### 3. **.docs/docs_src/src/best_practices.md**
**Location:** Lines 155-175 (added to Security Philosophy section)

**Changes:**
- Added "Critical Distinction - Symlink Behavior" subsection
- Explains behavior when symlink points to absolute path
- Lists three key use cases with emojis:
  - 🗜️ Archive extraction
  - 🏢 Multi-tenant systems
  - 📦 Container-like environments
- Emphasizes VirtualPath implements virtual filesystem semantics

**Integration:** Fits naturally into existing Security Philosophy section explaining StrictPath vs VirtualPath

---

### 4. **.docs/docs_src/src/examples/archive_extraction.md**
**Location:** Multiple sections

**Changes:**

#### Section: "Attack Scenarios Prevented" (Lines ~110-120)
- **Converted table** from 2 columns to 3 columns
- Added "VirtualPath Result" column showing clamping behavior
- Shows all attack scenarios are clamped instead of rejected
- Added note recommending VirtualPath for archive extraction

#### New Section: "Using VirtualPath for Extra Safety" (Lines ~310-350)
- Added complete code example using `VirtualRoot` and `VirtualPath`
- Shows how malicious entries are clamped instead of rejected
- Lists 5 benefits of using VirtualPath for archives
- Provides guidance on when to use each type
- Added to Best Practices list

**Key Addition:** Archives are a perfect use case for VirtualPath's clamping behavior

---

### 5. **.docs/docs_src/src/type_system_guarantees.md**
**Location:** Lines ~270-310 (new section before summary)

**Changes:**
- Added new section "StrictPath vs VirtualPath: Symlink Semantics"
- Provides side-by-side code examples for both types
- Shows exact behavior with symlinks pointing outside boundary
- Explains "Use for" scenarios for each type
- Adds "Key Insight" about virtual filesystem absolute path interpretation
- Updated "Common Patterns Summary" to include choosing right semantics

**Purpose:** Explains this distinction in the context of type system guarantees and markers

---

## Files Reviewed (No Updates Needed)

### 1. **security_methodology.md**
- Already comprehensive about security approach
- Symlink behavior is implementation detail; high-level methodology still accurate
- No changes needed

### 2. **examples/overview.md**
- High-level overview of example categories
- No symlink-specific content
- No changes needed

### 3. **examples/multi_user_storage.md**
- Focuses on VirtualRoot usage patterns
- Already demonstrates virtual filesystem concepts
- No symlink-specific additions needed (covered in other examples)

---

## Common Themes Across Updates

### 1. **Consistent Terminology**
- **StrictPath:** "System filesystem semantics" - validates and rejects
- **VirtualPath:** "Virtual filesystem semantics" - clamps absolute paths

### 2. **Key Use Cases Highlighted**
Across all documents, three use cases are consistently mentioned:
1. **Archive extraction** - Malicious entries with absolute paths/symlinks
2. **Multi-tenant systems** - User isolation and sandbox escaping prevention
3. **Container-like environments** - True virtual filesystem behavior

### 3. **Behavior Examples**
Common example used: `symlink -> /etc/passwd`
- **StrictPath:** Error if target outside boundary
- **VirtualPath:** Target clamped to `vroot/etc/passwd`

### 4. **Rule of Thumb**
Consistently stated across documents:
- **System-facing / shared resources:** Use `StrictPath`
- **User-facing / sandboxes:** Use `VirtualPath`

## Cross-References

All updated sections maintain consistency with:
- **README.md** - "Critical distinction - Symlink behavior" section
- **lib.rs** - "When to Use Which Type" with symlink semantics explanation
- **ANCHORED_SYMLINK_CLAMPING_PROPOSAL.md** - Design rationale document

## Testing Status

- ✅ Documentation updated and consistent
- ✅ Code examples compile (use existing API)
- ⏳ Tests expect clamping behavior (currently failing, waiting for soft-canonicalize patch)
- ⏳ Once patch applied: tests will pass, documentation will be accurate

## Future Maintenance

When the soft-canonicalize patch is applied:
1. Verify all code examples in these docs still work correctly
2. Update any "coming soon" or "planned" language if present
3. Add links to release notes mentioning the symlink clamping feature
4. Consider adding a dedicated "Security Features" page highlighting this distinction

## LLM Agent Notes

These updates are crafted for both human readers and LLM consumption:
- Clear behavioral comparisons with code examples
- Consistent terminology and use case patterns
- Side-by-side examples showing the difference
- Tables for quick reference
- Integration with existing content structure

The documentation now fully explains how VirtualPath's symlink clamping "upgrades what VirtualPath means" - transforming it from simple path validation to a complete virtual filesystem implementation.
