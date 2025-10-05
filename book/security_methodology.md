# How We Achieve Security

This chapter provides a detailed look at the multi-layered security methodology behind `strict-path`. Rather than relying on simple string validation or ad-hoc checks, we've built a comprehensive defense-in-depth approach that addresses path security from the ground up.

## 1. Battle-Tested Foundation: `soft-canonicalize`

Our security starts with `soft-canonicalize`—a purpose-built path resolution library that has been validated against 19+ globally known path-related CVEs. These CVEs represent years of accumulated attack patterns and edge cases discovered across the software ecosystem.

**What it handles:**
- **Symlink cycles and complex link chains**: Prevents infinite loops and traversal through symbolic links
- **Path resolution consistency**: Ensures paths are resolved consistently during validation, reducing some timing-related inconsistencies in path interpretation
- **Platform-specific quirks**: Windows 8.3 short names (`PROGRA~1`), UNC paths, NTFS Alternate Data Streams
- **Encoding tricks**: Unicode normalization attacks, case sensitivity issues, and filesystem encoding edge cases
- **Canonicalization edge cases**: Proper handling of `.`, `..`, multiple slashes, and malformed path components

**Why this matters:** Most directory traversal vulnerabilities stem from incomplete path resolution. By building on `soft-canonicalize`, we benefit from systematic validation against years of documented attack vectors that simple string validation would miss.

## 2. Secure API Design

Our API design is built around the principle that **security should be the easiest path forward**. Every design decision prioritizes preventing misuse over convenience.

### 2.1 LLM Agent-Aware Design

Modern threats include AI agents processing untrusted paths from various sources. Our API is designed specifically for this threat model:

- **Clear validation points**: `strict_join()` and `virtual_join()` make validation explicit and visible
- **LLM-friendly documentation**: Complete parameter documentation and usage examples specifically for AI consumption
- **Fail-safe defaults**: Operations fail closed rather than permitting potentially dangerous paths
- **Explicit interop boundaries**: `.interop_path()` makes filesystem handoffs to third-party code obvious

### 2.2 Minimal API Surface for Minimal Error Margin

We deliberately limit our public API surface to reduce the possibility of misuse:

- **No leaky trait implementations**: No `AsRef<Path>`, `Deref<Target = Path>`, or implicit conversions that bypass validation
- **Controlled constructors**: Only specific, well-audited entry points for creating secure path types
- **Helper API restrictions**: New public functions require explicit maintainer approval to prevent API drift
- **Dimension separation**: Strict and virtual paths have separate, non-interchangeable operations

### 2.3 Explicit Methods That Make Logic Errors Visible

Our method names are designed to make security-relevant operations obvious during code review:

```rust
// ❌ Unclear security implications
path.join(user_input)

// ✅ Security implications clear at a glance
boundary.strict_join(user_input)?
vroot.virtual_join(user_input)?
```

**Key principles:**
- **Verbose over clever**: `strict_join()` instead of `join()` makes the security operation explicit
- **Dimension-specific operations**: `strictpath_display()` vs `virtualpath_display()` prevent confusion
- **No hidden validation**: Every path that enters the system must go through an explicit validation step

### 2.4 Rust Type System for Mathematical Correctness

We leverage Rust's type system to provide **compile-time guarantees** about path security:

- **Marker types prevent confusion**: `StrictPath<UserUploads>` vs `StrictPath<SystemConfig>` prevent accidentally mixing boundaries
- **Borrowing prevents mutation**: Once validated, paths cannot be secretly modified
- **Ownership tracking**: The type system ensures validated paths aren't leaked or corrupted
- **Zero-cost abstractions**: Security guarantees come at compile time, not runtime

### 2.5 Distinct Types for "Hard to Get Wrong" Approach

Different use cases get different types with appropriate guarantees:

- **`PathBoundary<Marker>`**: For creating and managing restriction policies
- **`StrictPath<Marker>`**: For paths that must stay within boundaries (fails on violations)
- **`VirtualRoot<Marker>`**: For creating virtual filesystem views
- **`VirtualPath<Marker>`**: For virtual paths that clamp to safe boundaries
- **`StrictPathError`**: Comprehensive error handling for all failure modes
- **Safe builtin I/O operations**: Direct filesystem operations that bypass the need for `.interop_path()` calls

### 2.6 Type System-Enforced Authorization

The marker system enables compile-time authorization guarantees:

```rust
// Authorization proof required to construct the marker
struct SecureDocuments;
impl SecureDocuments {
    fn new(auth_token: ValidatedAdminToken) -> Self { Self }
}

// Type system ensures authorization happened
fn access_secure_file(path: &StrictPath<SecureDocuments>) -> Result<String> {
    path.read_to_string() // Compiler guarantees authorization
}
```

### 2.7 Safe Builtin I/O Operations

A critical security feature is our comprehensive suite of safe I/O operations that eliminate the need to escape to unsafe `std::fs` calls for routine work. The APIs mirror the semantics and return values of the standard library while preserving boundary guarantees.

**File operations:**
- `read_to_string()`, `read()` — Read file contents
- `write<C: AsRef<[u8]>>()` — Write bytes (e.g., `&str`, `&[u8]`)
- `create_file()`, `open_file()` — Obtain file handles
- `remove_file()` — Delete files

**Directory operations:**
- `create_dir()`, `create_dir_all()` — Create directories
- `read_dir()` — Iterate directory entries (discover names; re-join through strict/virtual APIs)
- `metadata()` — Access filesystem metadata
- `remove_dir()`, `remove_dir_all()` — Delete directories

**Move/Copy operations (dimension-specific):**
- `StrictPath::strict_rename(..)` / `VirtualPath::virtual_rename(..)` — Rename/move within the restriction
- `StrictPath::strict_copy(..)` / `VirtualPath::virtual_copy(..)` — Copy within the restriction (returns bytes copied)

**Links (creation):**
- `StrictPath::strict_symlink(..)` / `VirtualPath::virtual_symlink(..)` — Create symlinks within the same restriction
- `StrictPath::strict_hard_link(..)` / `VirtualPath::virtual_hard_link(..)` — Create hard links (subject to platform constraints)

Note: We intentionally do not expose separate helpers for "symlink metadata" or standalone canonicalization. When you must interoperate with APIs that require `AsRef<Path>` or specific OS semantics, use `.interop_path()` to get the validated path as `&OsStr` and keep such calls isolated to interop boundaries.

**Why this matters:** By providing safe alternatives to common `std::fs` operations, we eliminate the need for `.interop_path()` in routine file work, keeping the API surface focused on validated operations while still enabling necessary third‑party integrations.

## 3. Active CVE Research and Validation

We maintain a systematic approach to understanding and defending against path-related vulnerabilities:

**Research activities:**
- **CVE database analysis**: Study of documented path-related vulnerabilities across software ecosystems
- **Security advisory analysis**: Analysis of how attacks work and why existing solutions failed
- **Historical attack validation**: Testing our defenses against known attack patterns
- **Comparative analysis**: Study of similar libraries and their security approaches

**Validation process:**
- Attack patterns are tested against our validation logic during development
- Gaps identified in research inform security improvements
- Security enhancements are implemented with careful consideration of compatibility
- Relevant findings contribute to the broader security community understanding

## 4. Open-Source Transparency for Rapid Issue Detection

Security through obscurity is not security at all. Our open-source approach enables:

**Community validation:**
- **Expert review**: Security researchers can audit our implementation
- **Diverse testing**: Community members test on platforms and use cases we haven't considered
- **Collaborative bug reporting**: Issues are tracked and addressed openly through GitHub
- **Collaborative improvement**: Security enhancements come from the community as well as maintainers

**Transparency benefits:**
- **No hidden vulnerabilities**: All code paths are visible for audit
- **Public issue tracking**: Security concerns are discussed openly
- **Reproducible security**: Anyone can verify our claims by reading the code
- **Trust through verification**: Don't trust our claims—verify them yourself

## 5. Pseudo Projects for API Effectiveness Testing

We maintain a suite of realistic demo projects that test our API in real-world scenarios:

**Demo categories:**
- **Web servers**: File upload handlers, static asset serving, user content management
- **CLI tools**: File processors, archive extractors, configuration managers
- **LLM agents**: AI-driven file operations, automated code generation
- **Archive handling**: ZIP extraction, tar processing, backup restoration
- **Configuration systems**: Multi-environment config loading, user preference handling

**Testing methodology:**
- **Production authenticity**: Demos use real protocols and official ecosystem crates
- **Security integration patterns**: Each demo shows correct validation flow
- **Failure mode testing**: Demos include examples of rejected hostile inputs
- **Performance validation**: Real-world load testing of validation logic

**Why this matters:** APIs that work perfectly in isolation often fail when integrated into real systems. Our demos catch integration issues, performance problems, and usability gaps that unit tests miss.

## 6. Security Testing and Validation

We employ comprehensive testing methodologies to validate our security approach:

### 6.1 Black-Box Testing

**Automated fuzzing:**
- Random path generation across all Unicode ranges
- Platform-specific attack vectors (Windows short names, Unix special files)
- Encoding attack patterns (mixed encodings, normalization attacks)
- Length-based attacks (extremely long paths, empty components)

**LLM-assisted testing:**
- **AI-generated attack patterns**: Using advanced LLMs to generate potential bypass attempts
- **Reasoning model validation**: Employing reasoning models to explore attack vectors  
- **Multi-model consensus**: Cross-validating security assumptions across different AI models
- **Systematic attack exploration**: Multi-step validation approaches that build complexity

### 6.2 White-Box Testing

**Code analysis:**
- **Control flow analysis**: Mapping all possible execution paths through validation logic
- **State space exploration**: Testing all combinations of internal validation states
- **Boundary condition testing**: Edge cases in canonicalization, length limits, character handling
- **Race condition simulation**: Concurrent access patterns and filesystem state changes

**Architecture review:**
- **Trust boundary analysis**: Verifying that security boundaries are correctly enforced
- **Assumption validation**: Testing that our security assumptions hold under all conditions
- **Integration point review**: Ensuring third-party integrations don't introduce vulnerabilities

### 6.3 Security Validation Process

Testing results inform our ongoing development:

- **Successful attacks** become test cases and drive security improvements
- **Failed attacks** validate our defenses and expand our test coverage
- **Novel attack vectors** contribute to the security community's understanding
- **Performance characteristics** of attacks inform our optimization decisions

## 7. Comprehensive Test Suite

Our testing strategy covers multiple layers of validation:

### 7.1 Unit Testing

**Core logic validation:**
- Every public function has comprehensive test coverage
- Edge cases and boundary conditions are explicitly tested
- Platform-specific behavior is validated on all supported systems
- Error conditions are tested to ensure proper failure modes

### 7.2 Integration Testing

**Real-world scenario testing:**
- Full end-to-end flows from untrusted input to filesystem operations
- Cross-platform compatibility validation
- Third-party integration testing with common ecosystem crates
- Performance testing under realistic load conditions

### 7.3 Property-Based Testing

**Automated verification:**
- QuickCheck-style property validation for core invariants
- Fuzzing with structured inputs to explore edge cases
- Shrinking of failing test cases to minimal reproduction examples
- Statistical validation of security properties across large input spaces

### 7.4 Security-Focused Testing

**Attack simulation:**
- Known CVE reproduction tests to ensure we block historical attacks
- Platform-specific security tests (Windows short names, Unix symlinks)
- Encoding and normalization attack tests
- Filesystem race condition simulations

### 7.5 Continuous Testing

**Automated validation:**
- CI/CD pipeline runs full test suite on every change
- Multiple platform testing (Windows, Linux, macOS)  
- MSRV (Minimum Supported Rust Version) compatibility validation
- Performance regression detection

## Security Is a Process, Not a Product

Our security methodology recognizes that security is an ongoing commitment rather than a one-time achievement. We are committed to:

- **Monitor** for new attack vectors and vulnerability patterns
- **Adapt** our defenses as the threat landscape evolves
- **Learn** from security incidents in the broader ecosystem
- **Improve** our methods based on real-world feedback and usage
- **Contribute** our knowledge to the security community

The result is a library designed not only to address known path security issues but to evolve and adapt as new threats emerge. By building security into every layer—from the foundational libraries through the API design to the testing methodology—we provide comprehensive protection against the entire class of path traversal vulnerabilities.

**Remember:** Path security isn't just about blocking `../../../etc/passwd`. It's about creating a robust defense against all the ways that untrusted paths can be crafted to bypass your security controls. That's what `strict-path` delivers.