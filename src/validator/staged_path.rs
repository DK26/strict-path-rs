use crate::{JailedPathError, Result};
use soft_canonicalize::soft_canonicalize;

// --- Type-State Markers ---
#[derive(Debug, Clone)]
/// The original, unchecked path as provided by the user.
pub struct Raw;
#[derive(Debug, Clone)]
/// Path after normalization of `.` and `..` components (clamping).
pub struct Clamped;
#[derive(Debug, Clone)]
/// Path after being joined to the jail root.
pub struct JoinedJail;
#[derive(Debug, Clone)]
/// Path after canonicalization (symlinks resolved, absolute).
pub struct Canonicalized;
/// Path after boundary check against the jail root.
pub struct BoundaryChecked;

/// # Understanding `StagedPath` Type Parameters
///
/// `StagedPath<State>` uses Rust’s type system to track the exact sequence of security-relevant
/// transformations a path has undergone. The `State` parameter is a tuple of marker types,
/// each representing a processing stage (e.g., `Raw`, `Clamped`, `JoinedJail`, `Canonicalized`, `BoundaryChecked`).
///
/// ## How to Read the Type
///
/// - The **innermost** type (leftmost in the tuple) is always `Raw`, representing the original, unchecked path.
/// - Each additional marker (added as you call methods like `.clamp()`, `.join_jail()`, `.canonicalize()`, `.boundary_check()`)
///   is appended to the tuple, in the order the operations were performed.
/// - The **outermost** type (rightmost in the tuple) is the most recent operation performed.
///
/// ### Example
///
/// ```rust
/// use jailed_path::validator::staged_path::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// // This type means: Raw -> Clamped -> JoinedJail -> Canonicalized -> BoundaryChecked
/// type SecurePath = StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Why This Matters
///
/// - **Security:** The type system enforces that no step is skipped or reordered.
/// - **Auditability:** Anyone reading the type knows exactly what has been done to the path.
/// - **Extensibility:** New security steps can be added as new marker types.
///
/// ## Typical Flow
///
/// ```rust
/// use jailed_path::validator::staged_path::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// let jail = StagedPath::<Raw>::new("/jail").canonicalize().unwrap();
/// let staged = StagedPath::new("user_upload.txt")
///     .clamp()
///     .join_jail(&jail)
///     .canonicalize().unwrap()
///     .boundary_check(&jail).unwrap();
/// // staged: StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Type Aliases for Common States
///
/// For convenience, you may define type aliases for common state combinations:
///
/// ```rust
/// use jailed_path::validator::staged_path::{StagedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// type FullyChecked = StagedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Advanced Usage
///
/// You can branch or skip steps (if your security policy allows), and the type will always reflect the actual processing history.
///
/// ---
///
/// **In summary:**  
/// The `StagedPath` type parameter is a type-level log of all security-relevant processing steps applied to a path.
#[derive(Debug, Clone)]
pub struct StagedPath<State> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<State>,
}

impl StagedPath<Raw> {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Self {
        StagedPath {
            inner: path.as_ref().to_path_buf(),
            _marker: std::marker::PhantomData,
        }
    }
    // Only new() is implemented for StagedPath<Raw>. All transitions are on impl<S> StagedPath<S>.
}

// join_jail now requires the jail to be a canonicalized path (no unconstrained S2)
impl<S> StagedPath<(S, Clamped)> {
    pub fn join_jail(
        self,
        jail: &StagedPath<(Raw, Canonicalized)>,
    ) -> StagedPath<((S, Clamped), JoinedJail)> {
        let joined = jail.inner.join(self.inner);
        StagedPath {
            inner: joined,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> StagedPath<S> {
    /// Consumes the StagedPath and returns the inner PathBuf.
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }

    /// Returns a reference to the inner PathBuf.
    pub fn inner(&self) -> &std::path::PathBuf {
        &self.inner
    }

    pub fn clamp(self) -> StagedPath<(S, Clamped)> {
        use std::path::Component;
        let mut stack: Vec<Component> = Vec::new();
        let components = self.inner.components();
        // Remove all root components (RootDir, Prefix) to force jail-relative
        for comp in components {
            match comp {
                Component::RootDir | Component::Prefix(_) => continue,
                Component::ParentDir => {
                    if let Some(last) = stack.last() {
                        if *last != Component::RootDir {
                            stack.pop();
                        }
                    }
                }
                Component::CurDir => {}
                other => stack.push(other),
            }
        }
        let mut normalized = std::path::PathBuf::new();
        for comp in stack {
            normalized.push(comp.as_os_str());
        }
        StagedPath {
            inner: normalized,
            _marker: std::marker::PhantomData,
        }
    }
    pub fn canonicalize(self) -> Result<StagedPath<(S, Canonicalized)>> {
        // Inline soft_canonicalize logic (assume soft_canonicalize::soft_canonicalize is available)
        let canon = soft_canonicalize(&self.inner)
            .map_err(|e| JailedPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(StagedPath {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }
    pub fn as_path(&self) -> &std::path::Path {
        &self.inner
    }
}

// Boundary check for canonicalized path, adds BoundaryChecked stage
// Only callable on StagedPath<(((S, Clamped), JoinedJail), Canonicalized)>
#[allow(clippy::type_complexity)]
impl<S> StagedPath<(((S, Clamped), JoinedJail), Canonicalized)> {
    pub fn boundary_check(
        self,
        jail: &StagedPath<(Raw, Canonicalized)>,
    ) -> Result<StagedPath<((((S, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>> {
        if !self.inner.starts_with(jail.as_path()) {
            return Err(JailedPathError::path_escapes_boundary(
                self.inner,
                jail.as_path().to_path_buf(),
            ));
        }
        Ok(StagedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}
