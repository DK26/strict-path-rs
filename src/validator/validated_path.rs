use crate::{JailedPathError, Result};
use soft_canonicalize::soft_canonicalize;
use std::ops::Deref;
use std::path::Path;

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

/// # Understanding `ValidatedPath` Type Parameters
///
/// `ValidatedPath<State>` uses Rust’s type system to track the exact sequence of security-relevant
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
/// use jailed_path::validator::validated_path::{ValidatedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// // This type means: Raw -> Clamped -> JoinedJail -> Canonicalized -> BoundaryChecked
/// type SecurePath = ValidatedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
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
/// use jailed_path::validator::validated_path::{ValidatedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// let jail = ValidatedPath::<Raw>::new("/jail").canonicalize().unwrap();
/// let validated = ValidatedPath::new("user_upload.txt")
///     .clamp()
///     .join_jail(&jail)
///     .canonicalize().unwrap()
///     .boundary_check(&jail).unwrap();
/// // validated: ValidatedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Type Aliases for Common States
///
/// For convenience, you may define type aliases for common state combinations:
///
/// ```rust
/// use jailed_path::validator::validated_path::{ValidatedPath, Raw, Clamped, JoinedJail, Canonicalized, BoundaryChecked};
/// type FullyChecked = ValidatedPath<((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>;
/// ```
///
/// ## Advanced Usage
///
/// You can branch or skip steps (if your security policy allows), and the type will always reflect the actual processing history.
///
/// ---
///
/// **In summary:**  
/// The `ValidatedPath` type parameter is a type-level log of all security-relevant processing steps applied to a path.
#[derive(Debug, Clone)]
pub struct ValidatedPath<State> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<State>,
}

impl<S> AsRef<Path> for ValidatedPath<S> {
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

impl<S> Deref for ValidatedPath<S> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ValidatedPath<Raw> {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Self {
        ValidatedPath {
            inner: path.as_ref().to_path_buf(),
            _marker: std::marker::PhantomData,
        }
    }
    // Only new() is implemented for ValidatedPath<Raw>. All transitions are on impl<S> ValidatedPath<S>.
}

// join_jail now requires the jail to be a canonicalized path (no unconstrained S2)
impl<S> ValidatedPath<(S, Clamped)> {
    pub fn join_jail(
        self,
        jail: &ValidatedPath<(Raw, Canonicalized)>,
    ) -> ValidatedPath<((S, Clamped), JoinedJail)> {
        let joined = jail.inner.join(self.inner);
        ValidatedPath {
            inner: joined,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> ValidatedPath<S> {
    /// Consumes the ValidatedPath and returns the inner PathBuf.
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }

    pub fn clamp(self) -> ValidatedPath<(S, Clamped)> {
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
        ValidatedPath {
            inner: normalized,
            _marker: std::marker::PhantomData,
        }
    }
    pub fn canonicalize(self) -> Result<ValidatedPath<(S, Canonicalized)>> {
        // Inline soft_canonicalize logic (assume soft_canonicalize::soft_canonicalize is available)
        let canon = soft_canonicalize(&self.inner)
            .map_err(|e| JailedPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(ValidatedPath {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }
}

// Boundary check for canonicalized path, adds BoundaryChecked stage
// Only callable on ValidatedPath<(((S, Clamped), JoinedJail), Canonicalized)>
#[allow(clippy::type_complexity)]
impl<S> ValidatedPath<(((S, Clamped), JoinedJail), Canonicalized)> {
    pub fn boundary_check(
        self,
        jail: &ValidatedPath<(Raw, Canonicalized)>,
    ) -> Result<ValidatedPath<((((S, Clamped), JoinedJail), Canonicalized), BoundaryChecked)>> {
        if !self.starts_with(jail) {
            return Err(JailedPathError::path_escapes_boundary(
                self.into_inner(),
                jail.to_path_buf(),
            ));
        }
        Ok(ValidatedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}
