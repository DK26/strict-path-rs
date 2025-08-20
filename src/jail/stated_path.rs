use crate::{JailedPathError, Result};
use soft_canonicalize::soft_canonicalize;
use std::ops::Deref;
use std::path::Path;

// --- Type-State Markers ---
#[derive(Debug, Clone)]
/// The original, unchecked path as provided by the user.
pub struct Raw;
#[derive(Debug, Clone)]
/// Path after canonicalization (symlinks resolved, absolute).
pub struct Canonicalized;
/// Path after boundary check against the jail root.
#[derive(Debug, Clone)]
pub struct BoundaryChecked;
#[derive(Debug, Clone)]
/// Marker indicating that the file exists on the filesystem.
pub struct Exists;

/// # Understanding `StatedPath` (type-history)
///
/// `StatedPath<State>` uses a compact type-history pattern: each marker in the
/// `State` tuple documents a security-relevant transformation applied to the path
/// (for example: `Raw`, `Virtualized`, `JailJoined`, `Canonicalized`,
/// `BoundaryChecked`). This makes it harder to accidentally skip critical
/// validation steps because the compiler enforces the sequence.
///
/// Example: create a temporary jail and validate a virtual path inside it.
///
/// ```rust
/// use jailed_path::jail::stated_path::{StatedPath, Raw, Canonicalized, BoundaryChecked};
/// use tempfile::tempdir;
/// use std::fs;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // create a temporary directory to serve as the jail
///     let tmp = tempdir()?;
///     let jail_dir = tmp.path().join("jail");
///     fs::create_dir_all(&jail_dir)?;
///
///     // canonicalize and verify the jail exists to obtain the exact required type
///     let jail = StatedPath::<Raw>::new(&jail_dir).canonicalize().unwrap().verify_exists().unwrap();
///
///     // The high-level API will virtualize and join a user-supplied path to the jail for you.
///     // We avoid calling `canonicalize()` directly on a relative user path here since its
///     // resolution depends on the process CWD; the crate's public helpers perform the
///     // safe virtualization -> join -> canonicalize -> boundary_check sequence for you.
///     # Ok(())
/// }
/// ```
///
/// The `State` type parameter therefore serves as a compile-time log of the
/// processing steps applied to a path.
#[derive(Debug, Clone)]
pub struct StatedPath<State> {
    inner: std::path::PathBuf,
    _marker: std::marker::PhantomData<State>,
}

impl<S> AsRef<Path> for StatedPath<S> {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.inner
    }
}

impl<S> Deref for StatedPath<S> {
    type Target = Path;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl StatedPath<Raw> {
    #[inline]
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Self {
        StatedPath {
            inner: path.as_ref().to_path_buf(),
            _marker: std::marker::PhantomData,
        }
    }
    // Only new() is implemented for ValidatedPath<Raw>. All transitions are on impl<S> ValidatedPath<S>.
}

// join_jail now requires the jail to be a canonicalized path (no unconstrained S2)
// impl<S> StatedPath<(S, Virtualized)> {
//     #[inline]
//     pub fn join_jail(
//         self,
//         jail: &StatedPath<((Raw, Canonicalized), Exists)>,
//     ) -> StatedPath<((S, Virtualized), JailJoined)> {
//         let joined = jail.inner.join(self.inner);
//         StatedPath {
//             inner: joined,
//             _marker: std::marker::PhantomData,
//         }
//     }
// }

impl<S> StatedPath<S> {
    /// Consumes the ValidatedPath and returns the inner PathBuf.
    #[inline]
    pub fn into_inner(self) -> std::path::PathBuf {
        self.inner
    }

    // /// Clamps and removes the root, so it can be joined as virutal path to another path (a jail)
    // pub fn virtualize(self) -> StatedPath<(S, Virtualized)> {
    //     use std::path::Component;
    //     let mut normalized = std::path::PathBuf::new();
    //     let mut depth = 0i32; // Track how deep we are from the jail root

    //     let components = self.inner.components();
    //     // Remove all root components (RootDir, Prefix) and implement clamping
    //     for comp in components {
    //         match comp {
    //             Component::RootDir | Component::Prefix(_) => continue, // Strip absolute paths
    //             Component::CurDir => continue, // Skip current directory references
    //             Component::ParentDir => {
    //                 // This is the clamping logic - if we're at the jail root (depth 0),
    //                 // ignore parent directory attempts (clamp to jail root)
    //                 if depth > 0 {
    //                     normalized.pop(); // Go up one level
    //                     depth -= 1;
    //                 }
    //                 // If depth == 0, we're at jail root, so ignore the ".." (clamp)
    //             }
    //             Component::Normal(name) => {
    //                 normalized.push(name);
    //                 depth += 1;
    //             }
    //         }
    //     }

    //     StatedPath {
    //         inner: normalized,
    //         _marker: std::marker::PhantomData,
    //     }
    // }

    pub fn canonicalize(self) -> Result<StatedPath<(S, Canonicalized)>> {
        // Inline soft_canonicalize logic (assume soft_canonicalize::soft_canonicalize is available)
        let canon = soft_canonicalize(&self.inner)
            .map_err(|e| JailedPathError::path_resolution_error(self.inner.clone(), e))?;
        Ok(StatedPath {
            inner: canon,
            _marker: std::marker::PhantomData,
        })
    }

    pub fn verify_exists(self) -> Option<StatedPath<(S, Exists)>> {
        self.inner.exists().then_some(StatedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}

// Boundary check for canonicalized path, adds BoundaryChecked stage
// Only callable on ValidatedPath<(((S, RootStripped), JoinedJail), Canonicalized)>
#[allow(clippy::type_complexity)]
impl<S> StatedPath<(S, Canonicalized)> {
    #[inline]
    pub fn boundary_check(
        self,
        jail: &StatedPath<((Raw, Canonicalized), Exists)>,
    ) -> Result<StatedPath<((S, Canonicalized), BoundaryChecked)>> {
        if !self.starts_with(jail) {
            return Err(JailedPathError::path_escapes_boundary(
                self.into_inner(),
                jail.to_path_buf(),
            ));
        }
        Ok(StatedPath {
            inner: self.inner,
            _marker: std::marker::PhantomData,
        })
    }
}
