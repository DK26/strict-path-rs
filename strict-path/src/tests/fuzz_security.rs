#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
use crate::{PathBoundary, StrictPathError};
use std::path::PathBuf;

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }
    fn next_range(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % max
    }
    fn next_bool(&mut self) -> bool {
        self.next_u64() % 2 == 0
    }
}

fn generate_random_path(rng: &mut Lcg, depth: usize) -> String {
    let components = [
        ".",
        "..",
        "foo",
        "bar",
        "baz",
        "etc",
        "passwd",
        "windows",
        "system32",
        "/",
        "\\",
        "mixed/sep",
        "mixed\\sep",
        "nul\0byte",
    ];
    let mut path = String::new();

    // Maybe start with a root
    if rng.next_bool() {
        if cfg!(windows) {
            path.push_str("C:\\");
        } else {
            path.push('/');
        }
    }

    for i in 0..depth {
        if i > 0 {
            if rng.next_bool() {
                path.push('/');
            } else {
                path.push('\\');
            }
        }
        let idx = rng.next_range(components.len());
        path.push_str(components[idx]);
    }
    path
}

#[test]
fn fuzz_strict_join_security_invariant() {
    let temp = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::<()>::try_new(temp.path()).unwrap();
    let boundary_path = PathBuf::from(boundary.interop_path());

    let mut rng = Lcg::new(12345);

    for _ in 0..1000 {
        let depth = rng.next_range(10) + 1;
        let input = generate_random_path(&mut rng, depth);

        match boundary.strict_join(&input) {
            Ok(strict_path) => {
                // Invariant: If strict_join succeeds, the path MUST be inside the boundary
                let resolved = strict_path.interop_path();
                // We need to canonicalize to compare properly because strict_path is canonicalized
                // and boundary_path is also canonicalized (by try_new).
                // But strict_path.interop_path() returns the path stored in StrictPath which is already canonicalized.

                // Check if it starts with boundary
                // Note: On Windows, canonicalization might add \\?\ prefix.
                // PathBoundary handles this internally, but for raw comparison we need to be careful.
                // strict_path.strictpath_starts_with(boundary.interop_path()) is the correct check.

                assert!(
                    strict_path.strictpath_starts_with(&boundary_path),
                    "Security invariant violated! Path escaped boundary.\nInput: {:?}\nResult: {:?}\nBoundary: {:?}",
                    input,
                    resolved,
                    boundary_path
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. }) => {
                // Expected for malicious paths
            }
            Err(StrictPathError::PathResolutionError { .. }) => {
                // Expected for invalid paths (e.g. null bytes, non-existent components if we checked existence)
                // strict_join checks existence of the *boundary* but not necessarily the *result* unless we use strict_join_check_exists?
                // strict_join does NOT check existence of the target, only that it resolves to a path inside boundary.
                // However, canonicalize() might fail if components don't exist?
                // soft_canonicalize handles non-existent paths.
                // But if the path contains null bytes, it might fail.
            }
            Err(e) => {
                // Other errors are fine, but we shouldn't panic
                println!("Fuzz input '{:?}' caused error: {:?}", input, e);
            }
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn fuzz_virtual_join_clamping_invariant() {
    let temp = tempfile::tempdir().unwrap();
    let vroot = VirtualRoot::<()>::try_new(temp.path()).unwrap();
    let boundary_path = PathBuf::from(vroot.interop_path());

    let mut rng = Lcg::new(67890);

    for _ in 0..1000 {
        let depth = rng.next_range(10) + 1;
        let input = generate_random_path(&mut rng, depth);

        match vroot.virtual_join(&input) {
            Ok(vpath) => {
                // Invariant 1: Must be inside boundary
                assert!(
                    vpath.as_unvirtual().strictpath_starts_with(&boundary_path),
                    "Virtual invariant violated! Path escaped boundary.\nInput: {:?}\nResult: {:?}\nBoundary: {:?}",
                    input,
                    vpath.interop_path(),
                    boundary_path
                );

                // Invariant 2: Display path must be rooted
                let display = vpath.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display not rooted: {}",
                    display
                );

                // Invariant 3: Display path must not contain ..
                assert!(
                    !display.contains("/../") && !display.ends_with("/.."),
                    "Virtual display contains traversal: {}",
                    display
                );
            }
            Err(e) => {
                // Virtual join should generally succeed unless there are resolution errors (e.g. null bytes)
                // It shouldn't return PathEscapesBoundary because it clamps.
                if let StrictPathError::PathEscapesBoundary { .. } = e {
                    panic!(
                        "virtual_join should clamp, not error on escape! Input: {:?}",
                        input
                    );
                }
            }
        }
    }
}
