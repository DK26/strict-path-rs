// SCOPE NOTE: This Kani harness proves the component-array clamping invariant
// against a mock component enum (`MockComponent`). It does NOT prove the full
// `canonicalize_and_enforce_restriction_boundary` pipeline — the real pipeline
// depends on `soft-canonicalize` and OS-level symlink resolution, which are
// outside Kani's reach. Treat this as a structural proof of the virtualization
// algorithm (no ParentDir/RootDir survives clamping), not an end-to-end
// security proof. End-to-end guarantees come from the test suites in
// `src/path/tests/` and `src/validator/tests/`.
#[cfg(kani)]
mod verification {
    #[derive(Copy, Clone, Debug, kani::Arbitrary)]
    enum MockComponent {
        Normal,
        CurDir,
        ParentDir,
        RootDir,
        Prefix,
    }

    fn virtualize(components: &[MockComponent]) -> Vec<MockComponent> {
        let mut parts = Vec::new();
        for comp in components {
            match comp {
                MockComponent::Normal => parts.push(MockComponent::Normal),
                MockComponent::CurDir => {}
                MockComponent::ParentDir => {
                    if parts.pop().is_none() {
                        // At virtual root; ignore extra ".."
                    }
                }
                MockComponent::RootDir | MockComponent::Prefix => {
                    parts.clear();
                }
            }
        }
        parts
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_virtualize_clamping() {
        // Use a fixed-size array instead of Vec to work with Kani's Arbitrary trait
        let components: [MockComponent; 8] = kani::any();

        let result = virtualize(&components);

        // Invariant: the result must contain only Normal components — no traversal
        // (`ParentDir`), root resets (`RootDir`/`Prefix`), or no-ops (`CurDir`).
        // This proves virtual_join cannot produce a path that escapes the virtual root,
        // regardless of what components an attacker injects.
        for comp in &result {
            match comp {
                MockComponent::Normal => {}
                _ => panic!("Result contained non-Normal component: {:?}", comp),
            }
        }
    }
}
