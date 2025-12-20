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

        // Property: The result should only contain Normal components.
        // This proves that the virtualization logic effectively strips all
        // traversal (ParentDir), root resets (RootDir/Prefix), and no-ops (CurDir),
        // leaving only a safe relative path.
        for comp in &result {
            match comp {
                MockComponent::Normal => {}
                _ => panic!("Result contained non-Normal component: {:?}", comp),
            }
        }
    }
}
