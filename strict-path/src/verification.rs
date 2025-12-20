#[cfg(kani)]
mod verification {
    #[derive(Copy, Clone, kani::Arbitrary)]
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
    fn verify_virtualize_clamping() {
        let components: Vec<MockComponent> = kani::any();
        // Limit length to avoid state explosion
        kani::assume(components.len() <= 8);

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
