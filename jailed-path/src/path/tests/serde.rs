#[cfg(feature = "serde")]
mod serde_tests {
    use crate::validator::jail::Jail;
    use crate::validator::virtual_root::VirtualRoot;
    use crate::{path::jailed_path::JailedPath, path::virtual_path::VirtualPath};
    use serde::de::DeserializeSeed;

    #[test]
    fn serialize_jailed_and_virtual() {
        let td = tempfile::tempdir().unwrap();
        let jail = Jail::<()>::try_new(td.path()).unwrap();
        let jp: JailedPath = jail.try_path("a/b.txt").unwrap();
        let vp: VirtualPath = jp.clone().virtualize();

        let jp_json = serde_json::to_string(&jp).unwrap();
        let vp_json = serde_json::to_string(&vp).unwrap();

        // Deserialize back and assert path components in an OS-agnostic way
        let jp_str: String = serde_json::from_str(&jp_json).unwrap();
        let p = std::path::Path::new(&jp_str);
        assert_eq!(p.file_name().unwrap().to_string_lossy(), "b.txt");
        assert_eq!(
            p.parent().unwrap().file_name().unwrap().to_string_lossy(),
            "a"
        );

        // VirtualPath JSON is rooted and uses forward slashes
        assert_eq!(vp_json, "\"/a/b.txt\"");
    }

    #[test]
    fn deserialize_with_context_jailed() {
        let td = tempfile::tempdir().unwrap();
        let jail = Jail::<()>::try_new(td.path()).unwrap();

        let mut de = serde_json::Deserializer::from_str("\"alpha/beta.txt\"");
        let jp: JailedPath = crate::serde_ext::WithJail(&jail)
            .deserialize(&mut de)
            .unwrap();
        assert!(jp.systempath_starts_with(jail.path()));
    }

    #[test]
    fn deserialize_with_context_jailed_rejects_escape() {
        let td = tempfile::tempdir().unwrap();
        let jail = Jail::<()>::try_new(td.path()).unwrap();

        let mut de = serde_json::Deserializer::from_str("\"../../secret.txt\"");
        let err = crate::serde_ext::WithJail(&jail)
            .deserialize(&mut de)
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("boundary") || msg.contains("escape"),
            "msg={msg}"
        );
    }

    #[test]
    fn deserialize_with_context_virtual() {
        let td = tempfile::tempdir().unwrap();
        let vroot = VirtualRoot::<()>::try_new(td.path()).unwrap();

        let mut de = serde_json::Deserializer::from_str("\"../../etc/hosts\"");
        let vp: VirtualPath = crate::serde_ext::WithVirtualRoot(&vroot)
            .deserialize(&mut de)
            .unwrap();
        // Traversal is clamped to the virtual root
        assert_eq!(vp.virtualpath_to_string(), "/etc/hosts");
    }
}
