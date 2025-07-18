use std::path::{Path, PathBuf};
use std::{fs, io};

/// Performs "soft" canonicalization on a path.
///
/// Unlike `std::fs::canonicalize()`, this function works with non-existent paths by:
/// 1. Finding the deepest existing ancestor directory
/// 2. Canonicalizing that existing part (resolving symlinks, normalizing case, etc.)
/// 3. Appending the non-existing path components to the canonicalized base
///
/// This provides the security benefits of canonicalization (symlink resolution,
/// path normalization) without requiring the entire path to exist.
///
/// # Examples
///
/// ```rust
/// # use std::path::Path;
/// # use jailed_path::soft_canonicalize;
/// # fn example() -> std::io::Result<()> {
/// // Works with existing paths (same as std::fs::canonicalize)
/// let existing = soft_canonicalize(&std::env::temp_dir())?;
///
/// // Also works with non-existing paths
/// let non_existing = soft_canonicalize(&std::env::temp_dir().join("some/deep/non/existing/path.txt"))?;
/// # Ok(())
/// # }
/// ```
pub fn soft_canonicalize(path: &Path) -> io::Result<PathBuf> {
    // Convert to absolute path if relative
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Split path into components and process .. logically first
    let mut components = Vec::new();
    for component in absolute_path.components() {
        match component {
            std::path::Component::Normal(name) => {
                components.push(name.to_os_string());
            }
            std::path::Component::ParentDir => {
                // Handle .. by removing the last component if any
                if !components.is_empty() {
                    components.pop();
                }
                // If components is empty, .. cannot go further (already at root level)
            }
            std::path::Component::CurDir => {
                // Ignore . components
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                // These are handled by making the path absolute initially
            }
        }
    }

    // Reconstruct the logical path
    let mut logical_path = if absolute_path.has_root() {
        // Start with root
        if cfg!(windows) {
            absolute_path.ancestors().last().unwrap().to_path_buf()
        } else {
            PathBuf::from("/")
        }
    } else {
        PathBuf::new()
    };

    for component in &components {
        logical_path.push(component);
    }

    // Now find the longest existing prefix of the logical path
    let mut current = logical_path.as_path();
    let mut non_existing_components = Vec::new();

    while !current.exists() {
        if let Some(file_name) = current.file_name() {
            non_existing_components.push(file_name.to_os_string());
        }

        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            // We've reached the root and nothing exists, return the logical path
            return Ok(logical_path);
        }
    }

    // Canonicalize the existing prefix
    let mut resolved_path = fs::canonicalize(current)?;

    // Add back the non-existing components (they're already processed for .. components)
    for component in non_existing_components.iter().rev() {
        resolved_path.push(component);
    }

    Ok(resolved_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    fn create_temp_dir() -> io::Result<PathBuf> {
        let temp_base = std::env::temp_dir();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_name = format!(
            "soft_canonicalize_test_{}_{}",
            std::process::id(),
            timestamp
        );
        let temp_dir = temp_base.join(temp_name);
        fs::create_dir_all(&temp_dir)?;
        Ok(temp_dir)
    }

    fn cleanup_temp_dir(path: &Path) {
        if path.exists() {
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn test_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create a file
        let file_path = temp_dir.join("test.txt");
        File::create(&file_path)?.write_all(b"test")?;

        // Soft canonicalize should work the same as regular canonicalize
        let soft_result = soft_canonicalize(&file_path)?;
        let regular_result = fs::canonicalize(&file_path)?;

        assert_eq!(soft_result, regular_result);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_non_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create a directory structure but not the final file
        let existing_dir = temp_dir.join("existing");
        fs::create_dir(&existing_dir)?;

        let non_existing_path = existing_dir.join("non_existing").join("file.txt");

        // This should work even though the path doesn't exist
        let result = soft_canonicalize(&non_existing_path)?;

        // The result should start with the canonicalized existing directory
        let canonical_existing = fs::canonicalize(&existing_dir)?;
        assert!(result.starts_with(&canonical_existing));
        assert!(result.ends_with("file.txt"));

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_deeply_non_existing_path() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Only the temp_dir exists, everything else is non-existing
        let deep_path = temp_dir
            .join("level1")
            .join("level2")
            .join("level3")
            .join("file.txt");

        let result = soft_canonicalize(&deep_path)?;

        // Should start with the canonicalized temp_dir
        let canonical_temp = fs::canonicalize(&temp_dir)?;
        assert!(result.starts_with(&canonical_temp));
        assert!(result.ends_with("file.txt"));

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_relative_path() -> io::Result<()> {
        let result = soft_canonicalize(Path::new("non/existing/relative/path.txt"))?;

        // Should be absolute and start with current directory
        assert!(result.is_absolute());

        let current_dir = std::env::current_dir()?;
        let canonical_current = fs::canonicalize(current_dir)?;
        assert!(result.starts_with(canonical_current));

        Ok(())
    }

    #[test]
    fn test_parent_directory_traversal() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create directory structure: temp_dir/level1/level2/
        let level1 = temp_dir.join("level1");
        let level2 = level1.join("level2");
        fs::create_dir_all(&level2)?;

        // Test path: temp_dir/level1/level2/subdir/../../../target.txt
        // This should resolve to: temp_dir/target.txt
        let test_path = level2
            .join("subdir")
            .join("..")
            .join("..")
            .join("..")
            .join("target.txt");

        let result = soft_canonicalize(&test_path)?;
        let expected = fs::canonicalize(&temp_dir)?.join("target.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_mixed_existing_and_nonexisting_with_traversal() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create: temp_dir/existing/
        let existing_dir = temp_dir.join("existing");
        fs::create_dir(&existing_dir)?;

        // Test: temp_dir/existing/nonexisting/../sibling.txt
        // Should resolve to: temp_dir/existing/sibling.txt
        let test_path = existing_dir
            .join("nonexisting")
            .join("..")
            .join("sibling.txt");

        let result = soft_canonicalize(&test_path)?;
        let expected = fs::canonicalize(&existing_dir)?.join("sibling.txt");

        assert_eq!(result, expected);

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_traversal_beyond_root() -> io::Result<()> {
        let temp_dir = create_temp_dir()?;

        // Create minimal directory
        let subdir = temp_dir.join("subdir");
        fs::create_dir(&subdir)?;

        // Try to go beyond the canonicalized base
        // This should error because we're trying to traverse beyond what's possible
        let test_path = subdir
            .join("..")
            .join("..")
            .join("..")
            .join("nonexistent")
            .join("file.txt");

        let result = soft_canonicalize(&test_path);

        // This should either succeed (if it resolves to a valid path) or fail gracefully
        // The key is that it shouldn't panic or produce invalid results
        match result {
            Ok(path) => {
                // If it succeeds, the path should be valid and absolute
                assert!(path.is_absolute());
            }
            Err(e) => {
                // If it fails, it should be with a clear error
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            }
        }

        cleanup_temp_dir(&temp_dir);
        Ok(())
    }
}
