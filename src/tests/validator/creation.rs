use crate::validator::PathValidator;
use crate::JailedPathError;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

/// Creates cross-platform attack target paths for testing
#[allow(dead_code)]
fn get_attack_target_paths() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        vec![
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "D:\\sensitive\\data.txt",
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "/etc/passwd",
            "/usr/bin/malware",
            "/root/.ssh/authorized_keys",
            "/home/user/secrets.txt",
        ]
    }
}

fn create_test_directory() -> std::io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let thread_id = COUNTER.fetch_add(1, Ordering::SeqCst);

    let temp_base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let temp_dir = temp_base.join(format!("jailed_path_test_{}_{}_{}", std::process::id(), thread_id, nanos));

    // Create the main test directory
    fs::create_dir_all(&temp_dir)?;

    // Create a subdirectory structure for testing
    let sub_dir = temp_dir.join("subdir");
    fs::create_dir(&sub_dir)?;

    // Create a test file in the jail
    let test_file = temp_dir.join("test.txt");
    let mut file = fs::File::create(test_file)?;
    writeln!(file, "test content")?;

    // Create a test file in subdirectory
    let sub_file = sub_dir.join("sub_test.txt");
    let mut file = fs::File::create(sub_file)?;
    writeln!(file, "sub test content")?;

    Ok(temp_dir)
}

fn cleanup_test_directory(path: &std::path::Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

#[test]
fn test_pathvalidator_creation_with_existing_directory() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let result = PathValidator::<()>::with_jail(&temp_dir);
    assert!(result.is_ok(), "Should succeed with existing directory");
    let validator = result.unwrap();
    assert_eq!(validator.jail(), temp_dir.canonicalize().unwrap());
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_valid_relative_path() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should successfully validate existing file with relative path
    let result = validator.try_path("test.txt");
    assert!(
        result.is_ok(),
        "try_path should succeed with valid relative path"
    );

    let jailed_path = result.unwrap();
    assert!(
        jailed_path.real_path().ends_with("test.txt"),
        "JailedPath should point to the correct file"
    );
    assert!(
        jailed_path.real_path().starts_with(validator.jail()),
        "JailedPath should be within jail boundary"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_valid_subdirectory_path() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should successfully validate file in subdirectory
    let result = validator.try_path("subdir/sub_test.txt");
    assert!(
        result.is_ok(),
        "try_path should succeed with valid subdirectory path"
    );

    let jailed_path = result.unwrap();
    assert!(
        jailed_path.real_path().ends_with("sub_test.txt"),
        "JailedPath should point to the correct file"
    );
    assert!(
        jailed_path.real_path().starts_with(validator.jail()),
        "JailedPath should be within jail boundary"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_absolute_path_inside_jail() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should allow absolute path that's within the jail
    let absolute_path = temp_dir.join("test.txt");
    let result = validator.try_path(absolute_path);
    assert!(
        result.is_ok(),
        "try_path should allow absolute path within jail"
    );

    let jailed_path = result.unwrap();
    let jail_root = temp_dir.canonicalize().unwrap();
    let clamped_path = jailed_path
        .real_path()
        .canonicalize()
        .unwrap_or_else(|_| jailed_path.real_path().to_path_buf());
    assert!(
        clamped_path.starts_with(&jail_root) || clamped_path.parent() == Some(&jail_root),
        "Clamped absolute path should be at jail root or its parent: {}",
        clamped_path.display()
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_nonexistent_file() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should successfully validate non-existent file using touch technique
    let result = validator.try_path("user123/new_document.pdf");
    assert!(
        result.is_ok(),
        "try_path should succeed with non-existent file using touch technique"
    );

    let jailed_path = result.unwrap();
    assert!(jailed_path.real_path().ends_with("new_document.pdf"));
    assert!(jailed_path.real_path().starts_with(validator.jail()));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_nonexistent_nested_file() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should create parent directories and validate deeply nested non-existent file
    let result = validator.try_path("users/john/photos/vacation/beach.jpg");
    assert!(
        result.is_ok(),
        "try_path should succeed with deeply nested non-existent file"
    );

    let jailed_path = result.unwrap();
    assert!(jailed_path.real_path().ends_with("beach.jpg"));
    assert!(jailed_path.real_path().starts_with(validator.jail()));

    // SECURITY: Verify parent directories were cleaned up for anti-spam protection
    let parent_dir = temp_dir.join("users/john/photos/vacation");
    assert!(
        !parent_dir.exists(),
        "Parent directories should be cleaned up for security"
    );

    // Even the top-level directory should be cleaned up
    let top_dir = temp_dir.join("users");
    assert!(
        !top_dir.exists(),
        "All created directories should be cleaned up"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_with_mixed_existing_and_nonexistent() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Create some existing structure
    let existing_dir = temp_dir.join("existing_user");
    std::fs::create_dir(existing_dir).unwrap();

    // Should validate path that goes through existing directory to non-existent file
    let result = validator.try_path("existing_user/new_file.txt");
    assert!(
        result.is_ok(),
        "try_path should handle existing directory + non-existent file"
    );

    let jailed_path = result.unwrap();
    assert!(jailed_path.real_path().starts_with(validator.jail()));
    assert!(jailed_path.real_path().ends_with("new_file.txt"));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_preserves_file_after_validation() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    let test_path = "user123/document.pdf";
    let full_expected_path = temp_dir.join(test_path);

    // Validate non-existent path
    let result = validator.try_path(test_path);
    assert!(result.is_ok());

    // The temporary file should be cleaned up
    assert!(
        !full_expected_path.exists(),
        "Temporary file should be cleaned up after validation"
    );

    // SECURITY: Parent directories should also be cleaned up to prevent spam
    assert!(
        !full_expected_path.parent().unwrap().exists(),
        "Parent directories should be cleaned up for security (anti-spam protection)"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_handles_permission_errors_gracefully() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Try to create file in a location that might have permission issues
    // This test behavior may vary by platform, but should not panic
    let result = validator.try_path("restricted/file.txt");

    // Should either succeed or fail gracefully with a clear error
    match result {
        Ok(jailed_path) => {
            assert!(jailed_path.real_path().starts_with(validator.jail()));
        }
        Err(JailedPathError::PathResolutionError { .. }) => {
            // Acceptable - permission denied or other IO error
        }
        Err(other) => {
            panic!("Unexpected error type: {other:?}");
        }
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_edge_case_empty_relative_path() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Test edge case: empty or current directory path
    let edge_cases = vec![".", "./", "./file.txt", "file.txt"];

    for path in edge_cases {
        let result = validator.try_path(path);
        if let Ok(jailed_path) = result {
            assert!(jailed_path.real_path().starts_with(validator.jail()));
        }
        // Some of these might fail, which is acceptable behavior
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_performance_with_many_validations() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Test that multiple validations work correctly
    let test_paths = [
        "user1/file1.txt",
        "user2/documents/file2.pdf",
        "user3/photos/vacation.jpg",
        "shared/document.docx",
        "temp/upload.tmp",
    ];

    for (i, path) in test_paths.iter().enumerate() {
        let result = validator.try_path(path);
        assert!(
            result.is_ok(),
            "Validation #{} should succeed for path: {path}",
            i + 1
        );

        let jailed_path = result.unwrap();
        assert!(jailed_path.real_path().starts_with(validator.jail()));
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_marker_types_for_compile_time_safety() {
    // Define test marker types
    struct ImageResource;
    struct UserData;

    let temp_dir = create_test_directory().expect("Failed to create temp directory");

    // Create validators with different marker types
    let image_validator: PathValidator<ImageResource> =
        PathValidator::with_jail(&temp_dir).unwrap();
    let user_validator: PathValidator<UserData> = PathValidator::with_jail(&temp_dir).unwrap();

    // Both should work with the same file but produce different marker types
    let image_path: crate::JailedPath<ImageResource> =
        image_validator.try_path("test.txt").unwrap();
    let user_path: crate::JailedPath<UserData> = user_validator.try_path("test.txt").unwrap();

    // Paths should be the same but have different types (checked at compile time)
    assert_eq!(image_path.real_path(), user_path.real_path());

    // This ensures the PhantomData marker is working and size is consistent
    let expected_size = std::mem::size_of::<PathBuf>() + std::mem::size_of::<Arc<PathBuf>>();
    assert_eq!(
        std::mem::size_of::<crate::JailedPath<ImageResource>>(),
        expected_size,
        "JailedPath should have consistent size regardless of marker type"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_validator_jail_accessor() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // jail() method should return the canonical jail path
    let jail_path = validator.jail();
    assert_eq!(jail_path, temp_dir.canonicalize().unwrap());

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
#[allow(clippy::redundant_clone)]
fn test_validator_clone_and_debug() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Should be cloneable
    let cloned_validator = validator.clone();
    assert_eq!(validator.jail(), cloned_validator.jail());

    // Should be debuggable (just ensure it doesn't panic)
    let debug_str = format!("{validator:?}");
    assert!(debug_str.contains("PathValidator"));

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_anti_directory_spam_protection() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Test deep nested path that would create many directories
    let deep_path = "spam1/spam2/spam3/spam4/spam5/spam6/spam7/spam8/spam9/spam10/file.txt";

    // Capture directory state before validation
    let initial_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    // Validate the deep path
    let result = validator.try_path(deep_path);
    assert!(result.is_ok(), "Deep path validation should succeed");

    // Check that no spam directories were left behind
    let final_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    // Should have same number of entries (no spam directories left)
    assert_eq!(
        initial_entries.len(),
        final_entries.len(),
        "Directory count should be the same after validation - no spam directories"
    );

    // Specifically check that spam1 directory was not left behind
    let spam_dir = temp_dir.join("spam1");
    assert!(
        !spam_dir.exists(),
        "Spam directory should be completely cleaned up: {spam_dir:?}"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_preserves_existing_directories() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Create an existing directory structure
    let existing_path = temp_dir.join("existing");
    std::fs::create_dir(&existing_path).unwrap();
    let nested_existing = existing_path.join("nested");
    std::fs::create_dir(&nested_existing).unwrap();

    // Validate a file in the existing structure + new subdirectory
    let result = validator.try_path("existing/nested/new_subdir/file.txt");
    assert!(
        result.is_ok(),
        "Path with existing + new directories should work"
    );

    // Existing directories should still exist
    assert!(existing_path.exists(), "Existing directory should remain");
    assert!(
        nested_existing.exists(),
        "Nested existing directory should remain"
    );

    // But the new subdirectory should be cleaned up
    let new_subdir = nested_existing.join("new_subdir");
    assert!(
        !new_subdir.exists(),
        "New subdirectory should be cleaned up: {new_subdir:?}"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_try_path_cleanup_on_canonicalization_error() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Try to create a path that will fail during canonicalization
    // We'll use a very long path name that might hit OS limits
    let problematic_path = format!(
        "{}{}",
        "a/".repeat(1000), // Very deep nesting
        "x".repeat(300)    // Very long filename
    );

    let initial_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    // This should fail but not leave directories behind
    let _result = validator.try_path(problematic_path);

    // Regardless of success/failure, no directories should be left
    let final_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    assert_eq!(
        initial_entries.len(),
        final_entries.len(),
        "No directories should be left behind even on error"
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_massive_directory_spam_attack_prevention() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Capture initial state
    let initial_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    // Simulate massive spam attack with many deep paths
    let spam_paths = vec![
        "spam_attack_1/level1/level2/level3/level4/level5/file.txt",
        "spam_attack_2/a/b/c/d/e/f/g/h/i/j/file.txt",
        "spam_attack_3/very/deep/nested/structure/with/many/levels/file.txt",
        "spam_attack_4/user1/data/photos/2024/vacation/beach/file.jpg",
        "spam_attack_5/projects/web/assets/images/thumbnails/file.png",
        "spam_attack_6/documents/work/reports/2024/q1/analysis/file.pdf",
        "spam_attack_7/cache/temp/processing/batch1/output/file.tmp",
        "spam_attack_8/logs/application/debug/2024/07/18/file.log",
        "spam_attack_9/backup/incremental/daily/week1/data/file.bak",
        "spam_attack_10/system/config/modules/auth/settings/file.cfg",
    ];

    // Attempt all spam attacks
    for spam_path in &spam_paths {
        let result = validator.try_path(spam_path);
        // Should succeed (paths are valid within jail)
        assert!(result.is_ok(), "Spam path should validate: {spam_path}");
    }

    // CRITICAL: Verify NO spam directories were left behind
    let final_entries: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    assert_eq!(
        initial_entries.len(),
        final_entries.len(),
        "Directory count should be identical - no spam directories left behind"
    );

    // Specifically verify that none of the spam directories exist
    for spam_path in &spam_paths {
        let spam_root = temp_dir.join(spam_path.split('/').next().unwrap());
        assert!(
            !spam_root.exists(),
            "Spam directory should not exist: {spam_root:?}"
        );
    }

    println!(
        "✅ Successfully prevented directory spam attack with {} attempts",
        spam_paths.len()
    );

    // Cleanup
    cleanup_test_directory(&temp_dir);
}

#[test]
fn test_lexical_validation_allows_legitimate_paths() {
    let temp_dir = create_test_directory().expect("Failed to create temp directory");
    let validator = PathValidator::<()>::with_jail(&temp_dir).unwrap();

    // Test cases that should be allowed (no actual ".." components)
    let legitimate_paths = vec![
        // Normal paths
        "file.txt",
        "subdir/file.txt",
        "users/john/documents/report.pdf",
        "data/2024/january/backup.zip",
        // Paths with ".." in filenames (not as path components)
        "..file.txt",              // filename starts with ..
        "file..txt",               // filename contains ..
        "my_file...extension",     // multiple dots
        "documents/..hidden_file", // hidden file starting with ..
        "config/app..backup.conf", // .. inside filename
        // Current directory references (allowed)
        "./file.txt",
        "subdir/./file.txt",
        "./subdir/file.txt",
        // Complex legitimate paths
        "user_data/projects/website/assets/images/logo.png",
        "exports/reports/2024/Q1/financial_summary.xlsx",
        "uploads/profile_pics/user_12345/avatar.jpg",
    ];

    for legitimate_path in legitimate_paths {
        let result = validator.try_path(legitimate_path);

        // Should either succeed or fail with PathResolutionError (file doesn't exist)
        // but never with PathEscapesBoundary
        match result {
            Ok(_) => {
                println!("✅ Correctly allowed (exists): {legitimate_path}");
            }
            Err(JailedPathError::PathResolutionError { .. }) => {
                println!("✅ Correctly allowed (doesn't exist): {legitimate_path}");
            }
            Err(JailedPathError::PathEscapesBoundary { .. }) => {
                panic!("Legitimate path should not be blocked as escape: {legitimate_path}");
            }
            Err(other) => {
                panic!("Unexpected error for legitimate path '{legitimate_path}': {other:?}");
            }
        }
    }

    // Cleanup
    cleanup_test_directory(&temp_dir);
}
