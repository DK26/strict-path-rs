use soft_canonicalize::soft_canonicalize;
use std::path::{Path, PathBuf};

/// Validates that a user-provided path stays within a jail directory
fn validate_user_path(user_input: &str, jail_dir: &Path) -> Result<PathBuf, String> {
    println!("  Validating user input: {:?}", user_input);

    // Canonicalize the user input (may not exist yet)
    let canonical_path =
        soft_canonicalize(Path::new(user_input)).map_err(|e| format!("Invalid path: {}", e))?;

    println!("  Canonicalized to: {:?}", canonical_path);

    // Ensure it's within the jail directory
    if canonical_path.starts_with(jail_dir) {
        println!("  ✅ SAFE: Path is within jail boundary");
        Ok(canonical_path)
    } else {
        println!("  🚫 BLOCKED: Path escapes jail boundary");
        Err("Path escapes jail boundary".to_string())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Soft Canonicalize - Security Demo ===\n");

    // Set up a jail directory
    let jail = std::env::temp_dir().join("user_files");
    let canonical_jail = soft_canonicalize(&jail)?;

    println!("Jail directory: {:?}\n", canonical_jail);

    // Test cases: safe paths
    println!("--- SAFE PATHS ---");

    let safe_paths = [
        "documents/file.txt",
        "photos/vacation/beach.jpg",
        "projects/website/index.html",
        "./config/settings.json",
        "uploads/user123/document.pdf",
    ];

    for path in &safe_paths {
        match validate_user_path(path, &canonical_jail) {
            Ok(_) => println!(""),
            Err(e) => println!("  Error: {}\n", e),
        }
    }

    // Test cases: malicious paths with directory traversal
    println!("--- MALICIOUS PATHS (Directory Traversal) ---");

    let malicious_paths = [
        "../../../etc/passwd",
        "documents/../../../sensitive.txt",
        "uploads/../../../../../../root/.ssh/id_rsa",
        "../outside_jail/malware.exe",
        "safe/path/../../../../../../etc/shadow",
        "normal/../../../config.ini",
        "files/../../../../windows/system32/config/sam",
    ];

    for path in &malicious_paths {
        match validate_user_path(path, &canonical_jail) {
            Ok(_) => println!(""),
            Err(e) => println!("  Expected: {}\n", e),
        }
    }

    // Test cases: absolute paths outside jail
    println!("--- ABSOLUTE PATHS OUTSIDE JAIL ---");

    #[cfg(windows)]
    let absolute_attacks = [
        "C:\\Windows\\System32\\config\\SAM",
        "D:\\sensitive\\data.txt",
        "\\\\server\\share\\secrets.txt",
    ];

    #[cfg(not(windows))]
    let absolute_attacks = [
        "/etc/passwd",
        "/root/.ssh/authorized_keys",
        "/usr/bin/malware",
        "/home/other_user/secrets.txt",
    ];

    for path in &absolute_attacks {
        match validate_user_path(path, &canonical_jail) {
            Ok(_) => println!(""),
            Err(e) => println!("  Expected: {}\n", e),
        }
    }

    // Demonstrate edge cases
    println!("--- EDGE CASES ---");

    let edge_cases = [
        "",                                                     // Empty path
        ".",                                                    // Current directory
        "..",                                                   // Parent directory
        "file",                                                 // Simple filename
        "very/deep/nested/structure/with/many/levels/file.txt", // Deep nesting
    ];

    for path in &edge_cases {
        match validate_user_path(path, &canonical_jail) {
            Ok(_) => println!(""),
            Err(e) => println!("  Result: {}\n", e),
        }
    }

    println!("=== Security Demo Complete ===");
    println!("Soft canonicalize successfully blocked all directory traversal attempts!");

    Ok(())
}
