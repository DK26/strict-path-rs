use std::error::Error;
use strict_path::{PathBoundary, StrictPathError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test error chaining with strict_join (the detailed error method)
    #[cfg(windows)]
    let nonexistent_path = "C:\\NonExistent\\Path";
    #[cfg(not(windows))]
    let nonexistent_path = "/nonexistent/path";

    let result = PathBoundary::<()>::try_new(nonexistent_path);

    match result {
        Err(e) => {
            println!("Error: {e}");

            // Access the source error chain
            if let Some(source) = e.source() {
                println!("Caused by: {source}");

                // Can downcast to io::Error if needed
                if let Some(io_err) = source.downcast_ref::<std::io::Error>() {
                    println!("IO Error kind: {:?}", io_err.kind());
                }
            }

            // Pattern match on specific error types
            match e {
                StrictPathError::InvalidRestriction {
                    restriction,
                    source,
                } => {
                    println!(
                        "Failed to setup path boundary at: {}",
                        restriction.display()
                    );
                    println!("Reason: {source}");
                }
                StrictPathError::PathResolutionError { path, source } => {
                    println!("Cannot resolve: {}", path.display());
                    println!("IO Error: {source}");
                }
                StrictPathError::PathEscapesBoundary {
                    attempted_path,
                    restriction_boundary,
                } => {
                    println!(
                        "Security violation: {} tried to escape {}",
                        attempted_path.display(),
                        restriction_boundary.display()
                    );
                }
                #[cfg(windows)]
                StrictPathError::WindowsShortName {
                    component,
                    original,
                    checked_at,
                } => {
                    println!(
                        "Windows 8.3 short name '{}' rejected at '{}' for original '{}'",
                        component.to_string_lossy(),
                        checked_at.display(),
                        original.display()
                    );
                }
            }
        }
        Ok(boundary) => {
            // Test detailed error API
            println!("Validator created successfully!");

            // Try to validate a path - this is the only way to check validity
            match boundary.strict_join("../../../sensitive.txt") {
                Ok(_) => println!("Unexpected success!"),
                Err(e) => println!("Correctly blocked traversal: {e}"),
            }
        }
    }

    println!("Error handling test completed!");
    Ok(())
}
