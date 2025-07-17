use jailed_path::{JailedPathError, PathValidator};
use std::error::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test error chaining with try_path (the detailed error method)
    let result = PathValidator::<()>::with_jail("/nonexistent/path");

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
                JailedPathError::InvalidJail { jail, source } => {
                    println!("Failed to setup jail at: {}", jail.display());
                    println!("Reason: {source}");
                }
                JailedPathError::PathResolutionError { path, source } => {
                    println!("Cannot resolve: {}", path.display());
                    println!("IO Error: {source}");
                }
                JailedPathError::PathEscapesBoundary {
                    attempted_path,
                    jail_boundary,
                } => {
                    println!(
                        "Security violation: {} tried to escape {}",
                        attempted_path.display(),
                        jail_boundary.display()
                    );
                }
            }
        }
        Ok(validator) => {
            // Test detailed error API
            println!("Validator created successfully!");

            // Try to validate a path - this is the only way to check validity
            match validator.try_path("../../../etc/passwd") {
                Ok(_) => println!("Unexpected success!"),
                Err(e) => println!("Correctly blocked traversal: {e}"),
            }
        }
    }

    println!("Error handling test completed!");
    Ok(())
}
