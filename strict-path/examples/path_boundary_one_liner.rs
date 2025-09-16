// One-liner PathBoundary demo
//
// Create a PathBoundary and operate on a path in a single chained expression.

use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // True one-liner: write file in single chained expression
    let tmp_dir = tempfile::tempdir()?;
    PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("hello.txt")?
        .write_string("hello from a strict path\n")?;

    // One-liner read with size calculation
    let bytes_read = PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("hello.txt")?
        .read_bytes()?
        .len();
    println!("One-liner PathBoundary: read {bytes_read} bytes");

    // Note: temp directory cleanup is automatic
    Ok(())
}
