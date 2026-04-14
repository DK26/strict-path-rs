// One-liner PathBoundary demo
//
// Create a PathBoundary and operate on a path in a single chained expression.
// The file name comes from the first CLI argument (or defaults to "hello.txt"),
// demonstrating that strict_join() validates untrusted external input.
//
// Run with: cargo run --example path_boundary_one_liner -- <filename>

use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // File name from external input (CLI arg, HTTP request, config file, etc.)
    let requested_file: String = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hello.txt".to_owned());

    // True one-liner: write file in single chained expression
    let tmp_dir = tempfile::tempdir()?;
    PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join(&requested_file)?
        .write("hello from a strict path\n")?;

    // One-liner read with size calculation
    let bytes_read = PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join(&requested_file)?
        .read()?
        .len();
    println!("One-liner PathBoundary: read {bytes_read} bytes");

    // Note: temp directory cleanup is automatic
    Ok(())
}
