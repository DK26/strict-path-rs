// One-liner PathBoundary demo
//
// Create a PathBoundary and operate on a path in a single chained expression.
//
// **External Input Pattern**: In production, the file name passed to `strict_join()`
// would come from an external source (CLI args, HTTP request, config file). Here
// we use a constant for brevity, but the validation pattern is identical.

use strict_path::PathBoundary;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // True one-liner: write file in single chained expression
    let tmp_dir = tempfile::tempdir()?;
    PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("hello.txt")?
        .write("hello from a strict path\n")?;

    // One-liner read with size calculation
    let bytes_read = PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("hello.txt")?
        .read()?
        .len();
    println!("One-liner PathBoundary: read {bytes_read} bytes");

    // Note: temp directory cleanup is automatic
    Ok(())
}
