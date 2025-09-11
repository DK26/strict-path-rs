// One-liner patterns for strict-path
//
// Demonstrates concise, chained operations for quick tasks

use strict_path::{PathBoundary, VirtualRoot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== One-Liner Patterns ===");

    // 1. Quick file write - one-liner
    let tmp_dir = tempfile::tempdir()?;
    PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("hello.txt")?
        .write_string("Hello world!")?;
    println!("-> Wrote file in one line");

    // 2. File existence check - one-liner
    let tmp_dir = tempfile::tempdir()?;
    let exists = PathBoundary::<()>::try_new(&tmp_dir)?
        .strict_join("missing.txt")?
        .exists();
    println!("-> File exists: {exists}");

    // 3. VirtualRoot file write - one-liner
    let tmp_dir = tempfile::tempdir()?;
    VirtualRoot::<()>::try_new(&tmp_dir)?
        .virtual_join("simple.txt")?
        .write_string("VirtualRoot content")?;
    println!("-> VirtualRoot file write in one line");

    // 4. Custom marker type - one-liner
    struct Demo;
    let tmp_dir = tempfile::tempdir()?;
    PathBoundary::<Demo>::try_new(&tmp_dir)?
        .strict_join("demo.txt")?
        .write_string("Demo content")?;
    println!("-> Custom marker works");

    println!("=== All one-liners completed! ===");
    Ok(())
}
