// One-liner JailedPath demo
//
// Create a jail and operate on a path in a single chained expression.

use jailed_path::Jail;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create directory if missing, validate path, and write in one chain
    Jail::<()>::try_new_create("quick/safe")?
        .try_path("hello.txt")?
        .write_string("hello from jailed-path\n")?;

    // Read back using the same chain
    let bytes = Jail::<()>::try_new("quick/safe")?
        .try_path("hello.txt")?
        .read_bytes()?;
    println!("One-liner JailedPath: read {} bytes", bytes.len());

    // Cleanup
    std::fs::remove_dir_all("quick").ok();
    Ok(())
}
