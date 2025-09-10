// One-liner patterns for jailed-path
//
// Demonstrates concise, chained operations for quick tasks

use jailed_path::{Jail, VirtualRoot};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== One-Liner Patterns ===");

    // 1. Quick file write with Jail
    Jail::<()>::try_new_create("quick_jail")?
        .jailed_join("hello.txt")?
        .write_string("Hello from one-liner!")?;
    println!("-> Wrote file in one line");

    // 2. Quick file read with Jail
    let content = Jail::<()>::try_new("quick_jail")?
        .jailed_join("hello.txt")?
        .read_to_string()?;
    let line = content.trim();
    println!("-> Read: {line}");

    // 3. VirtualRoot one-liner with parent creation
    let vp =
        VirtualRoot::<()>::try_new_create("quick_vroot")?.virtual_join("nested/deep/file.txt")?;
    vp.create_parent_dir_all()?;
    vp.write_string("Deep content")?;
    println!("-> Created nested file with parents in one line");

    // 4. Chain validation + operation
    let size = VirtualRoot::<()>::try_new("quick_vroot")?
        .virtual_join("nested/deep/file.txt")?
        .read_bytes()?
        .len();
    println!("-> File size: {size} bytes");

    // 5. Conditional one-liner
    let exists = Jail::<()>::try_new("quick_jail")?
        .jailed_join("hello.txt")?
        .exists();
    println!("-> File exists: {exists}");

    // 6. With custom marker
    struct Demo;
    let safe_path = Jail::<Demo>::try_new_create("demo_jail")?.jailed_join("demo.txt")?;
    safe_path.write_string("Demo with marker")?;
    println!("-> Custom marker one-liner works");

    // Cleanup
    std::fs::remove_dir_all("quick_jail").ok();
    std::fs::remove_dir_all("quick_vroot").ok();
    std::fs::remove_dir_all("demo_jail").ok();

    println!("=== All one-liners completed! ===");
    Ok(())
}
