// Secure Archive Builder (TAR)
//
// Packages files from a source jail into a .tar archive, ensuring only
// paths inside the jail are included and entry names are relative (virtual view).

use jailed_path::{Jail, VirtualPath, VirtualRoot};
use std::fs;
use std::path::Path;
use tar::Builder;
use walkdir::WalkDir;

#[derive(Clone)]
struct Source;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo setup
    fs::create_dir_all("archive_src/docs")?;
    fs::write("archive_src/README.txt", b"Hello archive!\n")?;
    fs::write("archive_src/docs/guide.txt", b"Use me wisely.\n")?;

    // Jails
    let src = Jail::<Source>::try_new_create("archive_src")?;
    let vroot: VirtualRoot<Source> = VirtualRoot::try_new_create("archive_src")?;

    // Build tar archive
    let tar_path = Path::new("out.tar");
    let file = fs::File::create(tar_path)?;
    let mut builder = Builder::new(file);

    let root = src.jailed_join(".")?;
    for entry in WalkDir::new(root.interop_path()) {
        let entry = entry?;
        let p = entry.path();
        let rel = match p.strip_prefix(root.interop_path()) {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };
        let rel_str = rel.to_string_lossy().to_string();

        // Validate relative path back through the jail (defense-in-depth)
        let sp = match src.jailed_join(&rel_str) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if sp.is_dir() {
            // Add directory entry (optional; tar can infer)
            let vp: VirtualPath<Source> = vroot.virtual_join(&rel_str)?;
            let name = vp.virtualpath_to_string_lossy().into_owned();
            builder.append_dir(name, sp.interop_path())?;
            continue;
        }

        // Compute virtual (relative) name for the archive entry
        let vp: VirtualPath<Source> = vroot.virtual_join(&rel_str)?;
        let mut f = fs::File::open(sp.interop_path())?;
        let name = vp.virtualpath_to_string_lossy().into_owned();
        builder.append_file(name, &mut f)?;
        let display = vp.virtualpath_display();
        println!("Added: {display}");
    }

    builder.finish()?;
    let tar = tar_path.display();
    println!("Built archive: {tar}");

    // Cleanup demo source (keep tar)
    fs::remove_dir_all("archive_src").ok();
    Ok(())
}

