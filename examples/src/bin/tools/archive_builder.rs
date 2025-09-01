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
    let src = Jail::<Source>::try_new("archive_src")?;
    let vroot: VirtualRoot<Source> = VirtualRoot::try_new("archive_src")?;

    // Build tar archive
    let tar_path = Path::new("out.tar");
    let file = fs::File::create(tar_path)?;
    let mut builder = Builder::new(file);

    let root = src.systempath_join(".")?;
    for entry in WalkDir::new(root.systempath_as_os_str()) {
        let entry = entry?;
        let p = entry.path();
        let rel = match p.strip_prefix(root.systempath_as_os_str()) {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };
        let rel_str = rel.to_string_lossy().to_string();

        // Validate relative path back through the jail (defense-in-depth)
        let sp = match src.systempath_join(&rel_str) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if sp.is_dir() {
            // Add directory entry (optional; tar can infer)
            let vp: VirtualPath<Source> = vroot.virtualpath_join(&rel_str)?;
            builder.append_dir(vp.to_string(), sp.systempath_as_os_str())?;
            continue;
        }

        // Compute virtual (relative) name for the archive entry
        let vp: VirtualPath<Source> = vroot.virtualpath_join(&rel_str)?;
        let mut f = fs::File::open(sp.systempath_as_os_str())?;
        builder.append_file(vp.to_string(), &mut f)?;
        println!("Added: {vp}");
    }

    builder.finish()?;
    println!("✅ Built archive: {}", tar_path.display());

    // Cleanup demo source (keep tar)
    fs::remove_dir_all("archive_src").ok();
    Ok(())
}



