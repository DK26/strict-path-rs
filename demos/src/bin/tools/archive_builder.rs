// Secure Archive Builder (TAR)
//
// Packages files from a source PathBoundary into a .tar archive, ensuring only
// paths inside the PathBoundary are included and entry names are relative (virtual view).

use std::fs;
use std::path::Path;
use strict_path::{PathBoundary, VirtualPath, VirtualRoot};
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
    let archive_src: PathBoundary<Source> = PathBoundary::try_new_create("archive_src")?;
    let archive_src_vroot: VirtualRoot<Source> = VirtualRoot::try_new_create("archive_src")?;

    // Build tar archive
    let tar_path = Path::new("out.tar");
    let file = fs::File::create(tar_path)?;
    let mut builder = Builder::new(file);

    let archive_src_os = archive_src.interop_path();
    for entry in WalkDir::new(archive_src_os) {
        let entry = entry?;
        let entry_path = entry.path();
        let relative_path = match entry_path.strip_prefix(archive_src_os) {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };
        let relative_str = format!("{}", relative_path.display());

        // Validate relative path back through the PathBoundary (defense-in-depth)
        let archive_src_path = match archive_src.strict_join(&relative_str) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if archive_src_path.is_dir() {
            // Add directory entry (optional; tar can infer)
            let archive_entry_vpath: VirtualPath<Source> = archive_src_vroot.virtual_join(&relative_str)?;
            let entry_name = archive_entry_vpath.virtualpath_display().to_string();
            builder.append_dir(entry_name, archive_src_path.interop_path())?;
            continue;
        }

        // Compute virtual (relative) name for the archive entry
        let archive_entry_vpath: VirtualPath<Source> = archive_src_vroot.virtual_join(&relative_str)?;
        let mut file_handle = fs::File::open(archive_src_path.interop_path())?;
        let entry_name = archive_entry_vpath.virtualpath_display().to_string();
        builder.append_file(entry_name, &mut file_handle)?;
        let entry_display = archive_entry_vpath.virtualpath_display();
        println!("Added: {entry_display}");
    }

    builder.finish()?;
    let tar = tar_path.display();
    println!("Built archive: {tar}");

    // Cleanup demo source (keep tar)
    fs::remove_dir_all("archive_src").ok();
    Ok(())
}
