// Config Includes Demo
//
// Demonstrates resolving include directives safely using VirtualRoot/VirtualPath.
// Each `include path` is resolved relative to the including file’s virtual parent
// via `virtual_join`, so traversal attempts cannot escape the config root.

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::io;
use strict_path::{VirtualPath, VirtualRoot};

#[derive(Clone)]
struct ConfigRoot;

fn main() -> Result<()> {
    // Setup a small config tree
    fs::create_dir_all("cfg_root/includes")?;
    fs::write(
        "cfg_root/base.conf",
        b"title = Demo\ninclude includes/feature.conf\ninclude ../outside.conf\n",
    )?;
    fs::write("cfg_root/includes/feature.conf", b"feature = enabled\n")?;
    // Outside file shouldn't be reachable
    fs::write("outside.conf", b"hacked = true\n")?;

    let vroot: VirtualRoot<ConfigRoot> = VirtualRoot::try_new_create("cfg_root")?;
    let cfg = load_config(&vroot, "base.conf")?;
    println!("Loaded keys: {:?}", cfg.keys().collect::<Vec<_>>());

    // Cleanup demo files
    fs::remove_file("outside.conf").ok();
    fs::remove_dir_all("cfg_root").ok();
    Ok(())
}

fn load_config(vroot: &VirtualRoot<ConfigRoot>, entry: &str) -> Result<HashMap<String, String>> {
    let start = vroot.virtual_join(entry)?;
    let mut visited = std::collections::HashSet::new();
    load_config_from_vpath(&start, &mut visited)
}

fn load_config_from_vpath(
    file: &VirtualPath<ConfigRoot>,
    visited: &mut std::collections::HashSet<VirtualPath<ConfigRoot>>,
) -> Result<HashMap<String, String>> {
    if !visited.insert(file.clone()) {
        let where_at = file.virtualpath_display();
        return Err(anyhow::anyhow!("Include loop detected at {where_at}"));
    }

    let content = match file.read_to_string() {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.into()),
    };

    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("include ") {
            let include_rel = rest.trim();
            // Use the virtual parent to resolve includes relative to the including file's virtual path
            let vparent = match file.virtualpath_parent()? {
                Some(v) => v,
                None => file.clone(),
            };
            let include_vp = match vparent.virtual_join(include_rel) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let inc_map = load_config_from_vpath(&include_vp, visited)?;
            map.extend(inc_map);
        } else if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}
