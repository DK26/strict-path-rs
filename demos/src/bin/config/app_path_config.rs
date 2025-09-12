// App-Path Config Loader
//
// Uses app-path (optional) to locate the OS-appropriate config directory,
// then creates a PathBoundary for safe config access.

#[cfg(not(feature = "with-app-path"))]
fn main() {
    eprintln!("Rebuild with --features with-app-path to run this example.");
}

#[cfg(feature = "with-app-path")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use strict_path::{PathBoundary, StrictPath};
    use std::fs;

    #[derive(Clone)]
    struct AppCfg;

    // Discover or construct a config dir using app-path.
    // Use the app_path! macro to create a path relative to the executable,
    // with an optional environment override (APP_CONFIG_DIR) for deployments.
    let cfg_dir = app_path::app_path!("config", env = "APP_CONFIG_DIR");
    println!("Config dir: {}", cfg_dir.display());

    let cfg_jail: PathBoundary<AppCfg> = PathBoundary::try_new_create(&cfg_dir)?;

    // Write a sample config
    let path: StrictPath<AppCfg> = cfg_jail.strict_join("app.yaml")?;
    path.write_string("host: 127.0.0.1\nport: 8080\n")?;
    let disp = path.strictpath_display();
    println!("Wrote config to {disp}");

    // Read it back via a function that encodes guarantees in the signature
    fn read_cfg(p: &StrictPath<AppCfg>) -> std::io::Result<String> { p.read_to_string() }
    let content = read_cfg(&path)?;
    println!("Config loaded ({} bytes)", content.len());

    // Cleanup demo file (in real apps, keep config)
    fs::remove_file(path.interop_path()).ok();
    Ok(())
}



