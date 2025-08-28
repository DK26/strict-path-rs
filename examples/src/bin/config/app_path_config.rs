// App-Path Config Loader
//
// Uses app-path (optional) to locate the OS-appropriate config directory,
// then creates a Jail for safe config access.

#[cfg(not(feature = "with-app-path"))]
fn main() {
    eprintln!("Rebuild with --features with-app-path to run this example.");
}

#[cfg(feature = "with-app-path")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use jailed_path::{Jail, JailedPath};
    use std::fs;

    #[derive(Clone)]
    struct AppCfg;

    // Discover or construct a config dir using app-path.
    // Use the app_path! macro to create a path relative to the executable,
    // with an optional environment override (APP_CONFIG_DIR) for deployments.
    let cfg_dir = app_path::app_path!("config", env = "APP_CONFIG_DIR");
    println!("Config dir: {}", cfg_dir.display());

    let cfg_jail: Jail<AppCfg> = Jail::try_new_create(&cfg_dir)?;

    // Write a sample config
    let path: JailedPath<AppCfg> = cfg_jail.try_path("app.yaml")?;
    path.write_string("host: 127.0.0.1\nport: 8080\n")?;
    println!("Wrote config to {}", path.systempath_to_string());

    // Read it back via a function that encodes guarantees in the signature
    fn read_cfg(p: &JailedPath<AppCfg>) -> std::io::Result<String> { p.read_to_string() }
    let content = read_cfg(&path)?;
    println!("Config loaded ({} bytes)", content.len());

    // Cleanup demo file (in real apps, keep config)
    fs::remove_file(path.systempath_as_os_str()).ok();
    Ok(())
}
