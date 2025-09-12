// S3 Mirror Demo
//
// Mirrors files from a local PathBoundary to an S3 bucket. All keys are derived
// from VirtualPath (virtual root), while data reads use StrictPath.

#[cfg(not(feature = "with-aws"))]
fn main() {
    eprintln!("Rebuild with --features with-aws to run this example.");
}

#[cfg(feature = "with-aws")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;
    use aws_sdk_s3::types::ByteStream;
    use aws_sdk_s3::Client;
    use strict_path::{PathBoundary, VirtualPath, VirtualRoot};
    use std::fs;
    use walkdir::WalkDir;

    #[derive(Clone)]
    struct Src;

    // Setup demo source
    fs::create_dir_all("mirror_src/sub")?;
    fs::write("mirror_src/file.txt", b"hello s3\n")?;
    fs::write("mirror_src/sub/inner.txt", b"inner\n")?;

    let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "my-bucket".to_string());
    let prefix = std::env::var("S3_PREFIX").unwrap_or_default();

    let mirror_src: PathBoundary<Src> = PathBoundary::try_new_create("mirror_src")?;
    let mirror_src_vroot: VirtualRoot<Src> = VirtualRoot::try_new_create("mirror_src")?;

    // Use a mock unless explicitly enabled with EXAMPLES_S3_RUN=1
    let use_real = std::env::var("EXAMPLES_S3_RUN").ok().as_deref() == Some("1");
    let s3 = if use_real {
        let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Some(Client::new(&conf))
    } else {
        None
    };

    let source_root_os = mirror_src.interop_path();
    for entry in WalkDir::new(source_root_os) {
        let entry = entry?;
        let entry_path = entry.path();
        let relative_path = match entry_path.strip_prefix(source_root_os) {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };
        let source_file = mirror_src.strict_join(relative_path)?;
        if source_file.is_file() {
            let object_vpath: VirtualPath<Src> = mirror_src_vroot.virtual_join(relative_path)?;
            let key_part_owned = object_vpath.virtualpath_display().into_owned();
            let key_part = key_part_owned.trim_start_matches('/');
            let key = if prefix.is_empty() {
                key_part.to_string()
            } else {
                format!("{}/{}", prefix.trim_end_matches('/'), key_part)
            };
            if let Some(ref s3c) = s3 {
                let body = ByteStream::from_path(source_file.interop_path()).await?;
                s3c.put_object().bucket(&bucket).key(&key).body(body).send().await?;
                println!("Uploaded s3://{}/{}", bucket, key);
            } else {
                let src_disp = source_file.strictpath_display();
                println!("MOCK upload s3://{bucket}/{key} from {src_disp}");
            }
        }
    }

    fs::remove_dir_all("mirror_src").ok();
    Ok(())
}



