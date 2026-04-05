use pulldown_cmark::{html, Options, Parser as MarkdownParser};
use strict_path::{PathBoundary, StrictPath};
use tera::{Context, Tera};
use walkdir::WalkDir;

use crate::types::{OutputSite, Page, PageFrontmatter, SiteConfig, SourceContent, ThemeAssets};

pub fn build_site(
    source_path: &str,
    output_path: &str,
    theme_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building static site...");
    println!("Source: {source_path}");
    println!("Output: {output_path}");
    println!("Theme: {theme_path}");

    // Create secure directory restrictions for different content areas
    let site_content_dir: PathBoundary<SourceContent> = PathBoundary::try_new_create(source_path)?;
    let output_dir: PathBoundary<OutputSite> = PathBoundary::try_new_create(output_path)?;
    let theme_dir: PathBoundary<ThemeAssets> = PathBoundary::try_new_create(theme_path)?;

    // Load site configuration
    let config = load_site_config(&site_content_dir)?;
    println!("  Loaded config: {}", config.title);

    // Set up template engine with secure path validation
    let mut tera = Tera::default();
    load_templates(&mut tera, &theme_dir)?;

    // Process pages and posts
    let mut all_pages = Vec::new();
    let pages = process_content_directory(&site_content_dir, "pages")?;
    all_pages.extend(pages);
    let posts = process_content_directory(&site_content_dir, "posts")?;
    all_pages.extend(posts);

    println!("  Processed {} content files", all_pages.len());

    // Generate HTML files
    for page in &all_pages {
        generate_page_html(page, &config, &tera, &output_dir)?;
    }

    // Copy theme assets and static files
    copy_theme_assets(&theme_dir, &output_dir)?;
    copy_static_files(&site_content_dir, &output_dir)?;

    println!("Site built successfully in: {output_path}");
    Ok(())
}

pub fn load_site_config(
    site_content_dir: &PathBoundary<SourceContent>,
) -> Result<SiteConfig, Box<dyn std::error::Error>> {
    let config_path = site_content_dir.strict_join("site.yaml")?;
    let config_content = config_path.read_to_string()?;
    let config: SiteConfig = serde_yaml::from_str(&config_content)?;
    Ok(config)
}

pub fn load_templates(
    tera: &mut Tera,
    theme_dir: &PathBoundary<ThemeAssets>,
) -> Result<(), Box<dyn std::error::Error>> {
    let layouts_dir = theme_dir.strict_join("layouts")?;

    if !layouts_dir.exists() {
        return Err("Theme layouts directory not found".into());
    }

    // Walk through layout files securely
    for entry in WalkDir::new(layouts_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "html" {
                    let relative = path.strip_prefix(layouts_dir.interop_path())?;
                    let template_name = relative.display().to_string().replace('\\', "/");

                    // Validate the template path through directory restriction
                    let template_path_str = format!("layouts/{template_name}");
                    let template_path = theme_dir.strict_join(&template_path_str)?;
                    let content = template_path.read_to_string()?;

                    tera.add_raw_template(&template_name, &content)?;
                }
            }
        }
    }

    Ok(())
}

pub fn process_content_directory(
    site_content_dir: &PathBoundary<SourceContent>,
    dir_name: &str,
) -> Result<Vec<Page>, Box<dyn std::error::Error>> {
    let mut pages = Vec::new();
    let content_dir = site_content_dir.strict_join(dir_name)?;

    if !content_dir.exists() {
        return Ok(pages);
    }

    for entry in WalkDir::new(content_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "md" {
                    let relative = path.strip_prefix(content_dir.interop_path())?;
                    let relative_str = relative.display().to_string().replace('\\', "/");

                    // Validate through directory restriction
                    let content_path_str = format!("{dir_name}/{relative_str}");
                    let content_path = site_content_dir.strict_join(&content_path_str)?;

                    let page = process_markdown_file(&content_path, &relative_str)?;
                    pages.push(page);
                }
            }
        }
    }

    Ok(pages)
}

pub fn process_markdown_file(
    file_path: &StrictPath<SourceContent>,
    relative_path: &str,
) -> Result<Page, Box<dyn std::error::Error>> {
    let content = file_path.read_to_string()?;

    // Parse frontmatter and content
    let parts: Vec<&str> = content.splitn(3, "---").collect();
    if parts.len() != 3 {
        return Err("Invalid frontmatter format".into());
    }

    let frontmatter: PageFrontmatter = serde_yaml::from_str(parts[1].trim())?;
    let markdown_content = parts[2].trim();

    // Convert markdown to HTML
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);

    let parser = MarkdownParser::new_ext(markdown_content, options);
    let mut html_content = String::new();
    html::push_html(&mut html_content, parser);

    Ok(Page {
        frontmatter,
        _content: markdown_content.to_string(),
        html_content,
        relative_path: relative_path.to_string(),
    })
}

pub fn generate_page_html(
    page: &Page,
    config: &SiteConfig,
    tera: &Tera,
    output_dir: &PathBoundary<OutputSite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let layout = page.frontmatter.layout.as_deref().unwrap_or("page");
    let template_name = format!("{layout}.html");

    let mut context = Context::new();
    context.insert("site", config);
    context.insert(
        "page",
        &serde_json::json!({
            "title": page.frontmatter.title,
            "date": page.frontmatter.date,
            "tags": page.frontmatter.tags,
            "content": page.html_content
        }),
    );

    let html = tera.render(&template_name, &context)?;

    // Generate output path (convert .md to .html)
    let mut output_path = page.relative_path.clone();
    if output_path.ends_with(".md") {
        output_path = output_path.replace(".md", ".html");
    }

    let output_file = output_dir.strict_join(&output_path)?;
    output_file.create_parent_dir_all()?;
    output_file.write(&html)?;
    println!("  Generated: {output_path}");

    Ok(())
}

pub fn copy_theme_assets(
    theme_dir: &PathBoundary<ThemeAssets>,
    output_dir: &PathBoundary<OutputSite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let assets_dir = theme_dir.strict_join("assets")?;

    if !assets_dir.exists() {
        return Ok(());
    }

    let output_assets = output_dir.strict_join("assets")?;
    output_assets.create_dir_all()?;

    for entry in WalkDir::new(assets_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let relative = path.strip_prefix(assets_dir.interop_path())?;
            let relative_str = relative.display().to_string().replace('\\', "/");

            // Validate paths through directory restrictions
            let theme_asset = theme_dir.strict_join(format!("assets/{relative_str}"))?;
            let dest_path = output_dir.strict_join(format!("assets/{relative_str}"))?;

            dest_path.create_parent_dir_all()?;
            let content = theme_asset.read()?;
            dest_path.write(&content)?;

            println!("  Copied asset: {relative_str}");
        }
    }

    Ok(())
}

pub fn copy_static_files(
    site_content_dir: &PathBoundary<SourceContent>,
    output_dir: &PathBoundary<OutputSite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let static_dir = site_content_dir.strict_join("static")?;

    if !static_dir.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(static_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let relative = path.strip_prefix(static_dir.interop_path())?;
            let relative_str = relative.display().to_string().replace('\\', "/");

            // Validate paths through directory restrictions
            let static_file = site_content_dir.strict_join(format!("static/{relative_str}"))?;
            let dest_path = output_dir.strict_join(&relative_str)?;

            dest_path.create_parent_dir_all()?;
            let content = static_file.read()?;
            dest_path.write(&content)?;

            println!("  Copied static file: {relative_str}");
        }
    }

    Ok(())
}

pub fn serve_site(output_path: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting development server...");
    println!("Serving: {output_path}");
    println!("URL: http://localhost:{port}");

    let output_dir: PathBoundary<OutputSite> = PathBoundary::try_new_create(output_path)?;
    let index_file = output_dir.strict_join("index.html")?;

    if index_file.exists() {
        println!("Found index.html - site ready to serve");
        println!("Press Ctrl+C to stop the server");

        // Simulate server running
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    } else {
        println!("No index.html found. Run 'static-gen build' first.");
    }

    Ok(())
}
