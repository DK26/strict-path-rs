// Cargo.toml
// [dependencies]
// strict-path = "0.1.0"
// serde = { version = "1.0", features = ["derive"] }
// serde_yaml = "0.9"
// pulldown-cmark = "0.9"
// tera = "1.19"
// clap = { version = "4.0", features = ["derive"] }
// walkdir = "2.0"
// chrono = { version = "0.4", features = ["serde"] }

use clap::{Parser, Subcommand};
use pulldown_cmark::{html, Options, Parser as MarkdownParser};
use serde::{Deserialize, Serialize};
use strict_path::{PathBoundary, StrictPath};

use tera::{Context, Tera};
use walkdir::WalkDir;

// Type markers for different site contexts
struct SourceContent;
struct OutputSite;
struct ThemeAssets;

#[derive(Parser)]
#[command(name = "static-gen")]
#[command(about = "Secure static site generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new site project
    Init {
        /// Project directory
        #[arg(short, long, default_value = ".")]
        path: String,
    },
    /// Build the site
    Build {
        /// Source directory
        #[arg(short, long, default_value = "src")]
        source: String,
        /// Output directory
        #[arg(short, long, default_value = "dist")]
        output: String,
        /// Theme directory
        #[arg(short, long, default_value = "themes/default")]
        theme: String,
    },
    /// Serve the site locally (development)
    Serve {
        /// Output directory to serve
        #[arg(short, long, default_value = "dist")]
        output: String,
        /// Port to serve on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct SiteConfig {
    title: String,
    description: String,
    author: String,
    base_url: String,
    theme: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PageFrontmatter {
    title: String,
    date: Option<chrono::DateTime<chrono::Utc>>,
    draft: Option<bool>,
    tags: Option<Vec<String>>,
    layout: Option<String>,
}

struct Page {
    frontmatter: PageFrontmatter,
    _content: String,
    html_content: String,
    relative_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => init_site(&path),
        Commands::Build {
            source,
            output,
            theme,
        } => build_site(&source, &output, &theme),
        Commands::Serve { output, port } => serve_site(&output, port),
    }
}

fn init_site(project_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Initializing new static site project in: {project_path}");

    // Create secure project structure
    let project_dir: PathBoundary<SourceContent> =
        PathBoundary::try_new_create(project_path)?;

    // Create directory structure
    let dirs = [
        "src/pages",
        "src/posts",
        "themes/default/layouts",
        "themes/default/assets",
        "static",
    ];
    for dir in dirs {
        let dir_path = project_dir.strict_join(dir)?;
        dir_path.create_dir_all()?;
        println!("📁 Created: {dir}");
    }

    // Create default config
    let config = SiteConfig {
        title: "My Static Site".to_string(),
        description: "A secure static site built with strict-path".to_string(),
        author: "Site Author".to_string(),
        base_url: "https://example.com".to_string(),
        theme: "default".to_string(),
    };

    let config_path = project_dir.strict_join("site.yaml")?;
    let config_content = serde_yaml::to_string(&config)?;
    config_path.write_string(&config_content)?;
    println!("⚙️  Created: site.yaml");

    // Create sample content
    create_sample_content(&project_dir)?;
    create_default_theme(&project_dir)?;

    println!("✅ Project initialized! Run 'static-gen build' to build your site.");
    Ok(())
}

fn create_sample_content(
    project_dir: &PathBoundary<SourceContent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sample home page
    let index_content = r#"---
title: "Welcome to My Site"
layout: "page"
---

# Welcome!

This is the home page of your new static site. Edit this file in `src/pages/index.md` to customize it.

## Features

- Secure path handling with strict-path
- Markdown processing
- Template engine
- Static asset management
"#;

    let index_path = project_dir.strict_join("src/pages/index.md")?;
    index_path.write_string(index_content)?;

    // Sample blog post
    let post_content = r#"---
title: "My First Blog Post"
date: 2024-01-15T10:00:00Z
tags: ["blog", "first-post"]
layout: "post"
---

# My First Blog Post

Welcome to my blog! This is my first post using the secure static site generator.

## Why Security Matters

When building static sites, it's important to validate all file paths to prevent:

- Directory traversal attacks
- Unauthorized file access
- Path injection vulnerabilities

This generator uses `strict-path` to ensure all content stays within designated boundaries.
"#;

    let post_path = project_dir.strict_join("src/posts/first-post.md")?;
    post_path.write_string(post_content)?;

    println!("📝 Created sample content");
    Ok(())
}

fn create_default_theme(
    project_dir: &PathBoundary<SourceContent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Base layout template
    let base_layout = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if page.title %}{{ page.title }} - {% endif %}{{ site.title }}</title>
    <meta name="description" content="{{ site.description }}">
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <header>
        <h1><a href="/">{{ site.title }}</a></h1>
        <p>{{ site.description }}</p>
    </header>
    
    <main>
        {% block content %}{% endblock %}
    </main>
    
    <footer>
        <p>&copy; 2024 {{ site.author }}</p>
    </footer>
</body>
</html>"#;

    let base_path = project_dir.strict_join("themes/default/layouts/base.html")?;
    base_path.write_string(base_layout)?;

    // Page layout
    let page_layout = r#"{% extends "base.html" %}

{% block content %}
<article>
    <h1>{{ page.title }}</h1>
    {{ page.content | safe }}
</article>
{% endblock %}"#;

    let page_path = project_dir.strict_join("themes/default/layouts/page.html")?;
    page_path.write_string(page_layout)?;

    // Post layout
    let post_layout = r#"{% extends "base.html" %}

{% block content %}
<article>
    <header>
        <h1>{{ page.title }}</h1>
        {% if page.date %}
        <time datetime="{{ page.date | date(format='%Y-%m-%d') }}">
            {{ page.date | date(format='%B %d, %Y') }}
        </time>
        {% endif %}
        {% if page.tags %}
        <div class="tags">
            {% for tag in page.tags %}
            <span class="tag">#{{ tag }}</span>
            {% endfor %}
        </div>
        {% endif %}
    </header>
    
    {{ page.content | safe }}
</article>
{% endblock %}"#;

    let post_path = project_dir.strict_join("themes/default/layouts/post.html")?;
    post_path.write_string(post_layout)?;

    // Basic CSS
    let css_content = r#"/* Default theme styles */
body {
    font-family: system-ui, -apple-system, sans-serif;
    line-height: 1.6;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    color: #333;
}

header {
    border-bottom: 2px solid #eee;
    padding-bottom: 20px;
    margin-bottom: 40px;
}

header h1 a {
    text-decoration: none;
    color: #2563eb;
}

article {
    margin-bottom: 40px;
}

.tags {
    margin: 10px 0;
}

.tag {
    background: #f3f4f6;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.9em;
    margin-right: 5px;
}

footer {
    border-top: 1px solid #eee;
    padding-top: 20px;
    margin-top: 40px;
    text-align: center;
    color: #666;
}

code {
    background: #f8f9fa;
    padding: 2px 4px;
    border-radius: 3px;
}

pre {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
}
"#;

    let css_path = project_dir.strict_join("themes/default/assets/style.css")?;
    css_path.write_string(css_content)?;

    println!("🎨 Created default theme");
    Ok(())
}

fn build_site(
    source_path: &str,
    output_path: &str,
    theme_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔨 Building static site...");
    println!("Source: {source_path}");
    println!("Output: {output_path}");
    println!("Theme: {theme_path}");

    // Create secure directory restrictions for different content areas
    let source_dir: PathBoundary<SourceContent> = PathBoundary::try_new_create(source_path)?;
    let output_dir: PathBoundary<OutputSite> = PathBoundary::try_new_create(output_path)?;
    let theme_dir: PathBoundary<ThemeAssets> = PathBoundary::try_new_create(theme_path)?;

    // Load site configuration
    let config = load_site_config(&source_dir)?;
    println!("📋 Loaded config: {}", config.title);

    // Set up template engine with secure path validation
    let mut tera = Tera::default();
    load_templates(&mut tera, &theme_dir)?;

    // Process pages and posts
    let mut all_pages = Vec::new();

    // Process pages
    let pages = process_content_directory(&source_dir, "pages")?;
    all_pages.extend(pages);

    // Process posts
    let posts = process_content_directory(&source_dir, "posts")?;
    all_pages.extend(posts);

    println!("📄 Processed {} content files", all_pages.len());

    // Generate HTML files
    for page in &all_pages {
        generate_page_html(page, &config, &tera, &output_dir)?;
    }

    // Copy theme assets
    copy_theme_assets(&theme_dir, &output_dir)?;

    // Copy static files
    copy_static_files(&source_dir, &output_dir)?;

    println!("✅ Site built successfully in: {output_path}");
    Ok(())
}

fn load_site_config(
    source_dir: &PathBoundary<SourceContent>,
) -> Result<SiteConfig, Box<dyn std::error::Error>> {
    let config_path = source_dir.strict_join("site.yaml")?;
    let config_content = config_path.read_to_string()?;
    let config: SiteConfig = serde_yaml::from_str(&config_content)?;
    Ok(config)
}

fn load_templates(
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
                    let template_name = format!("{}", relative.display()).replace('\\', "/");

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

fn process_content_directory(
    source_dir: &PathBoundary<SourceContent>,
    dir_name: &str,
) -> Result<Vec<Page>, Box<dyn std::error::Error>> {
    let mut pages = Vec::new();
    let content_dir = source_dir.strict_join(dir_name)?;

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
                    let relative_str = format!("{}", relative.display()).replace('\\', "/");

                    // Validate through directory restriction
                    let content_path_str = format!("{dir_name}/{relative_str}");
                    let content_path = source_dir.strict_join(&content_path_str)?;

                    let page = process_markdown_file(&content_path, &relative_str)?;
                    pages.push(page);
                }
            }
        }
    }

    Ok(pages)
}

fn process_markdown_file(
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

fn generate_page_html(
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

    // Special case for index files
    if output_path == "index.html" {
        output_path = "index.html".to_string();
    }

    let output_file = output_dir.strict_join(&output_path)?;

    // Create parent directories
    output_file.create_parent_dir_all()?;

    output_file.write_string(&html)?;
    println!("📃 Generated: {output_path}");

    Ok(())
}

fn copy_theme_assets(
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
            let relative_str = format!("{}", relative.display()).replace('\\', "/");

            // Validate paths through directory restrictions
            let source_path = theme_dir.strict_join(format!("assets/{relative_str}"))?;
            let dest_path = output_dir.strict_join(format!("assets/{relative_str}"))?;

            // Create parent directories
            dest_path.create_parent_dir_all()?;

            // Copy file
            let content = source_path.read_bytes()?;
            dest_path.write_bytes(&content)?;

            println!("🎨 Copied asset: {relative_str}");
        }
    }

    Ok(())
}

fn copy_static_files(
    source_dir: &PathBoundary<SourceContent>,
    output_dir: &PathBoundary<OutputSite>,
) -> Result<(), Box<dyn std::error::Error>> {
    let static_dir = source_dir.strict_join("static")?;

    if !static_dir.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(static_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let relative = path.strip_prefix(static_dir.interop_path())?;
            let relative_str = format!("{}", relative.display()).replace('\\', "/");

            // Validate paths through directory restrictions
            let source_path = source_dir.strict_join(format!("static/{relative_str}"))?;
            let dest_path = output_dir.strict_join(&relative_str)?;

            // Create parent directories
            dest_path.create_parent_dir_all()?;

            // Copy file
            let content = source_path.read_bytes()?;
            dest_path.write_bytes(&content)?;

            println!("📁 Copied static file: {relative_str}");
        }
    }

    Ok(())
}

fn serve_site(output_path: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Starting development server...");
    println!("Serving: {output_path}");
    println!("URL: http://localhost:{port}");

    // In a real implementation, you'd start an HTTP server here
    // This is just a placeholder showing secure path validation
    let output_dir: PathBoundary<OutputSite> = PathBoundary::try_new_create(output_path)?;
    let index_file = output_dir.strict_join("index.html")?;

    if index_file.exists() {
        println!("✅ Found index.html - site ready to serve");
        println!("Press Ctrl+C to stop the server");

        // Simulate server running
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    } else {
        println!("❌ No index.html found. Run 'static-gen build' first.");
    }

    Ok(())
}
