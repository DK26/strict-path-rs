use strict_path::PathBoundary;

use crate::types::{SiteConfig, SourceContent};

pub fn init_site(project_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing new static site project in: {project_path}");

    // Create secure project structure
    let project_dir: PathBoundary<SourceContent> = PathBoundary::try_new_create(project_path)?;

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
        println!("  Created: {dir}");
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
    config_path.write(&config_content)?;
    println!("  Created: site.yaml");

    // Create sample content
    create_sample_content(&project_dir)?;
    create_default_theme(&project_dir)?;

    println!("Project initialized! Run 'static-gen build' to build your site.");
    Ok(())
}

pub fn create_sample_content(
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
    index_path.write(index_content)?;

    // Sample blog post
    let post_content = r#"---
title: "My First Post"
layout: "post"
tags: ["introduction", "blog"]
---

# My First Post

Welcome to my first blog post! This site is secured with strict-path.
"#;

    let post_path = project_dir.strict_join("src/posts/first-post.md")?;
    post_path.write(post_content)?;

    println!("  Created sample content files");
    Ok(())
}

pub fn create_default_theme(
    project_dir: &PathBoundary<SourceContent>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Page layout template
    let page_template = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ page.title }} - {{ site.title }}</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <header>
        <h1>{{ site.title }}</h1>
        <p>{{ site.description }}</p>
    </header>
    <main>
        <article>
            <h2>{{ page.title }}</h2>
            {{ page.content | safe }}
        </article>
    </main>
    <footer>
        <p>Built with strict-path | {{ site.author }}</p>
    </footer>
</body>
</html>
"#;

    let page_layout = project_dir.strict_join("themes/default/layouts/page.html")?;
    page_layout.write(page_template)?;

    // Post layout template (inherits from page)
    let post_template = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ page.title }} - {{ site.title }}</title>
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <header><h1><a href="/">{{ site.title }}</a></h1></header>
    <main>
        <article>
            <h2>{{ page.title }}</h2>
            {% if page.date %}<time>{{ page.date }}</time>{% endif %}
            {{ page.content | safe }}
        </article>
    </main>
</body>
</html>
"#;

    let post_layout = project_dir.strict_join("themes/default/layouts/post.html")?;
    post_layout.write(post_template)?;

    // Default CSS
    let css_content = r#"/* Secure Static Site - Default Theme */
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; line-height: 1.6; color: #333; }
header { background: #2c3e50; color: white; padding: 1rem 2rem; }
header h1 { font-size: 1.5rem; }
main { max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
article h2 { margin-bottom: 1rem; }
footer { text-align: center; padding: 2rem; color: #666; }
"#;

    let css_path = project_dir.strict_join("themes/default/assets/style.css")?;
    css_path.write(css_content)?;

    println!("  Created default theme");
    Ok(())
}
