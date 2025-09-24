# strict-path Documentation

📚 **Live Documentation**: https://dk26.github.io/strict-path-rs/

This is the orphaned documentation branch for the [strict-path](https://github.com/DK26/strict-path-rs) Rust crate. This branch contains only documentation files and is completely separate from the main codebase.

## Structure

```
docs_src/           # mdBook source files
├── book.toml      # mdBook configuration
└── src/           # Markdown documentation files
    ├── SUMMARY.md
    ├── getting_started.md
    ├── examples.md
    ├── best_practices.md
    ├── anti_patterns.md
    └── ...

docs/              # Generated HTML site (GitHub Pages serves from here)
├── index.html
├── getting_started.html
└── ...
```

## Editing Documentation

1. **Edit source files** in `docs_src/src/`
2. **Build locally** (optional, for preview):
   ```bash
   cd docs_src
   mdbook serve  # Live preview at http://localhost:3000
   # OR
   mdbook build  # Generate static files
   ```
3. **Commit and push** both source changes and generated files:
   ```bash
   git add -A
   git commit -m "docs: your changes"
   git push
   ```

## Requirements

- [mdBook](https://rust-lang.github.io/mdBook/guide/installation.html): `cargo install mdbook`

## GitHub Pages Setup

This branch is configured for GitHub Pages:
- **Source**: Deploy from branch `docs`, folder `/docs`  
- **URL**: https://dk26.github.io/strict-path-rs/
- **Auto-deploy**: Pushes to this branch automatically update the live site

## Branch Notes

- **Orphaned branch**: No shared history with `main` - completely independent
- **Docs-only contributors**: Can clone just this branch for documentation work
- **Smaller repository**: Only contains documentation files, not the full codebase
- **Focus**: Pure documentation without code distractions
