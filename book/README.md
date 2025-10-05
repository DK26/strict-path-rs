# Book Directory

This directory contains a **reference copy** of the mdBook source files for documentation purposes only.

## Modifying the Documentation

**Do not edit files in this directory.** Changes here will not be reflected in the published documentation.

To modify the mdBook documentation:

1. Switch to the `docs` branch:
   ```bash
   git checkout docs
   ```

2. Edit the source files in `docs_src/`

3. Build and preview locally:
   ```bash
   cd docs_src
   mdbook serve -o
   ```

4. Commit and push your changes to the `docs` branch

## Alternative: Using a Worktree

For a better workflow that lets you edit docs while working on `main`, set up a Git worktree:

```bash
# From the repository root on main branch
git worktree add .docs docs
```

Then edit and preview docs in `.docs/docs_src/` without switching branches. See `AGENTS.md` for detailed worktree setup instructions.

## Purpose of This Directory

This copy exists for:
- Quick reference when coding on the `main` branch
- Context for AI assistants and automation tools
- Browsing documentation structure without branch switching

For the authoritative, editable documentation source, always use the `docs` branch.
