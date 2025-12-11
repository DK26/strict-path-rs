# Contributing to strict-path

Thanks for your interest in contributing! 🦀

## Quick Start

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/strict-path-rs.git`
3. Test locally:
   - Linux/macOS/WSL: `bash ci-local.sh`
   - Windows PowerShell: `.\ci-local.ps1`
4. Submit a pull request

## How to Contribute

- 🐛 Bug reports: [Open an issue](https://github.com/DK26/strict-path-rs/issues) with reproduction steps
- 💡 Features: Discuss in an issue before implementing (see [Feature Suggestions](#feature-suggestions) below)
- 📝 Docs: Fix typos, add examples, improve clarity
- 🔧 Code: Bug fixes and improvements welcome

## Issue Template

Copy, paste, and fill what you need. Delete unused lines:

```markdown
What: [Brief description]

Why: [Problem or motivation]

Idea: [Your proposed solution]

Example: [Code or use case]

Benefits: [Who gains, what improves]

Links: [Related docs/issues]
```

## Feature Suggestions

Before suggesting features, **have your LLM agent read our [`AGENTS.md`](./AGENTS.md) and [`LLM_CONTEXT_FULL.md`](./LLM_CONTEXT_FULL.md) files** and ask it:

1. Does my suggested feature align with the project's design philosophy?
2. Why might this feature not already be implemented?
3. How does this fit within existing API patterns?

**LLM Prompt:**
```
I want to suggest a feature for strict-path crate. Please read the AGENTS.md and LLM_CONTEXT_FULL.md files from this repository and tell me if my feature idea aligns with the design philosophy and why it might not already be implemented.
```

**Timeline expectations:**
- **Within design philosophy:** May be added in minor releases
- **Outside design philosophy:** Requires major version (potentially far future unless critical)

We encourage **all** suggestions! The distinction just helps set implementation expectations. If you want to suggest design philosophy changes, create an issue for discussion.

## Development

**Project Philosophy:**
- Type-safe security with compile-time guarantees
- Never expose raw `std::path::Path` (zero attack surface)
- Explicit method naming (`strictpath_*` vs `virtualpath_*`)
- Cross-platform CVE protection


## Testing

Just run the CI script locally:

```bash
# Linux/macOS/WSL
bash ci-local.sh

# Windows PowerShell  
.\ci-local.ps1
```

If it passes, your code is ready.

### Local CI scripts (fast lanes)

Use these from the repo root to get fast, targeted feedback:

- Default pre-commit run: runs formatting + clippy auto-fixes for both core and demos, mirroring CI intent while staying fast.
   - Windows: `./ci-local.ps1`
   - Linux/macOS/WSL: `bash ./ci-local.sh`

- Core-only quick check: validate the `strict-path/` crate without demos. Runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo doc --no-deps` for the core.
   - Windows: `./ci-check.ps1`
   - Linux/macOS/WSL: `bash ./ci-check.sh`

- Demos-only selective check: focuses solely on changed demo files. Auto-formats changed demos by default, validates style without compiling, and gates clippy to safe features to avoid heavy native deps.
   - Windows: `./ci-check-demos.ps1`
   - Linux/macOS/WSL: `bash ./ci-check-demos.sh`

Notes
- The demos checker looks at both `git diff` and `git diff --staged` and only checks files that actually changed.
- Heavy demo feature sets (e.g., cloud SDKs) are opt-in; the default “safe features” keep runs lightweight.
- See `AGENTS.md` for full details and rationale.

## License

By contributing, you agree that your contributions will be licensed under MIT OR Apache-2.0.

## Getting Help

- **Issues:** Bug reports and feature requests
- **Email:** [dikaveman@gmail.com](mailto:dikaveman@gmail.com)

Every contribution matters! 🚀
