# Agent Behavior

Rules governing AI agent conduct in this repository.

## Git Usage — Read-Only Only

Agents may only run **read-only** git commands.

**Allowed**: `git status`, `git diff`, `git diff --staged`, `git log`, `git show`,
`git blame`, `git ls-files`, `git stash list`

**Banned**: `git add`, `git commit`, `git restore`, `git reset`, `git stash`,
`git merge`, `git rebase`, `git push`, `git pull`, `git fetch`, `git rm`, `git mv`,
`git tag`, `git branch -d`, `git branch <name>` (create), `git switch -c`,
`git checkout -b`

If you need to modify git state, ask the user.

### Commit Workflow (When User Instructs)

1. `git status` — see staged vs unstaged
2. `git diff --staged --stat` — verify commit scope
3. If unrelated files staged — unstage or ask user
4. Commit message must match staged content

## GitHub Issue Management

### Communication Rules

Communicate with the user directly, not via GitHub comments.

**Per issue**: ONE initial comment (< 10 lines) + edits to update progress +
ONE final comment (< 15 lines with commit links). No multi-comment progress updates.

**Forbidden**: verbose explanations, "awaiting guidance" comments without user approval,
status reports that belong in direct communication.

### Issue Workflow

- Search existing issues before starting work
- Reference issue numbers in commits (`Fixes #N`)
- Edit your initial comment for updates (don't create new ones)
- Ask the user directly for clarification

### Creating Issues

Offer to create only for **substantial, user-impacting, discussion-worthy** work.
Explain why it should be tracked, proposed scope, and alternatives.
Do NOT create issues for trivial fixes, completed work, or vague ideas.

## Contributing Rules

- Do not invent new surface APIs without discussion.
- Do not add helpers ad-hoc; propose design first.
- Follow module layout: `src/error`, `src/path`, `src/validator`, re-exports in `src/lib.rs`.
- Respect MSRV in library; demos may use newer crates behind features.

## Coding Session Discipline

### Trust the Code — Ask Before "Fixing"

When something seems unusual or wrong:
1. **Assume intentional** — this crate has security-motivated design decisions.
2. **Read surrounding code and docs** for rationale.
3. **ASK the maintainer** — present confusion as a question, not a fix.
4. **Never "fix" unilaterally** — especially API surface restrictions, "missing"
   methods, visibility choices, or type design decisions.

### Tests Must Use Public API Only

- Use `strictpath_display().to_string()` for comparisons
- Use `interop_path()` where `AsRef<Path>` is needed
- Use built-in I/O helpers for filesystem assertions
- If a test can't use public API, that's a signal to fix the API

### Test-First / Proof-First

Red → green → refactor. Write/update tests first for non-trivial changes.
Every bugfix includes a regression test.

### Evidence Rule

"Implemented" without proof is not acceptable. Provide:
- Tests proving behavior
- CI output showing clean build
- Manual verification notes (if no automation)

## Handling External Feedback

1. **Check against established principles first** — never weaken a principle to match feedback.
2. **Use git history** — `git log -S "<term>" --oneline` to resolve contradictions.
3. **Verify the claim** — quote actual text; reject if mischaracterized.
4. **Assess severity independently** — don't accept reviewer's rating at face value.
5. **Distinguish bugs from preferences** — fix invariant violations; evaluate preferences against cost.
6. **Reject with justification** when findings are invalid.
7. **Check for cascade** — fix the same pattern in all files in one pass.

## PR Checklist (Self-Check)

- [ ] Security guarantees preserved — no boundary escapes, no new `AsRef<Path>`/`Deref` leaks
- [ ] All `ci-local` steps pass locally
- [ ] New/changed logic covered by tests + doctests
- [ ] Docs updated if user-visible behavior changed
- [ ] No new runtime deps; MSRV respected; no unstable features
- [ ] No `#[allow(...)]` beyond approved `clippy::type_complexity`
- [ ] Doctests runnable with no skip flags
- [ ] Regression tests for every bugfix
