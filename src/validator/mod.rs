pub mod jail;
pub mod stated_path;
pub mod virtual_root;

// Keep helper functions crate-private; tests and internal modules can still use
// `crate::validator::validate` via the crate-private re-export.
pub(crate) use jail::{validate, virtualize_to_jail};

// Centralized tests for the validator module tree live under `src/validator/tests`.
// Expose them when running `cargo test` from the crate root.
#[cfg(test)]
mod tests;
