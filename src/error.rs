//! Crate-wide error handling: [`anyhow`] for ergonomics, context attached at
//! the call sites; `main` prints only the top-level message.

/// Canonical `Result` alias for the crate.
pub type Result<T> = std::result::Result<T, anyhow::Error>;
