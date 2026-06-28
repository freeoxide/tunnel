//! Crate-wide error handling.
//!
//! We lean on [`anyhow`] for ergonomics and rich context, and surface
//! user-friendly messages by attaching context at the call site (and via
//! `anyhow::bail!` for hard stops like a missing `cloudflared`). `main`
//! prints only the top-level message so the CLI output stays clean.

/// Canonical `Result` alias for the crate.
pub type Result<T> = std::result::Result<T, anyhow::Error>;
