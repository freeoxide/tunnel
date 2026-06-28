//! Service name validation and generation.

use crate::error::Result;
use crate::model::Registry;
use anyhow::bail;
use std::collections::HashSet;
use std::path::Path;

/// Validate a user-provided service name: `[A-Za-z0-9_-]`, length 1..=64.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("service name cannot be empty");
    }
    if name.len() > 64 {
        bail!("service name cannot be longer than 64 characters");
    }
    if name.chars().all(|c| c.is_ascii_digit()) {
        // An all-digit name would be indistinguishable from a numeric ID when
        // used as a target, so it could never be addressed by name.
        bail!("service name cannot be all digits — it would clash with numeric IDs");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!(
            "service name '{name}' is invalid — only letters, numbers, '-' and '_' are allowed"
        );
    }
    Ok(())
}

/// Derive a default name from a directory's basename, sanitizing characters.
pub fn generate_name(dir: &Path) -> String {
    let base = dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
        })
        .unwrap_or_default();
    let trimmed = base.trim_matches('-');
    if trimmed.is_empty() {
        "service".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Produce a name unique within the registry: `base`, `base-2`, `base-3`, ...
pub fn unique_name(registry: &Registry, base: &str) -> String {
    let taken: HashSet<&str> = registry.services.iter().map(|s| s.name.as_str()).collect();
    if !taken.contains(base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
        n += 1;
    }
}
