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
        bail!("service name '{name}' is invalid — only letters, numbers, '-' and '_' are allowed");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Registry, Service, ServiceKind};
    use std::path::PathBuf;

    fn service_named(name: &str) -> Service {
        Service {
            id: 1,
            name: name.to_string(),
            kind: ServiceKind::Static,
            dir: PathBuf::from("/tmp"),
            port: 8000,
            local_url: "http://127.0.0.1:8000".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp"),
            foreground: false,
        }
    }

    // --- validate_name ---------------------------------------------------

    #[test]
    fn validate_name_accepts_valid() {
        assert!(validate_name("blog").is_ok());
    }

    #[test]
    fn validate_name_allows_underscores_and_dashes() {
        assert!(validate_name("blog_1-2").is_ok());
    }

    #[test]
    fn validate_name_rejects_spaces() {
        assert!(validate_name("my blog").is_err());
    }

    #[test]
    fn validate_name_rejects_slash() {
        assert!(validate_name("a/b").is_err());
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn validate_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(validate_name(&long).is_err());
    }

    #[test]
    fn validate_name_accepts_exactly_64_chars() {
        let max = "a".repeat(64);
        assert!(validate_name(&max).is_ok());
    }

    #[test]
    fn validate_name_rejects_all_digits() {
        assert!(validate_name("12345").is_err());
    }

    // --- generate_name ---------------------------------------------------

    #[test]
    fn generate_name_simple_basename() {
        assert_eq!(generate_name(&PathBuf::from("/home/u/blog")), "blog");
    }

    #[test]
    fn generate_name_parent_dotdot() {
        // `..` has no usable file_name, so we fall back to the default.
        assert_eq!(generate_name(&PathBuf::from("..")), "service");
    }

    #[test]
    fn generate_name_trailing_slash() {
        // A trailing separator strips the final empty component; file_name is
        // the last real segment.
        assert_eq!(generate_name(&PathBuf::from("/home/u/blog/")), "blog");
    }

    #[test]
    fn generate_name_empty_to_default() {
        assert_eq!(generate_name(&PathBuf::from("")), "service");
    }

    #[test]
    fn generate_name_sanitizes_unsafe_chars() {
        assert_eq!(generate_name(&PathBuf::from("/home/u/my blog!")), "my-blog");
    }

    // --- unique_name -----------------------------------------------------

    #[test]
    fn unique_name_base_free() {
        let registry = Registry::default();
        assert_eq!(unique_name(&registry, "blog"), "blog");
    }

    #[test]
    fn unique_name_base_taken() {
        let mut registry = Registry::default();
        registry.services.push(service_named("blog"));
        assert_eq!(unique_name(&registry, "blog"), "blog-2");
    }

    #[test]
    fn unique_name_base_and_base_2_taken() {
        let mut registry = Registry::default();
        registry.services.push(service_named("blog"));
        registry.services.push(service_named("blog-2"));
        assert_eq!(unique_name(&registry, "blog"), "blog-3");
    }

    // --- property tests ---------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// A valid name ([A-Za-z0-9_-], 1..=64, not all digits) is always accepted.
        #[test]
        fn validate_name_accepts_valid_inputs(
            s in "[A-Za-z][A-Za-z0-9_-]{0,62}[A-Za-z0-9]"
        ) {
            prop_assert!(validate_name(&s).is_ok(), "{s} should be valid");
        }

        /// A name with any character outside [A-Za-z0-9_-] is rejected.
        #[test]
        fn validate_name_rejects_outside_charset(
            s in "[A-Za-z0-9_-]*[^A-Za-z0-9_-][A-Za-z0-9_-]*"
        ) {
            prop_assert!(validate_name(&s).is_err(), "{s} should be rejected");
        }

        /// generate_name never yields an empty result and never contains a path
        /// separator (so it is always a safe single path segment downstream).
        #[test]
        fn generate_name_never_empty_or_pathlike(base in "[^\\x00]{0,32}") {
            let n = generate_name(std::path::Path::new(&base));
            prop_assert!(!n.is_empty());
            prop_assert!(!n.contains('/') && !n.contains('\\'), "{n} must not contain a separator");
        }

        /// unique_name never collides with an existing name in the registry.
        #[test]
        fn unique_name_is_truly_unique(
            existing in proptest::collection::vec("[a-z]{1,5}", 0..8),
            base in "[a-z]{1,5}"
        ) {
            let mut reg = Registry::default();
            for n in &existing { reg.services.push(service_named(n)); }
            let picked = unique_name(&reg, &base);
            prop_assert!(!reg.services.iter().any(|s| s.name == picked));
        }
    }
}
