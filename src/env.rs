use anyhow::{Result, bail};

/// Resolve the caller's `$HOME`. Returns a normal error (not a panic) when it
/// is unset or not valid UTF-8 — basta binds and `--setenv`s it as a string.
pub fn host_home() -> Result<String> {
    std::env::var("HOME").map_err(|_| anyhow::anyhow!("$HOME is unset or not valid UTF-8"))
}

/// Env keys basta sets itself in argv.rs. `--env` must not shadow them —
/// a caller-supplied HOME/PATH/etc. would rewrite mount destinations or
/// the in-sandbox lookup path.
const RESERVED: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "XDG_RUNTIME_DIR",
    "TERM",
    "LANG",
    "LC_ALL",
];

pub struct EnvSpec {
    pub key: String,
    pub value: String,
}

impl EnvSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let (key, value) = match spec.split_once('=') {
            Some((k, v)) => (k, v.to_string()),
            None => {
                let v = std::env::var(spec)
                    .map_err(|_| anyhow::anyhow!("env passthrough '{spec}' unset on host"))?;
                (spec, v)
            }
        };
        if !is_valid_key(key) {
            bail!("invalid env key: '{key}' (must match ^[A-Za-z_][A-Za-z0-9_]*$)");
        }
        if RESERVED.contains(&key) {
            bail!("--env cannot override reserved key '{key}' — basta sets it");
        }
        Ok(EnvSpec {
            key: key.to_string(),
            value,
        })
    }
}

fn is_valid_key(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_keys() {
        assert!(is_valid_key("FOO"));
        assert!(is_valid_key("FOO_BAR"));
        assert!(is_valid_key("_FOO"));
        assert!(is_valid_key("FOO123"));
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("123FOO"));
        assert!(!is_valid_key("FOO BAR"));
        assert!(!is_valid_key("FOO=BAR"));
        assert!(!is_valid_key("--bind"));
    }

    #[test]
    fn parse_kv() {
        let e = EnvSpec::parse("FOO=bar").unwrap();
        assert_eq!(e.key, "FOO");
        assert_eq!(e.value, "bar");
    }

    #[test]
    fn parse_kv_with_equals_in_value() {
        let e = EnvSpec::parse("FOO=a=b=c").unwrap();
        assert_eq!(e.key, "FOO");
        assert_eq!(e.value, "a=b=c");
    }

    #[test]
    fn parse_rejects_invalid_key() {
        assert!(EnvSpec::parse("FOO BAR=baz").is_err());
        assert!(EnvSpec::parse("=orphan").is_err());
        assert!(EnvSpec::parse("123=bad").is_err());
    }

    #[test]
    fn parse_rejects_reserved_keys() {
        assert!(EnvSpec::parse("HOME=/etc").is_err());
        assert!(EnvSpec::parse("PATH=/evil").is_err());
        assert!(EnvSpec::parse("XDG_RUNTIME_DIR=/x").is_err());
        assert!(EnvSpec::parse("LC_ALL=C").is_err());
    }
}
