//! Optional client configuration: `~/.saltsh/config`, in ssh_config style.
//!
//! ```text
//! Host *.example.com
//!     Protocol MYSECRET/1
//!
//! Host 10.0.0.*
//!     Protocol SALTSH/2
//! ```
//!
//! Semantics (matching ssh_config):
//! * `Host` starts a section; its patterns (`*`, `?`, `!` negation,
//!   comma/space separated) are matched against the host the client was
//!   given on the command line.
//! * The **first** matching section wins; within a section the first
//!   occurrence of an option wins.
//! * Command-line flags always override the file.
//! * Only `Protocol` is honored today; unknown options and malformed
//!   lines are ignored (forward-compatible leniency).

use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;

struct Section {
    /// Comma-joined pattern list for this Host block.
    patterns: String,
    options: HashMap<String, String>,
}

pub struct ClientConfig {
    sections: Vec<Section>,
}

impl ClientConfig {
    /// Parse config file contents.
    pub fn parse(text: &str) -> ClientConfig {
        let mut sections: Vec<Section> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut toks = line.split_whitespace();
            let Some(first) = toks.next() else { continue };
            if first.eq_ignore_ascii_case("host") {
                let patterns: Vec<&str> = toks.collect();
                if !patterns.is_empty() {
                    sections.push(Section {
                        patterns: patterns.join(","),
                        options: HashMap::new(),
                    });
                }
            } else if let Some(section) = sections.last_mut() {
                // `first` is the option key; the rest is its value.
                let value = toks.collect::<Vec<_>>().join(" ");
                if !value.is_empty() {
                    let key = first.to_ascii_lowercase();
                    section.options.entry(key).or_insert(value);
                }
            }
        }
        ClientConfig { sections }
    }

    /// First value of `key` from the first section whose pattern list
    /// matches `host` (OpenSSH pattern-list semantics: `*`/`?` globs,
    /// `!` negation, comma-separated).
    pub fn get(&self, host: &str, key: &str) -> Option<&str> {
        for section in &self.sections {
            if crate::sshkeys::match_pattern_list(&section.patterns, host) {
                if let Some(v) = section.options.get(key) {
                    return Some(v.as_str());
                }
            }
        }
        None
    }

    /// The configured protocol identifier for `host`, if any.
    pub fn protocol_for(&self, host: &str) -> Option<&str> {
        self.get(host, "protocol")
    }
}

/// Load `path` (`~/.saltsh/config`); `Ok(None)` when the file is absent
/// (the config is optional) or unreadable (with a warning).
pub fn load(path: &Path) -> Result<Option<ClientConfig>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(ClientConfig::parse(&text))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            eprintln!("saltsh: warning: cannot read {}: {e}", path.display());
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_sections_and_options() {
        let cfg = ClientConfig::parse(
            "\
# comment
Host *.example.com
    Protocol MYSECRET/1
    protocol DUP/1

Host other.example.com,10.0.0.*
    Protocol SALTSH/2

UnknownOption value
",
        );
        // first occurrence within a section wins
        assert_eq!(cfg.protocol_for("a.example.com"), Some("MYSECRET/1"));
        // first MATCHING section wins: other.example.com also matches the
        // first section's *.example.com, so the second section never applies
        assert_eq!(cfg.protocol_for("other.example.com"), Some("MYSECRET/1"));
        // only the second section matches an IP-style host
        assert_eq!(cfg.protocol_for("10.0.0.7"), Some("SALTSH/2"));
        // no match
        assert_eq!(cfg.protocol_for("unrelated.com"), None);
    }

    #[test]
    fn pattern_semantics() {
        let cfg = ClientConfig::parse(
            "\
Host *.corp,!backup.corp
    Protocol A/1
",
        );
        assert_eq!(cfg.protocol_for("web.corp"), Some("A/1"));
        assert_eq!(cfg.protocol_for("backup.corp"), None);
    }

    #[test]
    fn case_insensitive_keys_and_keywords() {
        let cfg = ClientConfig::parse("hOsT x.example\n    PrOtOcOl B/2\n");
        assert_eq!(cfg.protocol_for("x.example"), Some("B/2"));
    }

    #[test]
    fn malformed_lines_ignored() {
        let cfg = ClientConfig::parse("garbage line\nProtocol NOLINE/1\nHost h\n\n");
        // "Protocol NOLINE/1" before any Host section is ignored
        assert_eq!(cfg.protocol_for("h"), None);
    }
}
