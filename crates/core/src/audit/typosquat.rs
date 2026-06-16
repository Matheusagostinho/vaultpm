//! Typosquatting heuristic (phase 2).
//!
//! Compares a package name against a bundled list of very popular packages. A
//! name within a small edit distance of a popular one — but not equal to it —
//! is a classic typosquat (`lodahs`, `expresss`, `crossenv`, …). Soft warning
//! only; legitimate similarly-named packages exist.

/// A curated slice of high-traffic npm package names. Kept short and obvious on
/// purpose; the goal is catching look-alikes of the most-attacked packages, not
/// exhaustive coverage.
const POPULAR: &[&str] = &[
    "lodash",
    "react",
    "react-dom",
    "express",
    "chalk",
    "axios",
    "commander",
    "request",
    "debug",
    "async",
    "moment",
    "vue",
    "webpack",
    "babel",
    "eslint",
    "typescript",
    "jest",
    "mocha",
    "next",
    "dotenv",
    "cross-env",
    "colors",
    "node-fetch",
    "uuid",
    "yargs",
    "rimraf",
    "glob",
    "semver",
    "bluebird",
    "underscore",
    "jquery",
    "socket.io",
    "mongoose",
    "redux",
    "prettier",
];

/// Maximum edit distance considered a likely typosquat.
const MAX_DISTANCE: usize = 2;

/// If `name` looks like a typosquat of a popular package, return that package.
pub fn nearest_popular(name: &str) -> Option<&'static str> {
    let name = name.to_lowercase();
    let mut best: Option<(&'static str, usize)> = None;
    for &popular in POPULAR {
        if name == popular {
            return None; // exact match — it *is* the popular package
        }
        let d = levenshtein(&name, popular);
        // Distance must be small relative to the name length to avoid noise on
        // very short names (e.g. "ms" vs "fs").
        if d <= MAX_DISTANCE && d > 0 && popular.len() >= 4 {
            best = Some(match best {
                Some((_, bd)) if bd <= d => best.unwrap(),
                _ => (popular, d),
            });
        }
    }
    best.map(|(p, _)| p)
}

/// Classic dynamic-programming Levenshtein distance.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_basics() {
        assert_eq!(levenshtein("lodash", "lodash"), 0);
        assert_eq!(levenshtein("lodahs", "lodash"), 2); // transposition = 2 edits
        assert_eq!(levenshtein("expresss", "express"), 1);
    }

    #[test]
    fn catches_typosquats() {
        assert_eq!(nearest_popular("expresss"), Some("express"));
        assert_eq!(nearest_popular("crossenv"), Some("cross-env"));
        assert_eq!(nearest_popular("loadash"), Some("lodash"));
    }

    #[test]
    fn exact_popular_is_safe() {
        assert_eq!(nearest_popular("lodash"), None);
        assert_eq!(nearest_popular("react"), None);
    }

    #[test]
    fn unrelated_names_are_safe() {
        assert_eq!(nearest_popular("my-cool-internal-lib"), None);
        assert_eq!(nearest_popular("is-odd"), None);
    }
}
