//! Reading and writing the project's `package.json`.

use crate::error::{Result, VaultError};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A minimal view over a project's `package.json`.
///
/// We keep the original [`serde_json::Value`] around so that writing the file
/// back preserves every field we don't explicitly understand.
#[derive(Debug, Clone)]
pub struct PackageJson {
    path: PathBuf,
    raw: Value,
}

impl PackageJson {
    /// Load `package.json` from the given project directory.
    pub fn load(project_dir: &Path) -> Result<Self> {
        let path = project_dir.join("package.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| VaultError::PackageJson(format!("{}: {e}", path.display())))?;
        let raw: Value = serde_json::from_str(&text)
            .map_err(|e| VaultError::PackageJson(format!("{}: {e}", path.display())))?;
        Ok(Self { path, raw })
    }

    /// Create an empty `package.json` scaffold in the given directory.
    pub fn scaffold(project_dir: &Path, name: &str) -> Self {
        let mut map = Map::new();
        map.insert("name".into(), Value::String(name.to_string()));
        map.insert("version".into(), Value::String("1.0.0".to_string()));
        map.insert("dependencies".into(), Value::Object(Map::new()));
        Self {
            path: project_dir.join("package.json"),
            raw: Value::Object(map),
        }
    }

    /// The package `name`, if present.
    pub fn name(&self) -> Option<&str> {
        self.raw.get("name").and_then(Value::as_str)
    }

    /// Runtime + dev dependency requirements merged into a single map.
    ///
    /// Returns a map of `name -> version range`.
    pub fn all_dependencies(&self, include_dev: bool) -> BTreeMap<String, String> {
        let mut deps = BTreeMap::new();
        for key in ["dependencies", "optionalDependencies"] {
            self.collect_into(key, &mut deps);
        }
        if include_dev {
            self.collect_into("devDependencies", &mut deps);
        }
        deps
    }

    fn collect_into(&self, key: &str, out: &mut BTreeMap<String, String>) {
        if let Some(Value::Object(map)) = self.raw.get(key) {
            for (name, range) in map {
                if let Some(range) = range.as_str() {
                    out.insert(name.clone(), range.to_string());
                }
            }
        }
    }

    /// The body of a named entry in the `scripts` map, if present.
    pub fn script(&self, name: &str) -> Option<String> {
        self.raw
            .get("scripts")?
            .get(name)?
            .as_str()
            .map(str::to_string)
    }

    /// Insert or update a dependency in `dependencies`.
    pub fn set_dependency(&mut self, name: &str, range: &str) {
        let obj = self.raw.as_object_mut().expect("package.json is an object");
        let deps = obj
            .entry("dependencies")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = deps {
            map.insert(name.to_string(), Value::String(range.to_string()));
        }
    }

    /// Remove a dependency from every dependency section.
    pub fn remove_dependency(&mut self, name: &str) -> bool {
        let mut removed = false;
        if let Some(obj) = self.raw.as_object_mut() {
            for key in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(Value::Object(map)) = obj.get_mut(key) {
                    removed |= map.remove(name).is_some();
                }
            }
        }
        removed
    }

    /// Persist the file back to disk with stable 2-space indentation.
    pub fn save(&self) -> Result<()> {
        let text = serde_json::to_string_pretty(&self.raw)?;
        std::fs::write(&self.path, format!("{text}\n"))?;
        Ok(())
    }
}
