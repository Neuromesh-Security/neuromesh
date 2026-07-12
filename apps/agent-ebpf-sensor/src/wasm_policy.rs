#![allow(dead_code)]

use neuromesh_common::SecurityTelemetryEvent;
use std::path::Path;

/// Verdict returned by a loaded Wasm security policy module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Deny,
    Alert,
}

/// Errors surfaced while loading or evaluating Wasm policy modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    NotImplemented,
    InvalidModule(String),
    LoadFailed(String),
}

/// Future-proof Wasm integration layer for dynamic runtime policies.
///
/// Policies ship as `.wasm` modules and are evaluated in user space so the BPF
/// kernel object does not need recompilation when rules change.
#[derive(Debug, Default)]
pub struct WasmPolicyEngine {
    loaded_policies: Vec<LoadedPolicy>,
}

#[derive(Debug, Clone)]
struct LoadedPolicy {
    name: String,
    // Future: wasmtime::Module + Store
}

impl WasmPolicyEngine {
    pub fn new() -> Self {
        Self {
            loaded_policies: Vec::new(),
        }
    }

    /// Register a Wasm policy module from disk (scaffolding — runtime not wired yet).
    pub fn load_policy_from_path(&mut self, path: &Path) -> Result<(), PolicyError> {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown.wasm")
            .to_string();

        let _bytes = std::fs::read(path).map_err(|error| {
            PolicyError::LoadFailed(format!("failed to read {}: {error}", path.display()))
        })?;

        // Future: compile with wasmtime, expose `evaluate(event) -> PolicyVerdict` export.
        self.loaded_policies.push(LoadedPolicy { name });
        Err(PolicyError::NotImplemented)
    }

    /// Evaluate all loaded policies against a telemetry event (scaffolding).
    pub fn evaluate(&self, _event: &SecurityTelemetryEvent) -> PolicyVerdict {
        PolicyVerdict::Allow
    }

    pub fn loaded_count(&self) -> usize {
        self.loaded_policies.len()
    }
}
