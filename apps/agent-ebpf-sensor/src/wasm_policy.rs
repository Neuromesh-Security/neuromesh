//! Intentional scaffold for a deferred Wasm policy hot-path on LSM events.
//!
//! This is **not** abandoned or dead code. `WasmPolicyEngine::new()` is
//! constructed at orchestrator startup and held for the agent lifetime so a
//! future wasmtime integration can plug in without a bootstrap rewrite.
//! Load/evaluate are not production-wired: `load_policy_from_path` returns
//! [`PolicyError::NotImplemented`]; [`WasmPolicyEngine::evaluate`] always
//! [`PolicyVerdict::Allow`].
//!
//! Out of scope for current sprints: wasmtime, a module ABI, and fail-closed
//! deny on the LSM hot path are a multi-week initiative, not a sprint item.
//! Deferred explicitly as v0.1.0-core out-of-scope in
//! `docs/threat-model.md` §1 and planned as v0.2.0 in
//! `docs/RELEASE_v0.1.0-core.md` ("Wasm policy hot-path evaluation").
//! Related: ADR-001 related work ("Wasm policy engine scaffolding").

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_starts_without_loaded_policies() {
        assert_eq!(WasmPolicyEngine::new().loaded_count(), 0);
    }

    #[test]
    fn evaluate_defaults_to_allow() {
        use neuromesh_common::SecurityTelemetryEvent;
        assert_eq!(
            WasmPolicyEngine::new().evaluate(&SecurityTelemetryEvent {
                pid: 0,
                ppid: 0,
                ppid_unresolved: false,
                uid: 0,
                euid: 0,
                comm: [0; 16],
                filename: [0; 256],
                argv_len: 0,
                argv_truncated: false,
                argv_trunc_mask: 0,
                argv: [0; neuromesh_common::MAX_ARGV_LEN],
                ..SecurityTelemetryEvent::default()
            }),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn load_policy_reports_not_implemented() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("neuromesh-wasm-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.wasm");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"\0asm").unwrap();

        let mut engine = WasmPolicyEngine::new();
        let result = engine.load_policy_from_path(&path);
        assert_eq!(result, Err(PolicyError::NotImplemented));
    }
}
