//! Signed eBPF bytecode manifest verification (Issue #44 Phase 1).
//!
//! # What this protects against
//!
//! Fail-closed startup attestation detects silent supply-chain / on-disk swaps of
//! the embedded BPF objects (`sys_exec.bpf.o`, `network_filter.bpf.o`, and the
//! Ring-0 LSM enforcement ELF) before any of those objects are loaded into the
//! kernel. Accidental or scripted tampering of those artifacts is fail-closed.
//!
//! # What this does NOT protect against
//!
//! This is **tamper evidence / detection**, not prevention against a fully
//! determined root attacker. A root-privileged adversary who can also suppress
//! or rewrite the alert channel, replace the orchestrator binary and its baked
//! manifest+signature together (and re-sign with a stolen key), or attack
//! in-kernel / direct memory after load, is out of scope for Phase 1. Do not
//! document or market this control as "root cannot tamper."
//!
//! # Trust boundaries
//!
//! - **Covered here:** digests of the three `include_bytes!` BPF payloads that
//!   this process is about to load, matched against a Cosign-static-key-signed
//!   JSON manifest baked into the container image at build time.
//! - **Not covered here (by design):** the agent binary itself — embedding a
//!   self-digest of the running executable into a manifest that is itself
//!   packaged inside that executable is circular. The binary+image layer is
//!   already covered by the existing Cosign image signature (PR #47 /
//!   `k8s-admission-webhook`).
//! - **Public key delivery:** mounted at runtime (Secret), mirroring the
//!   webhook's `NEUROMESH_COSIGN_PUBLIC_KEY_PATH` pattern — not baked into the
//!   image — so the trust root is not solely under the same writeable rootfs
//!   as the artifacts being attested.
//!
//! # Fail-closed contract
//!
//! There is **no** environment variable, feature flag, or fallback that allows
//! startup to proceed after a verification failure. Any failure aborts before
//! `EbpfLoader::load` / `Ebpf::load` / `load_with_map_pinning`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey as Ed25519DecodePublicKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::signature::Verifier as EcdsaVerifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as P256VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Same env var name as `apps/k8s-admission-webhook` Cosign static-key mode.
pub const ENV_COSIGN_PUBLIC_KEY_PATH: &str = "NEUROMESH_COSIGN_PUBLIC_KEY_PATH";

/// Absolute path to the baked-in signed bytecode JSON manifest.
pub const ENV_BYTECODE_MANIFEST_PATH: &str = "NEUROMESH_BYTECODE_MANIFEST_PATH";

/// Absolute path to the Cosign `sign-blob` detached signature over the manifest.
pub const ENV_BYTECODE_MANIFEST_SIG_PATH: &str = "NEUROMESH_BYTECODE_MANIFEST_SIG_PATH";

/// Default public-key mount path for the agent DaemonSet (webhook uses
/// `/etc/webhook/cosign/cosign.pub`; same Secret material, agent-specific mount).
pub const DEFAULT_COSIGN_PUBLIC_KEY_PATH: &str = "/etc/neuromesh/cosign/cosign.pub";

/// Default baked-in manifest path inside the agent container image.
pub const DEFAULT_BYTECODE_MANIFEST_PATH: &str = "/etc/neuromesh/bytecode-manifest.json";

/// Default baked-in Cosign detached signature path.
pub const DEFAULT_BYTECODE_MANIFEST_SIG_PATH: &str = "/etc/neuromesh/bytecode-manifest.sig";

/// Exact artifact names that must appear in every valid Phase 1 manifest.
pub const REQUIRED_ARTIFACT_NAMES: &[&str] = &[
    "sys_exec.bpf.o",
    "network_filter.bpf.o",
    "agent-ebpf-sensor-ebpf",
];

const EXPECTED_SCHEMA_VERSION: u32 = 1;

/// One embedded BPF artifact to attest (name must match the manifest entry).
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedArtifact<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

/// Specific fail-closed failure reasons for the audit trail.
#[derive(Debug)]
pub enum AttestationError {
    ManifestMissing { path: PathBuf },
    ManifestUnreadable { path: PathBuf, source: io::Error },
    SignatureMissing { path: PathBuf },
    SignatureUnreadable { path: PathBuf, source: io::Error },
    PublicKeyMissing { path: PathBuf },
    PublicKeyUnreadable { path: PathBuf, source: io::Error },
    PublicKeyInvalid { reason: String },
    PathNotAbsolute { env: &'static str, path: String },
    SignatureInvalid { reason: String },
    ManifestParse { reason: String },
    ManifestSchema { reason: String },
    ArtifactMissingFromManifest { name: String },
    UnexpectedArtifactInManifest { name: String },
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestMissing { path } => {
                write!(f, "bytecode manifest missing at {}", path.display())
            }
            Self::ManifestUnreadable { path, source } => {
                write!(
                    f,
                    "bytecode manifest unreadable at {}: {source}",
                    path.display()
                )
            }
            Self::SignatureMissing { path } => {
                write!(
                    f,
                    "bytecode manifest signature missing at {}",
                    path.display()
                )
            }
            Self::SignatureUnreadable { path, source } => {
                write!(
                    f,
                    "bytecode manifest signature unreadable at {}: {source}",
                    path.display()
                )
            }
            Self::PublicKeyMissing { path } => {
                write!(f, "Cosign public key missing at {}", path.display())
            }
            Self::PublicKeyUnreadable { path, source } => {
                write!(
                    f,
                    "Cosign public key unreadable at {}: {source}",
                    path.display()
                )
            }
            Self::PublicKeyInvalid { reason } => {
                write!(f, "Cosign public key invalid: {reason}")
            }
            Self::PathNotAbsolute { env, path } => {
                write!(f, "{env} must be an absolute path, got {path:?}")
            }
            Self::SignatureInvalid { reason } => {
                write!(f, "bytecode manifest signature verification failed: {reason}")
            }
            Self::ManifestParse { reason } => {
                write!(f, "bytecode manifest JSON parse failed: {reason}")
            }
            Self::ManifestSchema { reason } => {
                write!(f, "bytecode manifest schema invalid: {reason}")
            }
            Self::ArtifactMissingFromManifest { name } => {
                write!(f, "required artifact {name:?} missing from manifest")
            }
            Self::UnexpectedArtifactInManifest { name } => {
                write!(
                    f,
                    "unexpected artifact {name:?} in manifest (not in Phase 1 coverage set)"
                )
            }
            Self::DigestMismatch {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "digest mismatch for artifact {name:?}: manifest={expected} actual={actual}"
                )
            }
        }
    }
}

impl std::error::Error for AttestationError {}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: u32,
    #[allow(dead_code)]
    git_sha: String,
    #[allow(dead_code)]
    build_timestamp: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Deserialize)]
struct ManifestArtifact {
    name: String,
    digest: String,
}

/// Resolve attestation paths from the environment (absolute paths only).
pub fn paths_from_env() -> Result<(PathBuf, PathBuf, PathBuf), AttestationError> {
    let manifest = env_abs_path(ENV_BYTECODE_MANIFEST_PATH, DEFAULT_BYTECODE_MANIFEST_PATH)?;
    let signature =
        env_abs_path(ENV_BYTECODE_MANIFEST_SIG_PATH, DEFAULT_BYTECODE_MANIFEST_SIG_PATH)?;
    let public_key = env_abs_path(ENV_COSIGN_PUBLIC_KEY_PATH, DEFAULT_COSIGN_PUBLIC_KEY_PATH)?;
    Ok((manifest, signature, public_key))
}

fn env_abs_path(env: &'static str, default: &str) -> Result<PathBuf, AttestationError> {
    let raw = std::env::var(env).unwrap_or_else(|_| default.to_string());
    let path = PathBuf::from(&raw);
    if !path.is_absolute() {
        return Err(AttestationError::PathNotAbsolute {
            env,
            path: raw,
        });
    }
    Ok(path)
}

/// SHA-256 digest in OCI/`sha256:<hex>` form (lowercase hex).
pub fn sha256_digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    format!("sha256:{}", hex_encode(hash.as_ref()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Verify Cosign static-key detached signature over `message`.
///
/// Matches `cosign sign-blob` / `cosign verify-blob` for ECDSA P-256 (Cosign
/// default) and Ed25519 PEM public keys — the same key types the admission
/// webhook accepts via `signature.LoadVerifier(..., SHA256)`.
pub fn verify_cosign_blob_signature(
    public_key_pem: &[u8],
    message: &[u8],
    signature_file_bytes: &[u8],
) -> Result<(), AttestationError> {
    let sig_b64 = std::str::from_utf8(signature_file_bytes)
        .map_err(|e| AttestationError::SignatureInvalid {
            reason: format!("signature file is not UTF-8: {e}"),
        })?
        .trim();
    if sig_b64.is_empty() {
        return Err(AttestationError::SignatureInvalid {
            reason: "signature file is empty".into(),
        });
    }
    let sig_raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| AttestationError::SignatureInvalid {
            reason: format!("signature is not valid base64: {e}"),
        })?;

    let pem_str = std::str::from_utf8(public_key_pem).map_err(|e| {
        AttestationError::PublicKeyInvalid {
            reason: format!("public key PEM is not UTF-8: {e}"),
        }
    })?;

    if let Ok(key) = P256VerifyingKey::from_public_key_pem(pem_str) {
        let signature = parse_ecdsa_signature(&sig_raw)?;
        return key.verify(message, &signature).map_err(|e| {
            AttestationError::SignatureInvalid {
                reason: format!("ECDSA P-256 verification failed: {e}"),
            }
        });
    }

    if let Ok(key) = Ed25519VerifyingKey::from_public_key_pem(pem_str) {
        if sig_raw.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(AttestationError::SignatureInvalid {
                reason: format!(
                    "Ed25519 signature length {}, expected {}",
                    sig_raw.len(),
                    ed25519_dalek::SIGNATURE_LENGTH
                ),
            });
        }
        let mut sig_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(&sig_raw);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        return key
            .verify_strict(message, &signature)
            .map_err(|e| AttestationError::SignatureInvalid {
                reason: format!("Ed25519 verification failed: {e}"),
            });
    }

    Err(AttestationError::PublicKeyInvalid {
        reason: "PEM is neither Cosign ECDSA P-256 nor Ed25519 SubjectPublicKeyInfo".into(),
    })
}

fn parse_ecdsa_signature(sig_raw: &[u8]) -> Result<EcdsaSignature, AttestationError> {
    EcdsaSignature::from_der(sig_raw)
        .or_else(|_| EcdsaSignature::from_slice(sig_raw))
        .map_err(|e| AttestationError::SignatureInvalid {
            reason: format!("ECDSA signature neither DER nor raw fixed-size: {e}"),
        })
}

/// Core verification: signed manifest + digest match for every embedded artifact.
///
/// Callers must invoke this **before** any BPF load of covered objects.
pub fn verify_artifacts(
    manifest_path: &Path,
    signature_path: &Path,
    public_key_path: &Path,
    artifacts: &[EmbeddedArtifact<'_>],
) -> Result<(), AttestationError> {
    let public_key_pem = read_file(
        public_key_path,
        AttestationError::PublicKeyMissing {
            path: public_key_path.to_path_buf(),
        },
        |source| AttestationError::PublicKeyUnreadable {
            path: public_key_path.to_path_buf(),
            source,
        },
    )?;

    let manifest_bytes = read_file(
        manifest_path,
        AttestationError::ManifestMissing {
            path: manifest_path.to_path_buf(),
        },
        |source| AttestationError::ManifestUnreadable {
            path: manifest_path.to_path_buf(),
            source,
        },
    )?;

    let signature_bytes = read_file(
        signature_path,
        AttestationError::SignatureMissing {
            path: signature_path.to_path_buf(),
        },
        |source| AttestationError::SignatureUnreadable {
            path: signature_path.to_path_buf(),
            source,
        },
    )?;

    // Signature over the exact on-disk manifest bytes (no re-serialization).
    verify_cosign_blob_signature(&public_key_pem, &manifest_bytes, &signature_bytes)?;

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| AttestationError::ManifestParse {
            reason: e.to_string(),
        })?;

    if manifest.schema_version != EXPECTED_SCHEMA_VERSION {
        return Err(AttestationError::ManifestSchema {
            reason: format!(
                "schema_version {} (expected {EXPECTED_SCHEMA_VERSION})",
                manifest.schema_version
            ),
        });
    }
    if manifest.git_sha.trim().is_empty() {
        return Err(AttestationError::ManifestSchema {
            reason: "git_sha is empty".into(),
        });
    }
    if manifest.build_timestamp.trim().is_empty() {
        return Err(AttestationError::ManifestSchema {
            reason: "build_timestamp is empty".into(),
        });
    }

    validate_artifact_set(&manifest, artifacts)?;

    for artifact in artifacts {
        let entry = manifest
            .artifacts
            .iter()
            .find(|a| a.name == artifact.name)
            .expect("validated set contains every required name");
        if artifact.bytes.is_empty() {
            return Err(AttestationError::DigestMismatch {
                name: artifact.name.to_string(),
                expected: entry.digest.clone(),
                actual: "sha256:<unreadable-or-empty-embedded-bytes>".into(),
            });
        }
        let actual = sha256_digest(artifact.bytes);
        if actual != entry.digest {
            return Err(AttestationError::DigestMismatch {
                name: artifact.name.to_string(),
                expected: entry.digest.clone(),
                actual,
            });
        }
    }

    Ok(())
}

fn validate_artifact_set(
    manifest: &Manifest,
    artifacts: &[EmbeddedArtifact<'_>],
) -> Result<(), AttestationError> {
    if artifacts.len() != REQUIRED_ARTIFACT_NAMES.len() {
        return Err(AttestationError::ManifestSchema {
            reason: format!(
                "caller supplied {} artifacts; Phase 1 requires exactly {}",
                artifacts.len(),
                REQUIRED_ARTIFACT_NAMES.len()
            ),
        });
    }
    for required in REQUIRED_ARTIFACT_NAMES {
        if !artifacts.iter().any(|a| a.name == *required) {
            return Err(AttestationError::ArtifactMissingFromManifest {
                name: (*required).to_string(),
            });
        }
        if !manifest.artifacts.iter().any(|a| a.name == *required) {
            return Err(AttestationError::ArtifactMissingFromManifest {
                name: (*required).to_string(),
            });
        }
    }
    for entry in &manifest.artifacts {
        if !REQUIRED_ARTIFACT_NAMES.contains(&entry.name.as_str()) {
            return Err(AttestationError::UnexpectedArtifactInManifest {
                name: entry.name.clone(),
            });
        }
        if !entry.digest.starts_with("sha256:") || entry.digest.len() != "sha256:".len() + 64 {
            return Err(AttestationError::ManifestSchema {
                reason: format!(
                    "artifact {:?} digest must be sha256:<64 lowercase hex>, got {:?}",
                    entry.name, entry.digest
                ),
            });
        }
    }
    if manifest.artifacts.len() != REQUIRED_ARTIFACT_NAMES.len() {
        return Err(AttestationError::ManifestSchema {
            reason: format!(
                "manifest has {} artifacts; expected exactly {}",
                manifest.artifacts.len(),
                REQUIRED_ARTIFACT_NAMES.len()
            ),
        });
    }
    Ok(())
}

fn read_file(
    path: &Path,
    missing: AttestationError,
    unreadable: impl FnOnce(io::Error) -> AttestationError,
) -> Result<Vec<u8>, AttestationError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(missing),
        Err(e) => Err(unreadable(e)),
    }
}

/// Startup entry point: resolve paths from env and verify all embedded artifacts.
pub fn verify_startup(artifacts: &[EmbeddedArtifact<'_>]) -> Result<(), AttestationError> {
    let (manifest, signature, public_key) = paths_from_env()?;
    verify_artifacts(&manifest, &signature, &public_key, artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey as Ed25519EncodePublicKey;
    use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::signature::Signer as P256EcdsaSigner;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::pkcs8::LineEnding;
    use rand_core::OsRng;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("neuromesh-attest-{nanos}"));
        fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent");
        }
        fs::write(path, bytes).expect("write");
    }

    struct Fixture {
        manifest: PathBuf,
        signature: PathBuf,
        public_key: PathBuf,
        signing_key: P256SigningKey,
        artifacts: Vec<(String, Vec<u8>)>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tmp_dir();
            let signing_key = P256SigningKey::random(&mut OsRng);
            let pem = signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .expect("pem");
            let public_key = dir.join("cosign.pub");
            write(&public_key, pem.as_bytes());

            let artifacts = vec![
                ("sys_exec.bpf.o".into(), b"sys-exec-bytecode-v1".to_vec()),
                (
                    "network_filter.bpf.o".into(),
                    b"network-filter-bytecode-v1".to_vec(),
                ),
                (
                    "agent-ebpf-sensor-ebpf".into(),
                    b"enforcement-elf-bytecode-v1".to_vec(),
                ),
            ];

            let mut f = Self {
                manifest: dir.join("bytecode-manifest.json"),
                signature: dir.join("bytecode-manifest.sig"),
                public_key,
                signing_key,
                artifacts,
            };
            f.write_signed_manifest();
            f
        }

        fn manifest_json(&self) -> String {
            let arts: Vec<String> = self
                .artifacts
                .iter()
                .map(|(name, bytes)| {
                    format!(
                        r#"{{"name":"{name}","digest":"{}"}}"#,
                        sha256_digest(bytes)
                    )
                })
                .collect();
            format!(
                r#"{{"schema_version":1,"git_sha":"deadbeef","build_timestamp":"2026-07-17T00:00:00Z","artifacts":[{}]}}"#,
                arts.join(",")
            )
        }

        fn write_signed_manifest(&mut self) {
            let json = self.manifest_json();
            write(&self.manifest, json.as_bytes());
            let sig: EcdsaSignature = P256EcdsaSigner::sign(&self.signing_key, json.as_bytes());
            let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_der());
            write(&self.signature, b64.as_bytes());
        }

        fn embedded(&self) -> Vec<EmbeddedArtifact<'_>> {
            self.artifacts
                .iter()
                .map(|(n, b)| EmbeddedArtifact {
                    name: n.as_str(),
                    bytes: b.as_slice(),
                })
                .collect()
        }

        fn verify(&self) -> Result<(), AttestationError> {
            let embedded = self.embedded();
            verify_artifacts(
                &self.manifest,
                &self.signature,
                &self.public_key,
                &embedded,
            )
        }
    }

    #[test]
    fn valid_manifest_signature_and_digests_succeeds() {
        let f = Fixture::new();
        f.verify().expect("valid attestation must succeed");
    }

    #[test]
    fn missing_manifest_fails_closed() {
        let f = Fixture::new();
        fs::remove_file(&f.manifest).unwrap();
        let err = f.verify().expect_err("missing manifest");
        assert!(
            matches!(err, AttestationError::ManifestMissing { .. }),
            "got {err}"
        );
    }

    #[test]
    fn missing_signature_fails_closed() {
        let f = Fixture::new();
        fs::remove_file(&f.signature).unwrap();
        let err = f.verify().expect_err("missing signature");
        assert!(
            matches!(err, AttestationError::SignatureMissing { .. }),
            "got {err}"
        );
    }

    #[test]
    fn invalid_signature_bytes_fails_closed() {
        let f = Fixture::new();
        write(&f.signature, b"not-valid-base64-signature!!!");
        let err = f.verify().expect_err("invalid signature");
        assert!(
            matches!(err, AttestationError::SignatureInvalid { .. }),
            "got {err}"
        );
    }

    #[test]
    fn tampered_manifest_fails_closed() {
        let f = Fixture::new();
        // Alter signed content — Cosign detached signature must no longer verify.
        let mut json = fs::read_to_string(&f.manifest).unwrap();
        json = json.replace("deadbeef", "cafebabe");
        write(&f.manifest, json.as_bytes());
        let err = f.verify().expect_err("tampered manifest");
        assert!(
            matches!(err, AttestationError::SignatureInvalid { .. }),
            "got {err}"
        );
    }

    #[test]
    fn digest_mismatch_sys_exec_fails_closed() {
        let mut f = Fixture::new();
        f.artifacts[0].1 = b"tampered-sys-exec".to_vec();
        let err = f.verify().expect_err("sys_exec digest mismatch");
        match err {
            AttestationError::DigestMismatch { name, .. } => {
                assert_eq!(name, "sys_exec.bpf.o");
            }
            other => panic!("expected DigestMismatch, got {other}"),
        }
    }

    #[test]
    fn digest_mismatch_network_filter_fails_closed() {
        let mut f = Fixture::new();
        f.artifacts[1].1 = b"tampered-network-filter".to_vec();
        let err = f.verify().expect_err("network_filter digest mismatch");
        match err {
            AttestationError::DigestMismatch { name, .. } => {
                assert_eq!(name, "network_filter.bpf.o");
            }
            other => panic!("expected DigestMismatch, got {other}"),
        }
    }

    #[test]
    fn digest_mismatch_enforcement_fails_closed() {
        let mut f = Fixture::new();
        f.artifacts[2].1 = b"tampered-enforcement-elf".to_vec();
        let err = f.verify().expect_err("enforcement digest mismatch");
        match err {
            AttestationError::DigestMismatch { name, .. } => {
                assert_eq!(name, "agent-ebpf-sensor-ebpf");
            }
            other => panic!("expected DigestMismatch, got {other}"),
        }
    }

    #[test]
    fn empty_embedded_bytes_fails_closed() {
        let mut f = Fixture::new();
        f.artifacts[0].1.clear();
        let err = f.verify().expect_err("empty bytes");
        assert!(
            matches!(err, AttestationError::DigestMismatch { .. }),
            "got {err}"
        );
    }

    #[test]
    fn missing_public_key_fails_closed() {
        let f = Fixture::new();
        fs::remove_file(&f.public_key).unwrap();
        let err = f.verify().expect_err("missing pubkey");
        assert!(
            matches!(err, AttestationError::PublicKeyMissing { .. }),
            "got {err}"
        );
    }

    #[test]
    fn ed25519_cosign_compatible_signature_verifies() {
        let dir = tmp_dir();
        let sk = Ed25519SigningKey::generate(&mut OsRng);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("ed25519 pem");
        let pub_path = dir.join("cosign.pub");
        write(&pub_path, pem.as_bytes());

        let artifacts = [
            EmbeddedArtifact {
                name: "sys_exec.bpf.o",
                bytes: b"a",
            },
            EmbeddedArtifact {
                name: "network_filter.bpf.o",
                bytes: b"b",
            },
            EmbeddedArtifact {
                name: "agent-ebpf-sensor-ebpf",
                bytes: b"c",
            },
        ];
        let json = format!(
            r#"{{"schema_version":1,"git_sha":"abc","build_timestamp":"t","artifacts":[
              {{"name":"sys_exec.bpf.o","digest":"{}"}},
              {{"name":"network_filter.bpf.o","digest":"{}"}},
              {{"name":"agent-ebpf-sensor-ebpf","digest":"{}"}}
            ]}}"#,
            sha256_digest(b"a"),
            sha256_digest(b"b"),
            sha256_digest(b"c"),
        );
        let manifest = dir.join("m.json");
        let signature = dir.join("m.sig");
        write(&manifest, json.as_bytes());
        let sig = Ed25519Signer::sign(&sk, json.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        write(&signature, b64.as_bytes());

        verify_artifacts(&manifest, &signature, &pub_path, &artifacts).expect("ed25519 ok");
    }

    #[test]
    fn no_skip_env_bypass_is_consulted() {
        // Documented hard constraint: verification must not honor any skip flag.
        // Setting a hypothetical bypass env must not change verify_artifacts behavior.
        std::env::set_var("NEUROMESH_SKIP_BYTECODE_ATTESTATION", "1");
        std::env::set_var("NEUROMESH_BYTECODE_ATTESTATION_FAIL_OPEN", "1");
        let f = Fixture::new();
        fs::remove_file(&f.manifest).unwrap();
        let err = f.verify().expect_err("must still fail closed");
        assert!(matches!(err, AttestationError::ManifestMissing { .. }));
        std::env::remove_var("NEUROMESH_SKIP_BYTECODE_ATTESTATION");
        std::env::remove_var("NEUROMESH_BYTECODE_ATTESTATION_FAIL_OPEN");
    }
}
