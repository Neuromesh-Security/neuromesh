//! SPIFFE path-form construction (Slice 2b-ii-A).
//!
//! Canonical form matches PE / Rego: `spiffe://{trust}/ns/{ns}/sa/{sa}`.

/// Env for the trust domain segment (must match zt-policy-engine).
pub const SPIFFE_TRUST_DOMAIN_ENV: &str = "NEUROMESH_SPIFFE_TRUST_DOMAIN";

/// Default trust domain (PE bootstrap / Rego).
pub const DEFAULT_SPIFFE_TRUST_DOMAIN: &str = "neuromesh.security";

/// Resolve trust domain from env, or [`DEFAULT_SPIFFE_TRUST_DOMAIN`].
pub fn trust_domain_from_env() -> String {
    match std::env::var(SPIFFE_TRUST_DOMAIN_ENV) {
        Ok(v) => {
            let t = v.trim();
            if t.is_empty() {
                DEFAULT_SPIFFE_TRUST_DOMAIN.to_string()
            } else {
                t.to_string()
            }
        }
        Err(_) => DEFAULT_SPIFFE_TRUST_DOMAIN.to_string(),
    }
}

/// Build `spiffe://{trust}/ns/{namespace}/sa/{service_account}`.
///
/// Empty `service_account` becomes `"default"` (Kubernetes default SA).
pub fn construct_spiffe_id(trust_domain: &str, namespace: &str, service_account: &str) -> String {
    let sa = if service_account.trim().is_empty() {
        "default"
    } else {
        service_account.trim()
    };
    format!(
        "spiffe://{}/ns/{}/sa/{}",
        trust_domain.trim(),
        namespace.trim(),
        sa
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_form_matches_slice_2a() {
        assert_eq!(
            construct_spiffe_id("neuromesh.security", "default", "agent-ebpf-sensor"),
            "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"
        );
    }

    #[test]
    fn empty_sa_becomes_default() {
        assert_eq!(
            construct_spiffe_id("neuromesh.security", "kube-system", ""),
            "spiffe://neuromesh.security/ns/kube-system/sa/default"
        );
        assert_eq!(
            construct_spiffe_id("neuromesh.security", "kube-system", "  "),
            "spiffe://neuromesh.security/ns/kube-system/sa/default"
        );
    }

    #[test]
    fn trust_domain_env_default_and_override() {
        let _guard = {
            static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
            LOCK.get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap()
        };
        std::env::remove_var(SPIFFE_TRUST_DOMAIN_ENV);
        assert_eq!(trust_domain_from_env(), DEFAULT_SPIFFE_TRUST_DOMAIN);
        std::env::set_var(SPIFFE_TRUST_DOMAIN_ENV, "  ");
        assert_eq!(trust_domain_from_env(), DEFAULT_SPIFFE_TRUST_DOMAIN);
        std::env::set_var(SPIFFE_TRUST_DOMAIN_ENV, "corp.example");
        assert_eq!(trust_domain_from_env(), "corp.example");
        std::env::remove_var(SPIFFE_TRUST_DOMAIN_ENV);
    }
}
