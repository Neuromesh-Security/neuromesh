//! In-memory PE `identity_allow_exceptions.spiffe_ids` cache (Slice 2b-ii-A).

use std::collections::HashSet;
use std::sync::RwLock;

/// Shared allowlist updated on every Fresh policy-bundle apply (including TTL
/// refresh when content version is unchanged).
#[derive(Debug, Default)]
pub struct PeAllowlistCache {
    inner: RwLock<HashSet<String>>,
}

impl PeAllowlistCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the cache with the Fresh section's `spiffe_ids`.
    pub fn replace(&self, ids: impl IntoIterator<Item = String>) {
        let set: HashSet<String> = ids.into_iter().collect();
        *self.inner.write().expect("pe allowlist write") = set;
    }

    /// Clear on Invalid / VALID=0.
    pub fn clear(&self) {
        self.inner.write().expect("pe allowlist write").clear();
    }

    pub fn contains(&self, spiffe_id: &str) -> bool {
        self.inner
            .read()
            .expect("pe allowlist read")
            .contains(spiffe_id)
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("pe allowlist read").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot for revoke reconcile.
    pub fn snapshot(&self) -> HashSet<String> {
        self.inner.read().expect("pe allowlist read").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_and_contains() {
        let c = PeAllowlistCache::new();
        c.replace([
            "spiffe://neuromesh.security/ns/default/sa/a".into(),
            "spiffe://neuromesh.security/ns/default/sa/b".into(),
        ]);
        assert!(c.contains("spiffe://neuromesh.security/ns/default/sa/a"));
        assert!(!c.contains("spiffe://neuromesh.security/ns/default/sa/z"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn ttl_style_refresh_replaces_set() {
        let c = PeAllowlistCache::new();
        c.replace(["spiffe://t/ns/n/sa/old".into()]);
        // Unchanged-version TTL refresh still pushes the latest body ids.
        c.replace(["spiffe://t/ns/n/sa/new".into()]);
        assert!(!c.contains("spiffe://t/ns/n/sa/old"));
        assert!(c.contains("spiffe://t/ns/n/sa/new"));
    }

    #[test]
    fn clear_empties() {
        let c = PeAllowlistCache::new();
        c.replace(["spiffe://t/ns/n/sa/a".into()]);
        c.clear();
        assert!(c.is_empty());
    }

    #[test]
    fn snapshot_is_independent_copy() {
        let c = PeAllowlistCache::new();
        c.replace(["spiffe://t/ns/n/sa/a".into()]);
        let snap = c.snapshot();
        c.replace(["spiffe://t/ns/n/sa/b".into()]);
        assert!(snap.contains("spiffe://t/ns/n/sa/a"));
        assert!(!snap.contains("spiffe://t/ns/n/sa/b"));
        assert!(c.contains("spiffe://t/ns/n/sa/b"));
    }
}
