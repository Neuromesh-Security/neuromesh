//! Compile-time exec env capture policy (Issue #140).
//!
//! Kernel copies at most [`crate::MAX_ENV_CAPTURE`] allowlisted `NAME=VALUE`
//! slots (same 8×32 verifier-safe pattern as argv). Non-allowlisted names are
//! omitted entirely — not name-only redacted. Userspace prefix-redacts a small
//! set of high-signal secret shapes on allowlisted *values* before SIEM/OTel.

use crate::{MAX_ENV_CAPTURE, MAX_ENV_LEN, MAX_ENV_SCAN, MAX_ENV_STR_LEN};

/// Exact env *names* whose values may be copied into `ExecEvent` (Issue #140).
///
/// Technique citations:
/// - `LD_PRELOAD` / `LD_AUDIT` / `LD_LIBRARY_PATH`: T1574.006 / T1574.007
///   (dynamic linker / ELF search hijack)
/// - `PATH`: T1036.003 / T1059.004 (PATH hijack; attacker dir first)
/// - `NODE_OPTIONS`: T1059 (`--require` preload)
/// - `PYTHONPATH`: T1059.006 / T1574 (module search hijack)
/// - `BASH_ENV` / `PROMPT_COMMAND`: T1546.004 (shell config / prompt hook)
/// - `SSLKEYLOGFILE`: adjacent T1557 (TLS client keys written to a file)
pub const ENV_VALUE_ALLOWLIST: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "BASH_ENV",
    "PROMPT_COMMAND",
    "SSLKEYLOGFILE",
];

/// Suffixes that must never appear on an allowlisted name (CI guard, Issue #140).
pub const ENV_FORBIDDEN_NAME_SUFFIXES: &[&str] = &[
    "_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIAL",
    "_PRIVATE",
];

/// High-signal value prefixes redacted in userspace before logs/SIEM.
pub const ENV_VALUE_REDACT_PREFIXES: &[&str] = &["eyJ", "AKIA", "-----BEGIN"];

/// Replacement written over a redacted value (fits in a 32-byte slot with a name).
pub const ENV_VALUE_REDACTED: &str = "REDACTED";

/// Truncation / scan metadata matching kernel `env_flags` / counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnvCaptureMeta {
    pub slots: u16,
    pub ptr_count: u16,
    pub trunc_mask: u8,
    pub count_truncated: bool,
    pub slots_full: bool,
    pub probe_fault: bool,
}

/// True when `name` looks like a credential identifier (CI must reject these
/// on [`ENV_VALUE_ALLOWLIST`]).
pub fn env_name_has_forbidden_suffix(name: &str) -> bool {
    let upper = name.as_bytes();
    for suf in ENV_FORBIDDEN_NAME_SUFFIXES {
        let sb = suf.as_bytes();
        if upper.len() >= sb.len() && eq_ignore_ascii_case(&upper[upper.len() - sb.len()..], sb) {
            return true;
        }
    }
    false
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.to_ascii_uppercase() == y.to_ascii_uppercase())
}

/// True when `NAME` (no `=`) is on the compile-time value allowlist.
pub fn env_name_is_allowlisted(name: &str) -> bool {
    ENV_VALUE_ALLOWLIST.iter().any(|n| *n == name)
}

/// `NAME=VALUE` (or truncated) is allowlisted iff the name before `=` matches.
pub fn env_string_is_allowlisted(entry: &str) -> bool {
    let name = match entry.split_once('=') {
        Some((n, _)) => n,
        None => entry,
    };
    env_name_is_allowlisted(name)
}

/// Redact the value portion of `NAME=VALUE` when it matches a secret prefix.
/// Returns whether redaction occurred.
pub fn redact_env_slot(slot: &mut [u8]) -> bool {
    let nul = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
    let text = match core::str::from_utf8(&slot[..nul]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Some((name, value)) = text.split_once('=') else {
        return false;
    };
    if !value_needs_redact(value) {
        return false;
    }
    let mut out = [0u8; MAX_ENV_STR_LEN];
    let prefix = name.as_bytes();
    let mut i = 0;
    while i < prefix.len() && i + 1 < MAX_ENV_STR_LEN {
        out[i] = prefix[i];
        i += 1;
    }
    if i >= MAX_ENV_STR_LEN {
        let n = slot.len().min(MAX_ENV_STR_LEN);
        slot[..n].copy_from_slice(&out[..n]);
        return true;
    }
    out[i] = b'=';
    i += 1;
    for &b in ENV_VALUE_REDACTED.as_bytes() {
        if i >= MAX_ENV_STR_LEN {
            break;
        }
        out[i] = b;
        i += 1;
    }
    let n = slot.len().min(MAX_ENV_STR_LEN);
    slot[..n].copy_from_slice(&out[..n]);
    true
}

fn value_needs_redact(value: &str) -> bool {
    ENV_VALUE_REDACT_PREFIXES
        .iter()
        .any(|p| value.starts_with(p))
}

fn allowlist_bit(name: &str) -> u16 {
    for (i, n) in ENV_VALUE_ALLOWLIST.iter().enumerate() {
        if *n == name {
            return 1u16 << i;
        }
    }
    0
}

/// Copy allowlisted env strings into fixed 8×32 slots (userspace double of BPF).
pub fn fill_env_slots(envp: &[&str]) -> ([u8; MAX_ENV_LEN], EnvCaptureMeta) {
    let mut buf = [0u8; MAX_ENV_LEN];
    let mut meta = EnvCaptureMeta::default();
    let mut seen = 0u16;
    let scan = envp.len().min(MAX_ENV_SCAN);
    meta.ptr_count = scan as u16;
    if envp.len() > MAX_ENV_SCAN {
        meta.count_truncated = true;
    }

    for entry in envp.iter().take(scan) {
        let name = match entry.split_once('=') {
            Some((n, _)) => n,
            None => *entry,
        };
        if !env_name_is_allowlisted(name) {
            continue;
        }
        let bit = allowlist_bit(name);
        if bit != 0 && (seen & bit) != 0 {
            continue;
        }
        if meta.slots as usize >= MAX_ENV_CAPTURE {
            meta.slots_full = true;
            continue;
        }
        let i = meta.slots as usize;
        let start = i * MAX_ENV_STR_LEN;
        let bytes = entry.as_bytes();
        let n = bytes.len().min(MAX_ENV_STR_LEN);
        buf[start..start + n].copy_from_slice(&bytes[..n]);
        if bytes.len() >= MAX_ENV_STR_LEN {
            meta.trunc_mask |= 1u8 << i;
        }
        seen |= bit;
        meta.slots += 1;
    }
    (buf, meta)
}

/// Apply [`redact_env_slot`] across filled slots. Returns true if any slot redacted.
pub fn redact_env_slots(env: &mut [u8], env_len: u16) -> bool {
    let slots = (env_len as usize).min(MAX_ENV_CAPTURE);
    let mut any = false;
    for i in 0..slots {
        let start = i * MAX_ENV_STR_LEN;
        let end = (start + MAX_ENV_STR_LEN).min(env.len());
        if start >= end {
            break;
        }
        if redact_env_slot(&mut env[start..end]) {
            any = true;
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_justified_names_only() {
        assert!(env_string_is_allowlisted("LD_PRELOAD=/tmp/x.so"));
        assert!(env_string_is_allowlisted("PATH=/usr/bin"));
        assert!(env_string_is_allowlisted("PYTHONPATH=/opt/evil"));
        assert!(!env_string_is_allowlisted("AWS_SECRET_ACCESS_KEY=wJalr"));
        assert!(!env_string_is_allowlisted("DB_PASSWORD=secret"));
        assert!(!env_string_is_allowlisted(
            "KUBERNETES_SERVICE_HOST=10.0.0.1"
        ));
        assert!(
            !env_string_is_allowlisted("PATH_EXTRA=/tmp"),
            "PATH= is exact name, not a prefix of other names"
        );
        assert!(!env_string_is_allowlisted("PYTHONPATH_HOME=/x"));
    }

    #[test]
    fn non_allowlisted_are_omitted_not_name_redacted() {
        let (buf, meta) = fill_env_slots(&[
            "HOME=/root",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
            "LD_PRELOAD=/tmp/x.so",
            "KUBERNETES_SERVICE_HOST=10.0.0.1",
        ]);
        assert_eq!(meta.slots, 1);
        let nul = buf[..MAX_ENV_STR_LEN]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_ENV_STR_LEN);
        let slot = core::str::from_utf8(&buf[..nul]).unwrap();
        assert_eq!(slot, "LD_PRELOAD=/tmp/x.so");
        for chunk in buf.chunks(MAX_ENV_STR_LEN) {
            let s = core::str::from_utf8(chunk).unwrap_or("");
            assert!(!s.contains("AWS_SECRET"));
            assert!(!s.contains("KUBERNETES"));
            assert!(!s.contains("HOME="));
        }
    }

    #[test]
    fn prefix_redact_eyj_akia_begin() {
        let cases = [
            ("LD_PRELOAD=eyJhbGciOiJIUzI1NiJ9xxxx", true),
            ("PATH=AKIAIOSFODNN7EXAMPLE", true),
            ("NODE_OPTIONS=-----BEGIN RSA PRIVATE", true),
            ("LD_PRELOAD=/tmp/evil.so", false),
            ("PATH=/usr/bin:/bin", false),
        ];
        for (entry, want) in cases {
            let mut slot = [0u8; MAX_ENV_STR_LEN];
            let n = entry.as_bytes().len().min(MAX_ENV_STR_LEN);
            slot[..n].copy_from_slice(&entry.as_bytes()[..n]);
            let got = redact_env_slot(&mut slot);
            assert_eq!(got, want, "{entry}");
            let s = core::str::from_utf8(&slot).unwrap();
            if want {
                assert!(s.contains("REDACTED"), "{s:?}");
                assert!(!s.contains("eyJhbG"));
                assert!(!s.contains("AKIAIOSF"));
                assert!(!s.contains("BEGIN RSA"));
            } else {
                let t = s.trim_end_matches('\0');
                assert_eq!(t, entry);
            }
        }
    }

    #[test]
    fn ci_secret_suffix_guard_rejects_bad_names_and_passes_allowlist() {
        for name in ENV_VALUE_ALLOWLIST {
            assert!(
                !env_name_has_forbidden_suffix(name),
                "allowlist entry {name} matches a forbidden secret suffix — refuse merge"
            );
        }
        assert!(
            env_name_has_forbidden_suffix("AWS_SECRET_ACCESS_KEY"),
            "guard must reject a synthetic bad entry, not only scan the live list"
        );
        assert!(env_name_has_forbidden_suffix("DB_PASSWORD"));
        assert!(env_name_has_forbidden_suffix("API_TOKEN"));
        assert!(env_name_has_forbidden_suffix("tls_private"));
        assert!(!env_name_has_forbidden_suffix("LD_PRELOAD"));
        assert!(!env_name_has_forbidden_suffix("PATH"));
        assert!(!env_name_has_forbidden_suffix("SSLKEYLOGFILE"));
    }

    #[test]
    fn truncation_and_scan_budget() {
        let mut envp: [&str; 37] = [""; 37];
        for slot in envp.iter_mut().take(MAX_ENV_SCAN + 4) {
            *slot = "UNRELATED=x";
        }
        envp[MAX_ENV_SCAN + 3] = "LD_PRELOAD=/tmp/x.so";
        let (_buf, meta) = fill_env_slots(&envp);
        assert!(meta.count_truncated);
        assert_eq!(
            meta.slots, 0,
            "allowlisted var past scan cap must not be copied"
        );

        let long = "PATH=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(long.len() > MAX_ENV_STR_LEN);
        let (buf, meta) = fill_env_slots(&[long]);
        assert_eq!(meta.slots, 1);
        assert_ne!(meta.trunc_mask & 1, 0);
        assert_eq!(&buf[..5], b"PATH=");

        let extra = [
            "LD_PRELOAD=/a",
            "LD_AUDIT=/b",
            "LD_LIBRARY_PATH=/c",
            "PATH=/d",
            "NODE_OPTIONS=--require /e",
            "PYTHONPATH=/f",
            "BASH_ENV=/g",
            "PROMPT_COMMAND=id",
            "SSLKEYLOGFILE=/h",
        ];
        let (_buf, meta) = fill_env_slots(&extra);
        assert_eq!(meta.slots as usize, MAX_ENV_CAPTURE);
        assert!(meta.slots_full);
    }
}
