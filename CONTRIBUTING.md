# Contributing to Neuromesh

## Pre-commit hook (required)

Every commit must pass the same local gates Production CI enforces for Rust
formatting, Clippy (`-D warnings`), and shell script linting. A **fail-closed**
pre-commit hook in `scripts/hooks/pre-commit` runs automatically before each
commit when relevant files are staged.

| Staged files | Checks run |
|--------------|------------|
| Any `*.rs` | `cargo fmt --all -- --check`, then `cargo clippy --workspace --all-targets -- -D warnings` |
| Any `*.sh` | `shellcheck` on each staged script |

If a required tool is missing when matching files are staged, the hook **exits
non-zero and blocks the commit**. There is no silent skip for incomplete
environments.

### One-time install

From the repository root:

```bash
git config core.hooksPath scripts/hooks
```

**Why `core.hooksPath` (not a symlink into `.git/hooks/`)?**

- Hooks live in version control under `scripts/hooks/` — updates ship with
  `git pull`, no manual re-copy.
- One command per clone; no platform-specific symlink quirks (notably on
  Windows).
- `.git/hooks/` stays untouched; `core.hooksPath` is the Git-recommended way
  to point at a shared hooks directory.

Verify:

```bash
git config --get core.hooksPath   # should print: scripts/hooks
```

### Required toolchain

| Tool | Install |
|------|---------|
| `cargo`, `rustfmt`, `clippy` | [rustup](https://rustup.rs) + `rustup component add rustfmt clippy` |
| Native build deps for Clippy | Same as CI Lint: `clang`, `llvm`, `cmake`, `libbpf-dev`, etc. (see `.github/workflows/ci.yml` Lint job) |
| `shellcheck` | OS package manager (`apt install shellcheck`, `brew install shellcheck`, …) |

Clippy compiles workspace targets; without Linux BPF/build headers the hook
will fail closed — same as CI.

### Fixing common failures

```bash
# Formatting drift
cargo fmt --all

# Inspect Clippy output (fix warnings, do not #[allow] to bypass)
cargo clippy --workspace --all-targets -- -D warnings

# Shell issues
shellcheck path/to/script.sh
```

### `--no-verify`

`git commit --no-verify` bypasses hooks. Do **not** use it for code destined
for `main`; CI will still fail and unverified commits violate project policy.

## CI parity

Pre-commit mirrors the Production CI **Lint (work)** job (`.github/workflows/ci.yml`).
Push to `main` additionally runs Build Docker publish/sign paths that only
execute on `push` — the hook does not replace full CI.
