# Repository Guidelines

## Project Structure & Module Organization
- Core application code is in `src/`.
- `src/main.rs`: runtime wiring (UDP/TCP listeners, limits, timeouts).
- `src/config.rs`: config loading/validation (`CLI > env > TOML`).
- `src/dns.rs`: authoritative DNS response logic.
- `src/limits.rs`: rate and connection limiters.
- Integration tests live in `tests/` (`tests/e2e.rs`) and exercise the real binary over sockets.
- `README.md` (user-facing docs), `PRODUCTION_READINESS.md` (internet exposure checklist),
  `leaf.example.toml` (config template), `.gitlab-ci.yml` (pipeline definition).
- Container deployment assets: `Containerfile` and `.containerignore`.

## Build, Test, and Development Commands
- `cargo build` — compile debug binary.
- `cargo build --release` — compile optimized release binary.
- `cargo run -- --help` — inspect CLI flags.
- `cargo fmt --all -- --check` — verify formatting.
- `cargo check --all-targets --all-features --locked` — fast compile verification.
- `cargo clippy --all-targets --all-features --locked -- -D warnings` — enforce lint cleanliness.
- `cargo test --locked` — run unit + integration tests.
- `cargo test --all-targets --all-features --release --locked` — extended test run.
- `opal run --no-tui` — run local CI pipeline emulation.
- `podman build -t leaf:latest -f Containerfile .` — build container image.
- `podman run --rm -e LEAF_ZONE=dev.example.com -p 5300:5300/udp -p 5300:5300/tcp leaf:latest` — run in container.

## Coding Style & Naming Conventions
- Rust 2024 edition, standard `rustfmt` style (4-space indentation by formatter).
- Prefer small, focused functions and explicit error propagation (`Result`, no `unwrap` in production paths).
- Naming conventions:
- `snake_case` for functions/variables/modules.
- `CamelCase` for types/structs/enums.
- Clear config names matching env/TOML keys (e.g., `per_ip_qps_limit`).

## Testing Guidelines
- Add unit tests near logic modules (`#[cfg(test)]` in `src/*.rs`).
- Add behavior-level integration tests in `tests/` when changing runtime/network behavior.
- Test names should describe behavior (e.g., `returns_nxdomain_with_soa_authority`).
- Before opening a PR, run `fmt`, `check`, `clippy`, and both test commands.

## Commit & Pull Request Guidelines
- Follow conventional-style commit prefixes seen in history: `feat:`, `fix:`, `test:`, `ci:`, `docs:`, `chore:`.
- Keep commits scoped and meaningful (avoid mixing unrelated changes).
- Use signed + signed-off commits where required (`git commit -sS`).
- PRs should include:
- Concise summary.
- Rationale and risk notes.
- Test evidence (local command output or CI/opal result).
- Config/doc updates when behavior changes.

## Security & Configuration Tips
- Do not commit `leaf.toml` (local runtime config); use `leaf.example.toml`.
- For public deployment, follow `PRODUCTION_READINESS.md` and run as non-root with least privileges.
