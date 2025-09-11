# Repository Guidelines

## Project Structure & Module Organization
- Root crate: `mdconfcli` (Rust 2024 edition).
- Source lives in `src/`; entrypoint is `src/main.rs`.
- Add modules as `src/<module>.rs` and declare with `mod <module>;`, or use submodules under `src/<module>/mod.rs`.
- Multiple binaries go in `src/bin/<name>.rs`.
- Tests: unit tests live next to code; integration tests in `tests/`.
- Public APIs should have `///` rustdoc with small examples.

## Build, Test, and Development Commands
- Build: `cargo build` (optimized: `cargo build --release`).
- Run: `cargo run -- --help` (forward args after `--`).
- Lint: `cargo clippy --all-targets -- -D warnings` (treat warnings as errors).
- Format: `cargo fmt --all`.
- Test: `cargo test` (runs unit + integration tests).

### CLI Usage Examples
- Read a page: `cargo run -- read 123456 --format text`
- Alias: `cargo run -- get 123456 --format view` (same as `read`).

## Coding Style & Naming Conventions
- Use `rustfmt` defaults (4-space indent; toolchain line width).
- Naming: `snake_case` (functions/modules), `CamelCase` (types/traits), `SCREAMING_SNAKE_CASE` (consts).
- Error handling: prefer `Result<T, E>`; consider `thiserror` if errors grow; avoid `unwrap()` in non-test code.

## Testing Guidelines
- Unit tests: add `#[cfg(test)] mod tests { ... }` in the file under test.
- Integration tests: add files under `tests/`; each is a separate crate using public APIs.
- Test names describe behavior (e.g., `parses_basic_block()`); keep tests deterministic (no network/time flakiness).
- Run all checks locally: `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test`.

## Commit & Pull Request Guidelines
- Commits follow Conventional Commits (e.g., `feat: add parser`, `fix: handle empty input`); keep changes focused and reference issues with `#<id>`.
- PRs include a clear description, rationale, linked issues, and sample CLI output when relevant. Update docs and tests with behavior changes.

## Agent-Specific Notes
- This file governs the entire repo. If a nested `AGENTS.md` exists, it takes precedence for its subtree.
- For any file you modify, follow these guidelines and prefer minimal, targeted changes. Do not fix unrelated issues in the same PR.
