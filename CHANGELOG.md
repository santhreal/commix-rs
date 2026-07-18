# Changelog

All notable changes to `commix-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-07-17

### Fixed
- Clippy `-D warnings`: `#[allow(deprecated)]` on intentional `threads()` test calls.
- Crate docs: `scan`/`scan_stream` document `--version` preflight before the scan subprocess.
- Preflight errors distinguish missing binary (`NotFound`) from `--version` failure.
- `command_argv` rustdoc: flag tokens only (no program name).
- `ProcessFailed` includes captured stderr; stderr task is joined before failure.
- README Contributing: `cargo test`, `cargo clippy`, `cargo fmt --check`.
- `Technique` rustdoc documents serde wire names (`timebasedblind`, etc.).

### Changed
- Add empty `[workspace]` for nested Santh tree isolation.
- Gitignore `BACKLOG.md`.

## [0.1.0] - 2026-07-17

### Added
- Santh-standard test suite: `tests/contract.rs` (external contract), expanded
  `tests/gap.rs` and `tests/adversarial.rs`.

### Changed
- Add `command_argv()` introspection helper for contract tests; pin existing
  parser and argv gaps with Santh-standard test coverage (no parser/wiring fixes).

## [0.0.3] - 2026-07-17

### Fixed
- Emit `commix --skip-waf` (was incorrect `--ignore-waf`).
- Stop emitting nonexistent `commix --threads`; `threads()` is deprecated no-op.
- Surface stdout read/UTF-8 errors in `execution_errors` instead of treating as EOF.
- `version()` returns `ProcessFailed` when `commix --version` exits non-zero.
- Document real `--technique` letter codes (`c`/`e`/`t`/`f`).

### Changed
- MIT-only license (fleet parity with sibling bindings).
- Repository URL: `https://github.com/santhreal/commix-rs`.

## [0.0.2] - 2026-07-17

### Changed
- Categories: `api-bindings` + `web-programming` (parity with sibling bindings).

## [0.0.1] - 2026-07-17

### Added
- Initial crates.io release: type-safe asynchronous wrapper for the Commix OS
  command-injection engine.

### Fixed
- Wire `delay_secs` into `commix --delay` (previously configured but never
  passed to the subprocess). Rename from the misleading `delay_ms` name;
  `delay_ms` remains as a deprecated alias.
- Replace the hand-rolled base64 encoder with the `base64` crate.
- Preserve signal vs exit-code termination in `CommixError::ProcessFailed`
  instead of collapsing signal deaths to `-1`.
- Drop unused `async-trait` dependency.
