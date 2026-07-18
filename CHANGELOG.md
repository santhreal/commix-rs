# Changelog

All notable changes to `commix-rs` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-07-17

### Added
- ANSI/timestamp normalization before `|_` / `[+] Payload:` matching; adversarial test and fixture with grey `|_` prefix.
- `[traffic] HTTP request` PoC accumulation (modern Commix); legacy `Request:` retained.
- `[critical]` parsed as `ParseEvent::Error`.
- Technique heuristics: `tempfile-based` before `file-based`; `dynamic code evaluation` → `EvalBased`.
- `--disable-coloring` always passed to commix subprocess.
- Proxy userinfo redaction in `redact_command_debug`; scan span logs host-only URL; stderr debug log truncated.
- CI: `clippy --all-targets`, MSRV job (`cargo +1.71.0 check`).
- Gap test pinning reserved `CommixError::Json` variant.

### Changed
- `rust-version` raised to **1.71** (matches transitive deps).
- `gap_stream_parser_is_send` comment corrected (`StreamParser` is `Send`).

## [0.1.3] - 2026-07-17

### Added
- `StreamParser` support for current Commix stdout: `[HH:MM:SS] [info] … appears to be injectable`, `|_` payload continuations, `[warning]`/`[error]` (legacy `[!]`/`[x]`/`[+] Payload:` retained).
- Technique and injection-type heuristics from injectable-line text (`classic`, `time-based`, `file-based`, `eval-based`; GET/POST/HEADER/COOKIE).
- `redact_command_debug` for spawn `debug` logs; redacts `--cookie`, `--data`, and `Authorization` headers.
- Stdout line cap (1 MB) with `execution_errors` entry; lossy stderr decode for invalid UTF-8.
- `CommixError::Validation` for missing URL and `level` outside 1..=3 before scan.
- Contract fixture `tests/fixtures/modern_transcript.txt`; validation proving tests replace `gap_validation_variant_unused`.
- CI: `cargo fmt --check` and `RUSTDOCFLAGS=-D warnings cargo doc --no-deps`.

### Changed
- Removed unused `thiserror` dependency (errors remain hand-rolled `Display`).
- README/TRUSTED_DEPS updated for parser/validation/credential-logging behaviour.

## [0.1.2] - 2026-07-17

### Added
- Contract argv coverage for `user_agent`, `proxy`, `retries`, `network_timeout`, `random_agent`, `header`/`auth_*`, `tamper_script`, `level`.
- Gap test `gap_validation_variant_unused` pinning `CommixError::Validation` as reserved/unused in `src/`.
- README documents `Technique` serde wire names (`classic`, `timebasedblind`, `evalbased`, `filebased`).

### Changed
- Integration/adversarial `is_available()` smokes replaced with nonexistent-binary oracles where applicable.
- `CommixError::Validation` rustdoc notes reserved/unused status.

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
