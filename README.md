# commix-rs

![status: alpha](https://img.shields.io/badge/status-alpha-orange)

## What it does

`commix-rs` is an asynchronous, type-safe Rust wrapper for [`commix`](https://github.com/commixproject/commix), the OS Command Injection Exploiter. It provides a builder-pattern API that constructs and drives `commix` as a subprocess, streams structured findings back over a Tokio channel or as a collected `CommixResult`, and handles process lifecycle, stderr capture, and timeout enforcement - all without any manual CLI output parsing in user code.

Key capabilities:

- Builder API covers commix scan flags: URL, method, data, cookie, user-agent, proxy, level, technique, tamper scripts, retries, timeouts, prefix/suffix, offline mode, and WAF bypass (`ignore_waf` → `commix --skip-waf`).
- Real-time streaming via `scan_stream(mpsc::Sender<CommixFinding>)` so findings arrive as they are discovered.
- Structured output types (`CommixFinding`, `CommixResult`, `Confidence`, `Technique`) with full `serde` support for downstream JSON pipelines.
- `Technique` JSON wire names (via `#[serde(rename_all = "lowercase")]`): `classic`, `timebasedblind`, `evalbased`, `filebased`. Rust variants are `Classic`, `TimeBasedBlind`, `EvalBased`, `FileBased`.
- Basic-auth and bearer-token helpers that build the `Authorization` header (basic auth via the `base64` crate).
- Stderr capped at 64 KB; stdout lines capped at 1 MB (oversize lines recorded in `execution_errors`).
- `delay_secs` maps to `commix --delay` (seconds between HTTP requests).
- `poc` on `CommixFinding` is filled from modern `[traffic] HTTP request` blocks (verbosity ≥ 2) or legacy `Request:` lines when present; otherwise it is empty.
- Subprocess argv always includes `--disable-coloring` (Commix supports the flag); parser also strips ANSI before matching `|_` / `[+] Payload:`.
- MSRV: Rust **1.71** (`rust-version` in `Cargo.toml`; CI runs `cargo +1.71.0 check`).

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
commix-rs = "0.1.4"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Run a simple scan:

```rust
use commix_rs::Commix;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = Commix::builder()
        .url("http://localhost:8080/page?id=1")
        .level(2)
        .batch(true)
        .build()
        .scan()
        .await?;

    if result.is_vulnerable() {
        println!("{}", result);
    } else {
        println!("No command injection found.");
    }
    Ok(())
}
```

Stream findings as they arrive:

```rust
use commix_rs::{Commix, CommixFinding};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let (tx, mut rx) = mpsc::channel::<CommixFinding>(64);
    let runner = Commix::builder()
        .url("http://localhost:8080/page?id=1")
        .build();

    tokio::spawn(async move {
        let _ = runner.scan_stream(tx).await;
    });

    while let Some(finding) = rx.recv().await {
        // Parser classifies technique from injectable-line keywords when present.
        println!("Found: {} via {:?}", finding.parameter, finding.technique);
    }
}
```

## When to use / When not

**Use this crate when:**

- You want to drive `commix` from a Rust orchestration pipeline without writing shell glue code.
- You need structured, machine-readable findings (JSON, downstream analysis) rather than raw terminal output.
- You want real-time finding delivery over a channel while a long scan is still running.
- You are integrating command injection scanning into the Santh security platform.

**Do not use this crate when:**

- You only need a one-off manual scan - use `commix` directly on the CLI.
- The target environment does not have `commix` installed and you cannot install it; this crate is purely a wrapper and does not embed the engine.
- You need injection-type detection for parameters without GET/POST/HEADER context in commix output (see gap tests for `Unknown` fallback).

## Compared to alternatives

| Approach | Structured output | Async streaming | Rust types | No shell |
|---|---|---|---|---|
| `commix-rs` (this crate) | yes | yes | yes | yes |
| Shell script wrapper | no | no | no | no |
| Python subprocess wrapper | partial | partial | no | no |
| Direct `std::process::Command` | no | no | yes | yes |

The primary advantage over ad-hoc subprocess code is the builder API, the `kill_on_drop` lifecycle guarantee, the stderr memory cap, and the typed finding structs with `serde` support.

## How it fits in Santh

`commix-rs` lives in `bindings/commix` and is one of several tool-binding crates in the Santh security research ecosystem. It feeds structured `CommixFinding` records into Santh's threat intelligence and orchestration pipelines alongside other detection crates. The `CommixResult` type implements `serde::Serialize`/`Deserialize` so findings can be stored, forwarded, or merged with results from other scanners.

The crate depends on `tokio` for async process I/O, `serde`/`serde_json` for serialization, `base64` for basic-auth header encoding, and `tracing` for structured logging.

## Contributing

Contributions are welcome. Before sending a patch:

1. Run `cargo test` — all tests must pass.
2. Run `cargo clippy --all-targets -- -D warnings` — no warnings.
3. Run `cargo fmt --check` — formatting must match.
4. Run `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps` — docs must build cleanly.

## License

Licensed under the [MIT License](LICENSE-MIT).
