# asolaria-hbi-hbp

## Toolchain rule (operator, global — no exceptions)

**Rust 1.81 with clippy. Integer arithmetic and ternary (trits) only — never float.**

Pinned in `rust-toolchain.toml` (`channel = "1.81.0"`, `components = ["clippy", "rustfmt"]`),
declared as `rust-version = "1.81"` in every `Cargo.toml`, and enforced in CI by
`cargo clippy --all-targets -- -D warnings` plus a hard grep that fails the build on any
`f32`/`f64` in `src/` or `tests/`.

Any receipt in this repository naming a toolchain other than 1.81 records a run made outside
the rule. It is retained as history, not as the toolchain of record.

**The canonical HBI/HBP bridge — the machine-to-machine wire format for the Asolaria fabric and its colonies.**

This is the *hot path*. Two machines (e.g. an Asolaria node and a Simplicio node) talk to each other in **HBP tuple rows**, `json=0`, content-addressed by **sha256**, with **hash-chained receipts** — no JSON, no Node, no serialization framework in the loop. Pure Rust, **zero external crates** (pure `std` + a pure-Rust sha256), so it builds on any toolchain.

> JSON and TOON are **cold lanes** — LLM-context export/comparison only. They are deliberately *not* in this codec. The bridge is HBP/HBI.

## The contract (v1)

**Row** — one record. Pipe-delimited, tag first, ends with the hot-path marker `json=0`:

```
TAG|key=val|key=val|...|json=0
```
- Keys are bare. Values are escaped: `\` → `\\`, `|` → `\p`, newline → `\n`. Parsing splits on *unescaped* `|`; each field splits on its *first* `=` (values may contain `=`).
- `encode_row(tag, &[(k, v)])` / `parse_row(row) -> (tag, fields)`.

**Address** — content address of any slice:

```
AGT-<sha16>        where sha16 = sha256(canonical_content)[..16]   (20 chars total)
```
- `agt(content) -> "AGT-…"`. Same bytes ⇒ same address; the store dereferences it. This is the M2M reference: send the 12-token `AGT-<sha16>` instead of the whole slice.

**Index** — the `.hbi` byte-offset pointer into an `.hbp` blob:

```
IDX|pid=AGT-<sha16>|off=<u64>|len=<u64>|json=0
```
- `IdxPointer { pid, off, len }.encode()`. O(1) seek to a row without parsing the blob.

**Receipt** — append-only, tamper-evident evidence chain over rows:

```
<row>|prev_event_hash=<64hex>|event_hash=<64hex>
```
- `event_hash = sha256(row + "|prev_event_hash=" + prev)`; genesis `prev` = 64 zeros.
- `ReceiptChain::append(row) -> receipt`; `verify_chain(&[receipt]) -> bool`.
- This is where an evidence ledger belongs — as an HBP receipt, *not* a JSON one. (An `estimated → measured` claim upgrade rides as another receipt row that references the prior `event_hash`.)

## Use it

```rust
use asolaria_hbi_hbp::*;

let row = encode_row("VOICE", &[("wake", "hermes"), ("transcript", "open my run logs")]);
// -> "VOICE|wake=hermes|transcript=open my run logs|json=0"

let addr = agt(row.as_bytes());        // AGT-<sha16> — content address of the row
let mut chain = ReceiptChain::new();
let receipt = chain.append(&row);      // sealed, chained
assert!(verify_chain(&[receipt]));
```

## Why this is the bridge (measured)

Independent measurement (tiktoken cl100k) confirmed the lanes are orthogonal: HBP is a *hot* byte format — byte-parseable, sha-per-row, append-only, addressable — which is exactly the M2M property, and it is **not** trying to minimize LLM tokens (a token codec like TOON belongs only at the *LLM* boundary, a cold lane). So the fabric stores and talks HBP/HBI on the hot path at zero JSON cost, and projects to TOON/compact-JSON only when a slice must enter a model's context window. This crate is the hot-path half.

## Status

`MEASURED` — sha256 verified against standard KATs; row/address/index/receipt round-trips and tamper-detection covered by `cargo test`. `CANON` — the row/address/index/receipt shapes match Asolaria's live `.hbp/.hbi` usage. Colonies (e.g. Simplicio) implement their side against **this** contract; convergence happens at the `AGT-<sha16>` wire via GitHub.

## License

MIT OR Apache-2.0.
