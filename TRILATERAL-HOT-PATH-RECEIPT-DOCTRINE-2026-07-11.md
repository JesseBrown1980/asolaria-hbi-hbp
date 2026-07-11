# Trilateral hot-path receipt doctrine — HBP/HBI, 2026-07-11

Canonical doctrine:
[`HYPER-BECHS--the-third-set/TRILATERAL-REALITY-EVIDENCE-DOCTRINE-2026-07-11.md`](https://github.com/JesseBrown1980/HYPER-BECHS--the-third-set/blob/main/TRILATERAL-REALITY-EVIDENCE-DOCTRINE-2026-07-11.md)

## HBP is the evidence wire

A trilateral result should be transportable as machine-readable evidence rather than only prose.
Where safe, a verification receipt should include:

```text
claim_id
repository and immutable commit
seat/vantage
host or device PID when publishable
toolchain/runtime
input or snapshot digest
command/test surface
passed/failed/skipped counts
result scope
prior receipt hash
current event hash
authority/fire state
json=0
```

Private keys, corpus bodies, PII, and secret routes remain references or redacted carve-outs.

## Address boundary

`AGT-<sha16>` is a content address. It gives exact Path-1 recall only when an authorized receiver
retains the matching body and rehashes it successfully. It is not a standalone encoding of absent
bytes.

Path 2 is a separate companion mechanism: jointly sufficient CRT shadows can recover a bounded body
without a retained original. HBP/HBI can carry the shadow metadata, capacity ledger, selections, and
watcher receipts; the address and residue mechanisms must not be conflated.

## Trilateral receipt chain

```text
Acer receipt
-> Liris independent receipt referencing Acer event hash
-> third-seat receipt referencing the tested commit/input
-> CI receipt referencing the immutable head
```

The chain need not claim all seats saw the same private body. It must say what each seat actually
executed or could not see.

## Status transitions

An estimate or operator-reported measurement is never silently overwritten. Append a new receipt:

```text
OPERATOR_REPORTED_MEASURED
-> MEASURED_THIRD_SEAT
-> MEASURED_CI
```

with antecedents. Stale prose becomes `SUPERSEDED`, not deleted from history.

## No-deflate / no-inflate

- a compact receipt is not “only a hash” when it names a retained body and carries provenance;
- a receipt proves its declared event, not every live subsystem;
- HBP hot-path efficiency is not automatically LLM-token compression;
- `json=0` does not imply zero information or zero storage;
- a valid chain does not grant execution authority.

## Merge rule

Merge codec fixes, KATs, round-trip tests, receipt schemas, and additive evidence rows when clean.
Hold incompatible wire changes, chain rewrites, private body publication, secret material, authority
changes, or claims whose referenced input/commit cannot be recovered.
