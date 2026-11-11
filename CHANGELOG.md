# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This project is pre-1.0. While the major version is `0`, the minor version carries
new rule families and engine changes, and the patch version carries corrections.
A pre-release suffix (`aN`) marks a candidate that has not yet been validated
against a broad external corpus.

## [0.2.0a1] - 2026-11-11

Second alpha. The analysis engine was replaced and the rule set roughly doubled
against `0.1.0a0` (`3895383`). Consumers upgrading from `0.1.0a0` should read
[docs/DETECTION_ENVELOPE.md](docs/DETECTION_ENVELOPE.md) before treating a passing
result as a release decision: the detection envelope is now written down, and it
is deliberately narrower than "all Solana Python code".

First release published to PyPI, via Trusted Publishing (OIDC).

### Added

- **`PS-SOL-4` rule family** — reviews the message or transaction that reaches a
  signing shape. Records whether a correctly polarized comparison is enforced on
  a completing path before signing.
- **`PS-SOL-5` rule family** — records caller-derived amounts that reach a transfer
  without an independent upper bound, and swap-shaped calls without a known
  positive minimum-output or slippage value.
- **`sak_guard/dataflow.py`** — an abstract interpreter that replaces the previous
  line-ordered provenance tracking. It merges both branches of a conditional,
  seeds `try` handlers from the entry state, iterates loops to a bounded fixpoint,
  and ends a path at `raise`/`return` so a rejecting branch contributes no fact.
- **`sak_guard/worker.py`** — an isolated analysis worker. Only the analyzer runs;
  submitted code is never executed.
- **`sak_guard/limits.py`** — centralised source-size, AST-node and analysis-step
  ceilings, plus the shared failure envelope.
- **`docs/DETECTION_ENVELOPE.md`** — the alpha detection contract. States, per rule
  family, the evidence a rule uses and what that evidence does not prove.
- **`MANIFEST.in`** and an explicit `[tool.setuptools]` package declaration, so
  built distributions contain every module.
- **stdin input** — `sak-guard -` reads Python source from standard input.
- **Distinct exit code `2`** for usage, IO, parse and incomplete-analysis errors,
  kept separate from `1` (findings at or above the threshold).
- **Non-Solana negative fixtures and boundary tests**, so general-purpose code that
  resembles a domain call shape is exercised by the suite.

### Changed

- **`PS-SOL-2` is now four named rules**: `2a` commitment/options presence, `2b`
  simulation-result gating, `2c` blockhash freshness (Medium advisory), `2d`
  missing `await` on a recognised async client operation.
- **Each file is analysed in its own process.** This isolates analysis from the
  caller but costs roughly 0.1 s of process startup per small file; 100 small
  files add about 10 s. Documented in the README with a scoped-hook example.
- **`reports[].passed` is independent of the CLI threshold.** It means "no
  High/Critical findings", and an incomplete report is always `passed: false`.
- **CI** runs Python 3.10 through 3.14, exposes `workflow_call`, asserts exact exit
  codes rather than accepting any non-zero result, and builds and smoke-tests the
  wheel outside the checkout before publication.
- **Precision on general-purpose code.** Call-shape classification now requires a
  resolved origin rather than a name substring, so ordinary identifiers that
  resemble a domain operation are no longer reported.

### Fixed

- **An internal analysis error can no longer produce a clean verdict.** Failures
  are collected and surfaced as a critical finding with exit code `2`.
- **Quadratic analysis paths** — deep expression chains, long alias chains and
  large simulation counts now scale linearly. An 8,000-term chain that previously
  exceeded ten seconds completes in about one second.
- **Self-analysis false positives** — string and comment contents are masked before
  text patterns are applied, so a rule table no longer matches its own source.
- **`finally` on normal completion** and **`break` versus loop `else`** now follow
  Python semantics when facts are carried between paths.
- **Facts are keyed by access path**, so a check on one field does not authorize a
  different field, and a store through an alias invalidates the shared object.

### Known limitations

These are properties of the current alpha, not defects scheduled for this release.
Read them before relying on a passing result.

- **Heuristic analysis.** A passing result means the configured checks completed
  without reportable evidence at the selected threshold. It does not certify a
  transaction, a program, or a deployment.
- **Scope of the envelope.** Analysis covers the call shapes, sources and sinks
  that are documented in the detection contract. Code that reaches a sink through
  a shape outside that contract is not reported. When in doubt, assume a shape is
  outside the envelope rather than inside it.
- **No cross-file or full interprocedural analysis.** Local helper summaries and
  import aliases cover specific documented forms. They do not establish arbitrary
  function contracts, and behaviour that spans modules is not followed.
- **Dynamic constructs are out of scope.** Reflection, `getattr`, dynamic imports,
  monkey-patching, custom descriptors and operators, callbacks and third-party
  wrappers can hide sources, sinks and mutation.
- **Third-party API surfaces vary.** Libraries that expose the same operation under
  a different name, or through an unannotated or unresolved receiver, may fall
  outside the current envelope. Annotating receivers and importing from the
  documented modules improves coverage.
- **Conservative false positives are expected.** Function parameters are treated as
  untrusted by default, and a dynamic value that cannot be shown to satisfy a check
  is reported. A library may need an explicit check even when its callers enforce
  one. These are reported deliberately, not as evidence that the library is
  exploitable.
- **Policy coverage is partial.** The signing and amount rules are proxies for
  authorization and economic safety. They are not complete signer, program,
  account-owner, mint-authority, unit, decimal or slippage policy.
- **Resource ceilings.** Analysis runs under a per-file time budget and size
  ceilings. A file that exceeds them exits `2` and requires investigation; it never
  becomes a passing verdict.
- **Runtime controls remain necessary.** Expected signers and fee payer, trusted
  programs and instructions, account ownership, PDA/ATA derivation, exact integer
  units, slippage and fee budgets, blockhash lifetime and final confirmation must
  still be enforced where the transaction executes.

## [0.1.0a0] - 2026-11-06

First public alpha, at `3895383` on `main`.

### Added

- Three rule families: `PS-SOL-1` key material handling, `PS-SOL-2` `solders` and
  `solana-py` misuse, `PS-SOL-3` inference-artefact provenance into a transaction
  sink.
- Security pattern banks for assembled SQL, literal credentials, `eval`/`exec`,
  `subprocess` with `shell=True`, `os.system`, unsafe `pickle`/YAML and disabled
  JWT verification.
- Optional LLM intent pass behind `--use-llm`, off by default.
- Pre-commit hook definition and a plain CLI suitable for CI.
- Test suite and fixtures covering flagged and clean cases.

[0.2.0a1]: https://github.com/Pantronux-Research/sak-guard/compare/v0.1.0-alpha...v0.2.0-alpha.1
[0.1.0a0]: https://github.com/Pantronux-Research/sak-guard/releases/tag/v0.1.0-alpha
