# M2 Verification Report — Solana Pattern Bank

**Tool:** `sak-guard` v0.1.0-alpha · **Date:** 2026-11-05 · **Commit:** `280ccc5` (+ this report)
**Scope:** `PS-SOL-1`, `PS-SOL-2a/2b/2c`, `PS-SOL-3`

---

## 1. What this report is

The M2 deliverable promises a verification report **including its misses and false positives**. This is
that report. A security tool that publishes only a detection rate is overstating its coverage, and for a
tool whose purpose is finding defects, that overstatement *is* a defect.

Everything below is measured, not estimated. The corpus is **real third-party code**, not fixtures we
wrote to suit ourselves.

## 2. Baseline — the fixture matrix

Six fixtures, nine asserted cells, run under `pytest`:

| Fixture | PS-SOL-1 | PS-SOL-2 | PS-SOL-3 | Required | Actual |
|---|---|---|---|---|---|
| `vulnerable_solana_keys.py` | **found** | clear | clear | exit 1 | exit 1 ✓ |
| `clean_solana_keys.py` | clear | clear | clear | exit 0 | exit 0 ✓ |
| `vulnerable_solana_rpc.py` | clear | **found** | clear | exit 1 | exit 1 ✓ |
| `clean_solana_rpc.py` | clear | clear | clear | exit 0 | exit 0 ✓ |
| `vulnerable_solana_llm.py` | clear | clear | **found** | exit 1 | exit 1 ✓ |
| `clean_solana_llm.py` | clear | clear | clear | exit 0 | exit 0 ✓ |

**9/9 cells correct. Suite: 32 passed, exit 0.** The `clear` cells carry the weight — any non-`clear`
cell on a clean fixture is a false-positive generator. `vulnerable_solana_rpc.py` correctly fires 2a,
2b and 2c; `vulnerable_solana_keys.py` correctly fires 1a, 1b and 1d.

On non-Solana input every pattern returns **`n/a`** rather than `clear`, so a clean generic-Python file
is never mistaken for a clean Solana file.

## 3. False-positive run — real code

**Corpus:** `sendaifun/solana-agent-kit-py` @ `main` — **32 tool implementation files, 5,670 lines**,
fetched unmodified from the upstream repository. This is the exact layer the patterns target: agent
tools that hold wallets and build transactions.

| | Baseline | After FP fixes | After base-bank fixes |
|---|---|---|---|
| Files scanned | 32 | 32 | 32 |
| Files with zero findings | 23 (72%) | 25 (78%) | **25 (78%)** |
| Total findings | 17 | 14 | **11** |
| Judged true positives | 7 | 8 | **8** |
| Judged false positives | 10 | 6 | **3** |
| **Precision** | **41%** | **57%** | **73%** |

Three rounds, each one driven by what the previous run exposed rather than by a target number. The
final column is the honest capability of the tool as it stands.

### 3.1 Findings we judge CORRECT (8)

| File | Pattern | Line | Why it is real |
|---|---|---|---|
| `burn_and_close_account.py` | base bug | 83 | `process_multiple_accounts` has no return — implicitly `None` |
| `deploy_token.py` | PS-SOL-2c | 92 | Blockhash at L48, `create_account()` at L54, send at L92 — genuinely stale |
| `get_tps.py` | base bug | 124 | `num_transactions / sample_period_secs` — variable divisor, can be zero |
| `transfer.py` | PS-SOL-2a | 67 | `send_raw_transaction` with no commitment and no confirmation; returns the signature unconfirmed |
| `use_moonshot.py` | base bad practice | 48 | Bare `except:` swallows `KeyboardInterrupt`/`SystemExit` |
| `use_moonshot.py` | PS-SOL-2c | 171 | Blockhash at L95, work, send at L171 |
| `use_pumpfun.py` | base bug | 61 | `amount / token_price_sol` — variable divisor |
| `use_raydium.py` | PS-SOL-2c | 280 | Blockhash at L152, `create_with_seed()` at L225, send at L280 |

### 3.2 Findings we judge FALSE POSITIVES (3) — the honest half

| File | Pattern | Line | Why it is wrong |
|---|---|---|---|
| `use_pumpfun.py` | PS-SOL-2c | 126 | Blockhash at L79, send at L81 — refetched **immediately before** the send. The heuristic fired on adjacent lines |
| `use_pumpfun.py` | PS-SOL-2c | 202 | Blockhash at L121, send at L126 — same adjacent-line shape |
| `use_pumpfun.py` | base bug | 41 | Outer divisor is a compound expression whose parts are module constants; nothing user-controlled, nothing zero |

Three false positives were eliminated in this pass and are no longer in the counts: the duplicate
`base:off_by_one` emission (3× on one line), and `base:off_by_one` firing at all on `range(max_retries)`.

**PS-SOL-2c remains the weak pattern: 3/5 precision.** Both misses share one failure mode — a blockhash
fetched on the line immediately before the send still counts as "intervening work", because the send call
itself matches the slow-call vocabulary. It stays `medium` for exactly this reason, and it is left in the
counts rather than suppressed.

**As of this pass the pre-existing base bank (4/5, 80%) now outperforms PS-SOL-2c (3/5, 60%).** That is
the correct state to report: the base bank was worse, the base bank was fixed, and the pattern with the
known temporal weakness is now the weakest link.

Severity was set to `medium` for exactly this reason. It is registered rather than removed because the
`deploy_token` and `use_raydium` hits are real and costly, but **a `medium` 2c finding should be read as
"check this order", not as a defect.**

## 4. Misses — what we know we do not catch

| Limitation | Consequence |
|---|---|
| **PS-SOL-3 is single-file taint, allow-list-shaped** | A custom validator function, a decorator, or a value round-tripped through a database is **not** recognised. A naked `Pubkey(llm_output)` is caught; a validated-looking one that isn't validated will be missed |
| **PS-SOL-2a/2b are intra-function** | A `confirm_transaction` in another module reads as a miss; a simulation check inside a decorator is not seen |
| **PS-SOL-2c is temporal** | Order-based, so both false positives (§3.2) *and* false negatives: a genuinely stale blockhash reused across functions may not be linked |
| **PS-SOL-1 detects literals only** | Whether an env var or a keyring entry is *well protected* is not assessed. We find keys in source, not exposed keys in custody |
| **No on-chain analysis at all** | Rust/Anchor program bugs (arbitrary CPI, PDA derivation, missing signer checks) are out of scope — covered by Trail of Bits `solana-lints` and the program scanners |

## 5. Defects this run exposed in our own tool

The false-positive run found more bugs in `sak-guard` than it found in the corpus. All are reported:

1. **FIXED — `/` inside a string literal read as division.** The rule scanned raw source lines, so
   `Client("https://api.mainnet-beta.solana.com")` was reported as "division by variable without
   zero-check" (`/api` matched). Now gated on `ast.BinOp(ast.Div)`. Five regression tests pin it.
2. **FIXED — `logger.info(f"{kp.pubkey()}")` flagged as a key leak.** A public key is meant to be
   printed. PS-SOL-1d now skips `.pubkey()`/`.public_key()`/`.to_string()` interpolations.
3. **FIXED — division by a module constant flagged.** `x / LAMPORTS_PER_SOL` is a fixed value, never
   zero. Divisors that are literals or `UPPER_CASE` names are now ignored. This removed 3 of the 5
   division findings.
4. **FIXED — duplicate emission.** The de-duplication pass had been placed inside `analyze_intent`,
   so findings emitted by `analyze_patterns` — including `base:off_by_one` — were never deduplicated.
   Moved to `analyze_code`, the single point where every channel's issues merge. **Dedupe where the
   streams meet, not inside one of them.**
5. **FIXED — `base:off_by_one` narrowed.** The rule flagged every `range(<name>)` with no evidence of
   an actual off-by-one, which is idiomatic Python and produced 3 of the 6 false positives on its own.
   It now fires only on shapes that carry a signal *in the source*: an adjusted bound
   (`range(len(x) + 1)`, `range(n+1)`) or a `<=` comparison against the loop subject inside a `range()`
   loop. Six behaviour cases pin it, including two that must stay silent.

Both were found by running the tool on real code, not by reading it. The `<=` check also had its logic
inverted on the first attempt — it looked for the loop variable among the comparison's *comparators*,
when in `i <= n` the subject is the *left* operand. It matched nothing, and only the behaviour cases
showed it.

## 6. Reproducing this

```bash
git clone https://github.com/sendaifun/solana-agent-kit-py /tmp/sak-py
python -m pip install -e ".[dev]"
python -m pytest -v tests/                     # 32 passed
sak-guard /tmp/sak-py/solana_agent_kit/tools/  # the run in §3
```

The corpus is third-party code under its own licence and is **not** vendored into this repository.

## 7. What this means for the milestone

- **PS-SOL-1 and PS-SOL-3: no false positives on 5,670 lines of real agent code.** The two patterns that
  do not exist anywhere else in the Solana tooling landscape are also the two that stayed quiet.
- **PS-SOL-2a: 1/1 correct.** **PS-SOL-2c: 3/5** — honest, and labelled `medium` to match.
- **Overall precision on real third-party code: 73%** (8 of 11 findings judged correct), up from 41%
  at first run. Every point of that came from fixing defects the tool found in itself.
- The remaining three false positives are all `medium`: two are PS-SOL-2c's known temporal weakness and
  one is a compound-expression divisor in the base bank. **No `critical` or `high` finding in this corpus
  was judged wrong.**

---

## 8. Release-readiness UAT (v0.1.0-alpha)

End-to-end acceptance run over the packaged artifact, not the working tree. Four defects were found and
fixed; the third is the one that mattered.

| Area | Check | Result |
|---|---|---|
| CLI | `--fail-on` at every level, file and stdin | correct |
| CLI | stdin contract (`-`, not a `--stdin` flag) | correct |
| CLI | malformed / empty / binary / comment-only Python | no traceback, sane exit |
| CLI | `--fail-on never` on vulnerable input | exit 0 |
| Engine | dedup holds across a multi-file scan | 0 duplicates |
| Engine | `range(max_retries)` no longer flags `base:off_by_one` | 0 findings |
| Tests | `pytest` | **36 passed** (4 added by this UAT) |
| Packaging | `python -m build` + `twine check` | **PASSED** both artifacts |
| Packaging | wheel contents | 6 modules + `py.typed`; no caches, no tests |
| Packaging | `License-Expression: Apache-2.0`, no `License ::` classifier | correct |
| CI | `publish.yml` trigger `release: [published]` (+ `workflow_dispatch`) | correct |
| CI | `id-token: write` scoped to the publish job only | correct |
| CI | `ci.yml` matrix 3.10–3.13 matches `requires-python >=3.10` | correct |
| Downstream | pre-commit installs the remote repo, fires on a vulnerable file | exit 1 |
| Downstream | pre-commit on a clean file | exit 0, "Passed" |
| Downstream | staged-only semantics | unstaged 0, staged 1 |

### Defects found and fixed by this run

1. **A nonexistent path exited 0 — success on a repo never read.** `iter_targets()` printed
   `no such path` to stderr, yielded nothing, and the run ended with no findings. Since the exit code is
   computed from findings (`worst` stays 99 when there are none), it returned **0**. The README documents
   *"2 usage or IO error"*, so this was a published contract violation, and the worst kind for a
   pre-commit hook: a typo in a path silently passes. Now raises `BadPath` → exit 2.
2. **`--help` advertised the wrong program name.** `prog="sec-audit"` — the internal CLI this was
   decoupled from — so `sak-guard --help` printed `usage: sec-audit`. Now `PROG = "sak-guard"`.
3. **The module docstring was stale internal text**, describing `sec-audit` and its ALM origin in a
   public repository. Rewritten for the actual tool and scope.
4. **The dev venv was empty** (no `build`, `twine`, or `pytest`), so a venv-based build failed with
   `No module named build`. Environment defect, not a repo defect — the build is verified against the
   system interpreter, and neither the venv nor `dist/` is tracked.

Four regression tests were added so each CLI contract is pinned: exit 2 on a bad path, the program name,
the `-` stdin contract, and no traceback on malformed source.

**No false-positive regression:** re-scanning the 32-file corpus after these fixes still yields **11
findings**, so the §3 numbers stand unchanged.
