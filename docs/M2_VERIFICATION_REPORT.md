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

| | Before fixes | After fixes |
|---|---|---|
| Files scanned | 32 | 32 |
| Files with zero findings | 23 (72%) | **25 (78%)** |
| Total findings | 17 | **14** |
| Judged true positives | 7 | **8** |
| Judged false positives | 10 | **6** |
| **Precision** | **41%** | **57%** |

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

### 3.2 Findings we judge FALSE POSITIVES (6) — the honest half

| File | Pattern | Line | Why it is wrong |
|---|---|---|---|
| `use_pumpfun.py` | base off-by-one | 67 | `for ata_attempt in range(max_retries)` is **correct**. Flagged **three times** on one line — a duplicate-emission defect, still unfixed (see §5) |
| `use_pumpfun.py` | PS-SOL-2c | 126 | Blockhash at L79, send at L81 — refetched **immediately before** the send. The heuristic fired on adjacent lines |
| `use_pumpfun.py` | PS-SOL-2c | 202 | Blockhash at L121, send at L126 — same adjacent-line shape |
| `use_pumpfun.py` | base bug | 41 | Outer divisor is a compound expression whose parts are module constants; nothing user-controlled, nothing zero |

**The honest summary: PS-SOL-2c is the weak pattern.** It fired 5 times on real code and 2 were noise,
both from the same failure mode — a blockhash fetched on the line immediately before the send is still
counted as "intervening work", because the send call itself matches the slow-call vocabulary. Precision
on 2c: **3/5**.

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
4. **OPEN — duplicate emission.** `range(max_retries)` at `use_pumpfun.py:67` is reported **three
   times**. A de-duplication pass was added to `analyze_patterns`, but the off-by-one rule is emitted
   from a different function, so it still duplicates. **Known, unfixed, and deliberately left visible
   in the numbers above** rather than filtered out of the count.
5. **OPEN — `base:off_by_one` itself is a false positive** on `range(max_retries)`. Correct Python
   idiomatic usage. Recommend disabling this rule or narrowing it to explicit `range(n+1)` patterns.

**Stated plainly: the pre-existing base analyzer bank has a materially worse false-positive rate than
the Solana patterns added in this milestone (base 50% precision, PS-SOL 67%).** Anyone adopting
`sak-guard` should run `--strategy default` until §5 items 4 and 5 are resolved, or read base-bank
`medium` findings with suspicion.

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
- The patterns work; the surrounding base bank needs the same discipline. That is the next piece of work,
  and it is cheaper than M2 was.
