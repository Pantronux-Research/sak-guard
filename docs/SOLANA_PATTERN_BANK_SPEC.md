# sak-guard — Solana Pattern Bank Specification (Milestone 2)

**Status:** draft for review · **Target:** `sak_guard/strategies.py` (`_EXTRA_SECURITY_PATTERNS` + strategy
hooks) and `tests/fixtures/` · **Scope:** Python client/agent code, not on-chain Rust programs

---

## 0. Why this is the whole grant

The current engine is 1,419 lines of **generic** Python analysis — 10 patterns, zero Solana-specific logic.
`grep -E 'solders|solana|web3|anchor|transaction|keypair'` returns one hit, in a docstring. This milestone
is what makes `sak-guard` a Solana tool rather than a linter that happens to run on Solana code.

**And the gap is real.** The established Solana security tooling — Trail of Bits' `solana-lints`, the
Anchor/native program scanners — targets **Rust programs** and the on-chain account model (arbitrary CPI,
PDA seed validation, missing signer/ownership checks, sysvar spoofing). **Nothing covers the Python client
and agent layer.** That is the layer where agents now hold keys and build transactions, and it is
unscanned. Every pattern below sits there.

## 1. Design rules

1. **The tool must never execute the code it audits.** Patterns are AST- and regex-based. No imports, no
   eval, no subprocess of the target. A pattern that requires running the code is out of scope.
2. **Every pattern ships with a positive AND a negative fixture.** The negative fixture is the real
   deliverable: it is what proves the pattern is not a keyword grep.
3. **Prefer AST over regex** where the distinction is structural. Regex cannot tell
   `Pubkey(user_input)` from `Pubkey(ALLOWED[user_input])` reliably; the AST can.
4. **Every pattern emits a verdict, never silence.** Adopted from the program-scanner skill's coverage
   table: `found` / `clear` / `n/a` for every registered pattern, so a clean result is distinguishable
   from a pattern that never ran.
5. **Severity is honest.** A pattern that is a heuristic gets `medium`, not `critical`. Inflated severity
   in a security tool is a defect.

## 2. Naming

`PS-SOL-<n>` (pattern set, Solana). Stable ids — fixtures and the verification report cite them.

---

## 3. PS-SOL-1 — Unsafe key material handling

**Severity:** critical · **Engine:** AST + regex

**What it catches.** A signing key, seed, or mnemonic that reaches the code as a literal, a module-level
constant, a log line, or an unaudited file read: the ways an agent leaks the one secret that matters.

| # | Detection | Method |
|---|---|---|
| 1a | `Keypair.from_base58_string(<literal>)` or `from_seed(<literal>)` — literal key material in source | AST: `Call` whose arg is a `Constant[str/bytes]` |
| 1b | Mnemonic literal (12/24 space-separated words) passed to a derivation call | regex on string constants |
| 1c | `base58.b58decode(<literal>)` assigned to a name matching `key\|secret\|seed\|priv` | AST assign + name match |
| 1d | Secret interpolated into an f-string, `print`, or a logger call | AST: f-string/`%`/`.format` whose args include a tainted name |
| 1e | Bare 64-element `bytes`/`list[int]` literal bound to a key-like name | AST: constant sequence of length 64 |

**Positive fixture:** `tests/fixtures/vulnerable_solana_keys.py`
```python
SECRET = "4Zk8...<base58>"                       # 1a with a literal
keypair = Keypair.from_base58_string(SECRET)
print(f"using key {SECRET}")                      # 1d
words = "abandon ability able ..."                # 1b (24 words)
k2 = Keypair.from_seed(bytes(64))                 # 1e
```
**Negative fixture:** `tests/fixtures/clean_solana_keys.py`
```python
SECRET = os.environ["SOLANA_PRIVATE_KEY"]         # env, not a literal
keypair = Keypair.from_base58_string(SECRET)
logger.info("key loaded")                         # no interpolation of SECRET
raw = json.loads(Path(p).read_text())             # file read, not a literal
```
**Must NOT fire on:** `os.environ[...]`, `getpass`/`keyring` reads, `Keypair.from_json(...)` of a path.
**Honest limit:** cannot tell whether an *env var* is well-protected. 1a–1e are literal-detection only.
**Fix text:** load from a secret manager or file with tightened permissions; never log key material.

---

## 4. PS-SOL-2 — `solders` / `solana-py` misuse

Three distinct sub-patterns; each gets its own fixture pair and its own id so the report can be precise.

### PS-SOL-2a — Send without confirmation (severity: high)
`send_transaction` / `send_raw_transaction` whose result is not awaited/confirmed, or which passes no
`commitment`/`preflight_commitment`. A fire-and-forget send reports success on submission, not inclusion.
- **Detection:** AST — a send call with no `commitment` kwarg, and no reachable
  `confirm_transaction`/`get_signature_statuses` on the returned signature.
- **Positive:** bare `client.send_transaction(tx)` and discard.
- **Negative:** `client.send_transaction(tx, opts=TxOpts(commitment=Confirmed))` **and** a following
  `confirm_transaction(sig, commitment="confirmed")`.
- **Limit:** intra-function analysis only. A confirm in another module reads as a miss; documented, and
  why the pattern is `high` rather than `critical`.

### PS-SOL-2b — Simulation result ignored (severity: high)
`simulate_transaction` / `simulate_transaction_with_config` whose `.value.err` is never checked — the
classic "it simulated but we shipped anyway". Anchor raised this on the RaptorX thread as a real failure mode.
- **Detection:** AST — a `simulate_*` call whose result is bound to a name, where that name is never
  subsequently used in an `if`/`assert`/`raise` guarding `.err`.
- **Positive:** `sim = client.simulate_transaction(tx)` then straight to send.
- **Negative:** `if sim.value.err: raise RuntimeError(sim.value.err)` before send.
- **Limit:** dataflow within one function; a check in a decorator is not seen.

### PS-SOL-2c — Stale blockhash (severity: medium)
`get_latest_blockhash()` fetched, then transaction built/sent after intervening work. Blockhashes expire
(~60–90s); a stale one fails late, after partial side effects. Classic in agent loops that fetch then think.
- **Detection:** AST — `get_latest_blockhash` call and a `send_transaction` in the same function with an
  intervening loop, LLM call, network call, or `sleep`.
- **Positive:** fetch blockhash → `llm.complete(...)` → build + send.
- **Negative:** fetch blockhash immediately before build+send, or a refetch inside the retry path.
- **Limit:** temporal, so heuristic. **`medium`, and it will have false positives.** Registered anyway
  because in agent code the "fetch then think" order is the common shape, and it is the pattern most likely
  to fire on real repos.

---

## 5. PS-SOL-3 — Unsanitized LLM output into RPC or transaction construction

**Severity:** critical · **Engine:** AST taint, single-file

**What it catches.** Model output reaching `Pubkey()`, a transfer destination, an amount, or a raw RPC
call without an intervening allow-list check. This is the pattern that makes an *agent* unsafe rather than
its library usage — a hallucinated or prompt-injected recipient is a live fund-loss path, and it is the
one class no existing Solana tool looks for.

**Detection (honest about the hard part):** the destination must trace to a name assigned from an LLM-ish
source — a call on an object with `llm|model|openai|anthropic|agent|completion|chat` in its name, or a
`json.loads` of such a result — and reach a `Pubkey(...)`, transfer `to=`, or `send_transaction` argument
with no intervening membership/validation call.

**Positive fixture:** `tests/fixtures/vulnerable_solana_llm.py`
```python
plan = llm.chat(...)                       # model output
dest = json.loads(plan)["recipient"]       # untrusted
client.send_transaction(transfer(Pubkey(dest), amount))   # no allow-list
```
**Negative fixture:** `tests/fixtures/clean_solana_llm.py`
```python
dest = json.loads(llm.chat(...))["recipient"]
if dest not in ALLOWED_RECIPIENTS:          # validated before use
    raise ValueError("recipient not allowed")
client.send_transaction(transfer(Pubkey(dest), amount))
```
**Limit — state this in the README, do not hide it:** this is single-file, allow-list-shaped taint
analysis. A custom validator function, a decorator, or a value round-tripped through a database will not
be recognised, so **false negatives are expected**. It catches the naked case, which is the one that ships.

---

## 6. Fixture matrix (the acceptance criteria)

| Fixture | PS-SOL-1 | 2a | 2b | 2c | PS-SOL-3 | Required result |
|---|---|---|---|---|---|---|
| `vulnerable_solana_keys.py` | **found** | clear | clear | clear | clear | exit 1 |
| `clean_solana_keys.py` | clear | clear | clear | clear | clear | exit 0 |
| `vulnerable_solana_rpc.py` | clear | **found** | **found** | **found** | clear | exit 1 |
| `clean_solana_rpc.py` | clear | clear | clear | clear | clear | exit 0 |
| `vulnerable_solana_llm.py` | clear | clear | clear | clear | **found** | exit 1 |
| `clean_solana_llm.py` | clear | clear | clear | clear | clear | exit 0 |

The `clear` cells matter as much as the `found` ones: a pattern that fires on the clean fixtures is a
false-positive generator, and any cell that is not `clear` fails the milestone.

## 7. Verification report (published with the milestone)

Per pattern: positive caught / negative clean, plus a false-positive run over three real
`solana-agent-kit`-style example repos with the count of findings a human judged wrong. **Published with
its failures listed** — a security tool that reports only its detection rate is overstating its coverage.

## 8. Out of scope, stated plainly

- **On-chain Rust/Anchor programs.** Covered by Trail of Bits lints and existing scanners; duplicating
  them badly is worse than not doing it. Cite them instead.
- **Runtime behaviour.** Static analysis cannot see state, economics, or on-chain conditions.
- **Key custody, keyring, HSM, MPC.** We detect literals in source; we do not audit a signer service.
- **Dependency vulnerabilities.** That is `pip-audit`, not this.
