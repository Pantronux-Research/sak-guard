# Alpha detection contract

This contract describes the implemented release candidate, not complete Python or
Solana verification. A passing result means the configured checks completed without
reportable evidence at the selected threshold. It does not certify a transaction.

## Rule families

| Family | Evidence the rule uses | What the evidence does not prove |
|---|---|---|
| PS-SOL-1 | Literal material at private loaders; import origins, aliases and local wrapper returns; mnemonic-shaped literals in mnemonic contexts; key-shaped names in f-strings | Every secret source, secret format, logging API or opaque third-party wrapper |
| PS-SOL-2a | A submission has a non-disabled commitment/options value or its own signature is confirmed on completing paths | The RPC actually reached consensus, options have the intended runtime type, or every confirmation response is successful |
| PS-SOL-2b | The simulation's own result gates an abort before submission, on every completing path | The simulation used the final message, RPC state is fresh, or submission will succeed |
| PS-SOL-2c | Latest blockhash fetch, possible slow work and send within one scope | The actual blockhash reaching a transaction, elapsed time or block height; this is a Medium advisory |
| PS-SOL-2d | A recognized AsyncClient operation lacks an await on a completing path | Arbitrary scheduling frameworks, returned awaitables delegated across helpers or untyped clients |
| PS-SOL-3 | Recognized model calls flow through expressions, aliases and fields into recognized address/transaction sinks without an enforcing allow-list | Model APIs with unrelated names, arbitrary validators, complete schemas, cross-file flows or dependency implementations |
| PS-SOL-4 | Externally supplied/decoded messages reach known signing shapes without an enforcing comparison on a message field | Complete authorization: a payer or account-key comparison alone cannot establish instruction, program, account-owner, signer-set or fee policy |
| PS-SOL-5 | Caller/input-derived amounts lack an independent upper bound at a transfer; resolved Solana swap APIs lack a known positive explicit minimum-output/slippage value | Opaque swap wrappers, SDK defaults, units, decimals, rounding, economic suitability, fee limits, pool/program trust or runtime account ownership |

General security checks cover assembled SQL queries, literal credentials,
eval/exec, subprocess shell calls, os.system, unsafe pickle/YAML and disabled JWT
verification. These are API and syntax patterns, not proof of exploitability.
Parameterized SQL and SafeLoader calls have safe regression neighbours.

## Provenance and enforcement

The interpreter joins paths conservatively. Facts belong to values at program
points; one checked field cannot clear another. Dynamic indices do not establish
an exact-field clearance. Stores invalidate affected facts through possible
aliases. Rebinding a name does not mutate the old object.

An upper bound must come from an independent trusted limit. The result of
`min(amount, MAX)` must actually reach the transfer. A discarded cap, a lower-bound
check, a self-comparison or a caller-supplied unbounded maximum is insufficient.

Swap checks require a resolved origin in `jupiter_python_sdk`, `solana_agent_kit`
or `solana_agentkit`, plus an exact operation name: `swap`, `swap_exact`,
`swapExact`, `swap_exact_in`, `swap_exact_out` or `jupiter_swap`. Imported callable
aliases, instance identities and receiver annotations supply context; identifiers
such as `route`, `re_route`, `swapcase` and `_py_swap_current_task` do not. A Solana
import elsewhere in a file does not classify an unrelated call as a swap.

An unresolved application wrapper named `swap` is outside this selector's
coverage. This is a deliberate precision boundary. On recognized calls the rule
requires explicit bound evidence; it does not infer SDK defaults. Consequently a
finding means the explicit-bound policy is unmet, not proof that the runtime SDK
has no slippage protection. SDK defaults can make a reported call safe.

Message review requires a correctly polarized comparison and rejection. Recognized
local review helpers have a deliberately narrow body-derived summary; an ignored
predicate, a helper that returns on failure, rebinding a helper, or an unawaited
async helper establishes no fact. Arbitrary function names such as `validate`
do not establish a validation contract by spelling alone.

Review belongs to the exact message access path. Reviewing one batch element
does not review the batch, and rebinding an earlier argument while evaluating a
later argument does not transfer the helper's review to the new object.

Comprehensions retain possible outer writes and shared-object mutations. Lazy
generators conservatively include recognized sources that can later rebind a free
variable in the same scope. This is not a model of arbitrary consumption order,
callbacks or asynchronous scheduling; conservative reports can occur when a
generator is consumed before the possible rebind or is never consumed.

Function parameters are conservatively untrusted for signing and amount checks.
The analyzer does not prove that every external caller is trusted. A library may
therefore need an explicit cap/check even if its callers enforce one. A dynamic
swap limit that cannot be shown positive is reported. Unknown key-loading wrappers
can also require manual review. These conservative false positives are expected
alpha behaviour, not evidence that the library is exploitable.

## Boundaries requiring another control

There is no full interprocedural, cross-file or Python object-model analysis.
Opaque helpers, callbacks, reflection, `getattr`, dynamic imports, monkey-patching,
custom descriptors/operators and RPC wrappers can hide sources, sinks or mutation.
Local helper summaries and import aliases cover specific documented shapes; they
do not establish arbitrary function contracts. API names also remain heuristic
outside imports the analyzer can resolve.

Runtime controls must enforce expected signers and fee payer, trusted programs and
instructions, account ownership/mint/authority, PDA/ATA derivation, exact integer
units, slippage and fee budgets, blockhash lifetime and final confirmation. On-chain
checks remain necessary for signer verification, account authorization and CPI.
PS-SOL-4/5 provide partial client-side proxies for these original coverage gaps.

Mnemonic detection uses context and standard phrase lengths, not a bundled BIP39
word-list/checksum validator. Secret formatting uses name/context evidence and is
not comprehensive leak analysis. Return/type/loop diagnostics are conservative
heuristics; stubs, loop progress and text-based intent mismatches are advisory.
The `confidence` field is a heuristic score, not a calibrated probability or recall.

## Failure and resource contract

- CLI: exit 0 for completed reports below threshold, 1 for completed findings at or
  above threshold, and 2 for IO, usage, parse or incomplete-analysis failures.
- `--fail-on never` is explicit report-only mode for findings. It still returns 2
  for incomplete analysis. `reports[].passed` independently reflects High/Critical
  findings and is always false on a scan error.
- Each file is read with a 4 MiB byte cap before decoding. Invalid UTF-8 is an IO
  error. Public analysis APIs also enforce the source and 200,000-node AST limits.
- Each interpreter has a 500,000-step work budget and at most 128 loop passes.
  Exhaustion is a critical analysis error, never a clean verdict. Branch snapshots
  count toward work; unusually large valid/generated code may hit this budget.
- The CLI uses an isolated worker with a 15-second deadline per file, or 60 seconds
  when LLM analysis was explicitly requested. Linux workers also have a 1 GiB
  address-space limit. Worker failure, timeout and malformed reports fail closed.
- Process startup is paid per file (about 0.1 seconds per small file in the review
  measurements). Scope a consumer's hook to its complete key/transaction paths and
  measure on the actual runner. Loaded machines or dense valid generated code can
  hit the 15-second deadline; this remains an error, not a defect classification.
- Worker import paths are pinned to the running tool. A package in the scanned
  checkout cannot replace the worker. Submitted code is parsed, never executed.
- Direct library APIs do not provide the CLI's process deadline or OS memory cap.
  Use the CLI, or equivalent caller-managed isolation, for hostile input.
- LLM requests are opt-in under every strategy. Provider failure or invalid response
  falls back to local intent heuristics; static findings cannot be cleared by it.

## Release checks

CI tests Python 3.10–3.14, checks exact exit codes and runs an installed wheel from
outside the checkout. The publish workflow depends on that matrix. Local validation
on one interpreter does not replace the matrix. Before creating a public release,
verify the exact release commit's CI and the PyPI Trusted Publisher configuration.
