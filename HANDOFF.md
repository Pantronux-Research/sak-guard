# Current remediation state — 2026-11-11

The working tree contains the author-approved remediation handoff. Nothing has
been committed, pushed or installed. The research snapshot below is historical.

- Local Python 3.14.4: **498 tests passed** in the checkout after the post-handoff
  review. The earlier 379-test artifact is superseded. Current artifact verification
  results are recorded in the external report below.
- The global `swap`/`route` false positives are fixed with resolved SDK origins
  and exact operation names. Generic swap/router fixtures and stdlib asyncio are
  negative controls. Follow-up fixes cover key import rebinding, expression side
  effects, dictionary keys, lazy captures and exact-message review facts.
- Pattern analysis shares one parsed AST across its structural checks (previously
  eight parses). Per-file process overhead and timeout limitations are documented;
  large-module decomposition remains maintenance work before further features.
- Current rule limits and alpha coverage are in
  [docs/DETECTION_ENVELOPE.md](docs/DETECTION_ENVELOPE.md). SG-10/SG-11 have partial
  policy proxies, not complete signer/account/economic authorization coverage.
- Public publication remains pending the exact commit's Python 3.10–3.14 matrix
  and PyPI Trusted Publisher verification. Publish now depends on that matrix.
- `/home/kuro/.local/bin/sak-guard` remains a stale installation and still misses
  the model-to-Pubkey reproduction. Use `python3 -m sak_guard.cli` from this
  checkout for review; replace the installed copy before relying on it.
- The full report is outside the project as requested:
  `/home/kuro/recon/sak-guard-audit/POST_HANDOFF_REVIEW.md`.
- Build/evidence directory:
  `/home/kuro/recon/sak-guard-audit/post-review-n35ryz8v/`.

---

# sak-guard — Research Handoff and State Summary (historical)

**Prepared:** 2026-11-06
**Status:** PAUSED at owner's direction — work resumes on request
**Repo:** https://github.com/Pantronux-Research/sak-guard (public, `main` @ `c6bc1e8`)
**Local tree:** `/home/kuro/recon/sak-guard/`

This document exists so that context lost between sessions does not have to be
reconstructed. It records what the project *is*, what is *done*, what is
*pending*, and the specific facts needed to resume without re-deriving them.

---

## 1. What the project is

**`sak-guard`** — a static pre-commit security guardrail for the Python client
and agent layer of Solana applications.

**The positioning that matters:** every existing Solana security tool observes
the wrong layer. On-chain linters and scanners (Trail of Bits `solana-lints`,
Soleker) inspect contracts and bytecode. Runtime firewalls inspect a transaction
at submission. **Neither sees the Python code where an agent sources a keypair,
misconfigured a commitment level, or passed unvalidated model output into a
transaction sink.** `sak-guard` operates there, at commit time.

It is framed as the **static complement to a runtime transaction firewall** —
not a competitor. The firewall decides whether a transaction may execute;
`sak-guard` decides whether the code that builds it should be merged.

**Applicant / entity (for the grant):**
- Name: Irfan Achmad Firmansyah
- Entity: Pantronux Research (Solo Builder)
- Region: Indonesia
- Wallet: `Ca6GSvPdnkKX3zSbqt6aPVzkmLXNoBaaP62hxPY3RbLd`
- Contact: `Pantronux-Research/sak-guard`

---

## 2. Technical state

### The engine

`sak_guard/` — `analyzer.py`, `strategies.py`, `cli.py`, `solana.py`, `__init__.py`.
Pure stdlib, no runtime dependencies, installable as a pre-commit hook that does
not touch the caller's environment.

**Nine patterns in three families:**

| ID | Family | Detects |
|---|---|---|
| PS-SOL-1 (a–d) | Key material | base58/seed literals, 12/24-word mnemonics, `b58decode` literals bound to key-like names, key names interpolated into f-strings |
| PS-SOL-2a | solders/solana-py misuse | submission with no commitment and no confirmation |
| PS-SOL-2b | " | `simulate_transaction` result whose `.err` is never checked |
| PS-SOL-2c | " | blockhash → intervening work → send (temporal, heuristic) |
| PS-SOL-3 (a–d) | Inference artefact provenance | unverified model output reaching `Pubkey()`, `transfer`, `send_transaction`, `send_raw_transaction` |

Every pattern emits `found` / `clear` / `n/a`. Non-Solana input returns `n/a`
rather than `clear`, so a clean generic-Python file is never mistaken for a
clean Solana file.

### Verified state

```
tests        : 36 passed, exit 0
corpus       : 32 real files, 5,670 lines (sendaifun/solana-agent-kit-py @ main)
findings     : 11        precision: 73% (8 true / 3 false)
trajectory   : 41% -> 57% -> 73%
cli contract : --fail-on all levels correct; stdin is '-' (not --stdin)
               exit 0 clean / 1 findings / 2 usage-or-IO
packaging    : build + twine check PASS; License-Expression: Apache-2.0
               (PEP 639, no License:: classifier); wheel has no caches or tests
ci           : publish.yml on release:[published], id-token scoped to publish job
               ci.yml matrix 3.10-3.13 == requires-python >=3.10
downstream   : pre-commit installs the repo; vulnerable -> 1, clean -> 0
```

**Per-pattern precision:** PS-SOL-1 and PS-SOL-3 produced **zero false positives**
across 5,670 lines. PS-SOL-2c is the weak pattern at **3/5** — both errors come
from a blockhash fetched on the line immediately before the send still counting
the send itself as intervening work. It is retained at `medium` severity
deliberately, and its measured failure is published.

### Defects found in our own tool by the evaluation

Fixed: slash-in-literal read as division (now AST-gated on `ast.BinOp(ast.Div)`);
`f"{kp.pubkey()}"` read as a key leak; division by a module constant;
duplicate emission; `range(max_retries)` flagged as an off-by-one;
a nonexistent path exiting **0** (silent success — the worst pre-commit failure
mode); `prog="sec-audit"` instead of `sak-guard`.

---

## 3. The paper

The research paper is developed outside this repository. It is deliberately not
tracked here, and will be published with a stable release rather than an alpha —
the package and the paper keep independent release cadences.

---

## 4. Pending work

### Blocked on owner action

1. **PyPI Trusted Publisher (OIDC)** — must be linked from the PyPI dashboard,
   naming workflow `publish.yml`, environment `pypi`, repo
   `Pantronux-Research/sak-guard`. Until then `publish.yml` cannot mint its token.
2. **Grant submission** — `SAK_GUARD_GRANT_APPLICATION.md` is complete
   (**$4,000 / 2 milestones**: M1 $1,500 packaging, M2 $2,500 Solana pattern bank).
   Not submitted.
3. **Five accidental Superteam agent accounts** (`schema-probe-*`, zero
   submissions, zero funds) — owner decided to leave them dormant. No self-service
   removal exists.

### Technical, not blocking

- PS-SOL-2c precision (3/5) — a genuine improvement target; the failure mode is
  identified precisely (adjacent-line firing).
- No recall claim is made: no ground-truth labels exist for the corpus. A
  multi-repository corpus with adjudicated labels is required before any recall
  figure would be defensible.

---

## 5. Traps learned (do not re-learn these)

- **`filecontents*` does NOT overwrite an existing `references.bib`.** A stale
  copy silently shadows the embedded block and `bibtex` drops whatever changed in
  it **with no warning**. The `filecontents` package cannot fix it — it is
  obsolete and defers to the kernel. Use `build.sh`.
- **Zero undefined citations ≠ clean compile.** Citations and cross-references are
  separate counters. A `\ref` to an unlabelled equation renders as `??` while the
  citation count stays 0. Check both.
- **Verify the effect, not the write.** A green local check cannot distinguish a
  pushed commit from one that never left the machine. Scrub-token → push is one
  atomic sequence: set token URL → push → scrub → **verify from the remote**.
- **`gitignore` does not untrack.** `git add -A` before writing `.gitignore`
  commits bytecode; use `git rm -r --cached`.
- **A path that does not exist must not exit 0.** An exit code derived from
  findings *present* returns success when a path yields no files — a typo silently
  passes the hook. Assert the exit code for inputs that **must fail**.
- **Metadata verification ≠ having read the paper.** Bibliographic facts can be
  perfectly resolved while the claim attached to them is unsupported, and author
  lists can be wrong in both directions. Read the abstract at minimum.
- **Never fabricate a citation field.** A DOI, venue or year that could not be
  resolved is marked for author confirmation, never guessed.

---

## 6. Where everything lives

```
/home/kuro/recon/sak-guard/            release tree (public repo)
  sak_guard/{analyzer,dataflow,limits,worker,solana,strategies,cli}.py
  tests/{test_cli.py,test_solana_patterns.py,test_audit_regressions.py,fixtures/}
  docs/{DETECTION_ENVELOPE.md,SOLANA_PATTERN_BANK_SPEC.md,M2_VERIFICATION_REPORT.md}
  .github/workflows/{publish.yml,ci.yml}
  .pre-commit-hooks.yaml  pyproject.toml  README.md  CHANGELOG.md
  SECURITY.md  LICENSE  NOTICE

/home/kuro/recon/paper/                 paper sources — outside the repo, not tracked
/home/kuro/recon/SAK_GUARD_HANDOFF.pdf  handoff PDF — outside the repo, not tracked
/home/kuro/recon/SAK_GUARD_GRANT_APPLICATION.md    ($4k / 2 milestones)
/home/kuro/recon/SOLANA_RECON_DOSSIER.md
/home/kuro/recon/ACCIDENTAL_AGENT_ACCOUNTS.md
/home/kuro/recon/fpcheck/real/                     32-file evaluation corpus
```

The paper is intentionally kept out of the repository: it ships with a stable
release, not an alpha, so the package and the paper keep independent cadences.

**Commits of record:** `280ccc5` (M2 pattern bank, tag `v0.1.0-alpha`) ·
`6d656a1` (0.2.0a1, tag `v0.2.0-alpha.1`).

History was rewritten on 2026-11-11 to remove the paper sources and the handoff
PDF. Hashes recorded before that date no longer exist; a mirror backup is at
`/home/kuro/recon/_sak-guard-backup-20261111/`.

**One-line resume:** the tool works and is measured; the paper is submission-ready
except for four paywalled papers worth reading and the PyPI publisher link; the
grant is written and unsubmitted.
