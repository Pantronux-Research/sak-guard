# sak-guard

[![CI](https://github.com/Pantronux-Research/sak-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Pantronux-Research/sak-guard/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/Pantronux-Research/sak-guard/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](https://github.com/Pantronux-Research/sak-guard/blob/main/pyproject.toml)
[![PyPI](https://img.shields.io/pypi/v/sak-guard.svg)](https://pypi.org/project/sak-guard/)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

**Static pre-commit security guardrail for Solana agent code.**
The static complement to a runtime transaction firewall.

> **Status: 0.2.0a1 release candidate.** Five Solana rule families are implemented.
> This is an alpha heuristic guardrail. Read the [detection envelope](docs/DETECTION_ENVELOPE.md)
> before using a passing result as a release decision.

---

## Why this exists

Solana's agent ecosystem is adding transaction capability faster than safety tooling.
`solana-agent-kit` lets an agent construct and submit transactions, and the community is
patching the gap ad hoc — most visibly
[`sendaifun/solana-agent-kit#575`](https://github.com/sendaifun/solana-agent-kit/issues/575),
which proposes `@prflght/sak-plugin`, a plugin that wraps the SAK execution flow to
**intercept every transaction before it lands on-chain**.

That is a **runtime** control. It sees a transaction at the moment it is built. It does not
see, and cannot stop, the bad *code* that builds it — an agent-authored tool that sources a
keypair from the wrong place, leaks a seed into a prompt, or does something other than what
its description claims. By the time a runtime firewall has something to intercept, the
vulnerable code is already merged and running.

`sak-guard` asks a different question, earlier:

> Before this code is merged — does it do what it claims to do, and does it handle keys and
> transactions safely?

The two are **complements, not competitors**. Use both.

## Install

```bash
pip install sak-guard          # 0.2.0a1 is currently the only release
pip install --pre sak-guard    # once a stable release also exists
pip install "sak-guard==0.2.0a1"   # pin this exact version
```

Published on PyPI under [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC) — no API token is stored in this repository.

Requires **Python >= 3.10** (see [why the floor is 3.10 rather than 3.9](https://github.com/Pantronux-Research/sak-guard/blob/main/pyproject.toml)).

No runtime dependencies — the engine is stdlib-only, so a pre-commit hook does not have to
touch your environment.

## Use

```bash
sak-guard FILE|DIR            # audit a file or a tree
sak-guard -                   # Python source on stdin (not a git diff)
sak-guard F --json            # machine-readable
sak-guard F --fail-on X       # critical | high | medium | low | any | never
sak-guard F --strategy S      # security-focused (default) | default | ast-heavy | intent-focused
sak-guard F --intent "..."    # what the code is supposed to do
sak-guard F --use-llm         # optional LLM intent pass (provider from LLM_* env)
sak-guard F --language python # source language (default: python)
sak-guard F --quiet           # only print failing targets
```

Exit codes: **0** clean or below threshold · **1** findings at/above threshold · **2** usage,
IO, parse or incomplete-analysis error. Scan errors remain exit 2 with `--fail-on never`.
That option suppresses the failure status for completed findings only.

`reports[].passed` means there are no High/Critical findings; it is independent of
the selected CLI threshold. An incomplete report always has `passed: false`.

```console
$ sak-guard tests/fixtures/vulnerable_api.py
tests/fixtures/vulnerable_api.py: 3 issue(s) (confidence 0.95)
  [critical]:13 security: Hardcoded secret/credential detected
      fix: Use environment variables or a secrets manager
  [critical]:23 security: Use of eval() is a security risk — allows arbitrary code execution
      fix: Use ast.literal_eval() for safe evaluation or avoid eval entirely
  [high]:9 security: subprocess with shell=True allows shell injection
      fix: Use shell=False and pass args as a list

3 issue(s) across 1 target(s); fail-on=high
$ echo $?
1
```

### Why the default strategy is `security-focused`

The base analyzer bank covers hardcoded secrets and `eval()`. It does **not** look for shell
injection at all — no `os.system` or `shell=True` pattern exists in it. Those live in the
`security-focused` strategy's extra patterns. A security auditor defaulting to the base bank
reports **"clean" on `subprocess.call(cmd, shell=True)`**. So the CLI defaults to the bank
that actually looks for command injection.

Verify this yourself: run the same fixture with `--strategy default` and count.

## Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Pantronux-Research/sak-guard
    rev: v0.2.0-alpha.1 # use the reviewed release tag once it exists
    hooks:
      - id: sak-guard
        args: ["--fail-on", "high"]
```

Each pre-commit file scan uses its own isolated process. Budget roughly 0.1
seconds of process startup per small file on the review machine; 100 files can
add about 10 seconds before substantial analysis. Measure this on your runner.
For larger projects, scope the consumer hook to all key-handling and
transaction-building paths, for example:

```yaml
      - id: sak-guard
        files: ^(src/transaction_client/|src/agents/|tests/solana/)
        require_serial: true
        args: ["--fail-on", "high"]
```

Replace those example paths with your own complete set. Files outside the filter
receive no checks. `require_serial` avoids competing hook processes on a loaded
runner; it does not reuse workers. The 15-second deadline is a per-file analysis
budget, not a promise that every valid generated module fits it. A timeout exits
2 and requires investigation; it never becomes a passing verdict.

## GitHub Actions

```yaml
- run: python -m pip install .
- run: sak-guard src/ --fail-on high
```

## Three engines

1. **AST analysis** — structural inspection: where keypairs are sourced, whether transaction
   construction is validated, whether signing is gated.
2. **Security pattern banks** — AST checks for hardcoded secrets, `eval`/`exec`,
   `subprocess(..., shell=True)` and unsafe deserialization. Text heuristics supply
   additional advisory diagnostics.
3. **Intent-mismatch verification** *(in progress)* — declare what a tool is *supposed* to
   do; fail the build when the implementation diverges. No existing Solana safety tool does
   this statically.

## Detection envelope

**Read this before treating a pass as proof.** `sak-guard` is static analysis. It will miss
whole vulnerability classes:

- anything depending on **runtime state**, **economic conditions**, or **on-chain state** —
  none of which exist at commit time;
- logic errors that are syntactically safe;
- vulnerabilities in dependencies.

It is not a replacement for a runtime firewall, a fuzzer, or a formal audit. We publish our
detection gaps and false-positive rate rather than hide them, because a safety tool that
overstates its coverage **is itself a risk**. Current measured rates are in
[`VERIFICATION.md`](VERIFICATION.md).

The [current rule contract](docs/DETECTION_ENVELOPE.md) describes the signing and amount
proxies, conservative false positives, resource limits and unsupported flows. Historical
verification reports describe their own snapshots, not this release candidate.

Each CLI file scan has a 15-second worker deadline (60 seconds with explicit LLM use),
a 4 MiB source limit and a 200,000-node AST limit. Analysis never imports or executes
submitted code. Only `--use-llm` permits sending source to a configured provider.

## Roadmap

- [x] Decoupled CLI, stdlib-only, no server
- [x] AST + regex engines with verified pass/fail behaviour
- [x] Initial Solana banks: key handling, RPC, model provenance, signing and amount bounds
- [ ] GitHub Action with inline PR annotations
- [ ] Intent-mismatch verification, published fixtures
- [x] Documented detection envelope and regression fixtures

## License

Apache-2.0. See [LICENSE](LICENSE).

---

*Pantronux Research (Lead: Irfan Achmad Firmansyah) — Indonesia*
