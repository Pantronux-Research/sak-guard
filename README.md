# sak-guard

**Static pre-commit security guardrail for Solana agent code.**
The static complement to a runtime transaction firewall.

> **Status: v0.1.0-alpha.** The engine is real and tested; the Solana-specific pattern
> banks are in progress. Read [Detection envelope](#detection-envelope) before trusting
> a green check.

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
pip install sak-guard
```

No runtime dependencies — the engine is stdlib-only, so a pre-commit hook does not have to
touch your environment.

## Use

```bash
sak-guard FILE|DIR            # audit a file or a tree
sak-guard -                   # read stdin (pipe a diff into it)
sak-guard F --json            # machine-readable
sak-guard F --fail-on X       # critical | high | medium | low | any | never
sak-guard F --strategy S      # security-focused (default) | default | ast-heavy | intent-focused
sak-guard F --intent "..."    # what the code is supposed to do
sak-guard F --use-llm         # optional LLM intent pass (provider from LLM_* env)
```

Exit codes: **0** clean or below threshold · **1** findings at/above threshold · **2** usage
or IO error.

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
    rev: v0.1.0-alpha
    hooks:
      - id: sak-guard
        args: ["--fail-on", "high"]
```

## GitHub Action

```yaml
- uses: Pantronux-Research/sak-guard@v0.1.0-alpha
  with:
    path: .
    fail-on: high
```

## Three engines

1. **AST analysis** — structural inspection: where keypairs are sourced, whether transaction
   construction is validated, whether signing is gated.
2. **Regex security pattern banks** — the defect class a runtime firewall never sees because
   it lives in source: hardcoded secrets, `eval`/`exec` on agent-supplied input,
   `subprocess(..., shell=True)`, unchecked deserialisation.
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

## Roadmap

- [x] Decoupled CLI, stdlib-only, no server
- [x] AST + regex engines with verified pass/fail behaviour
- [ ] Solana-specific pattern banks (keypair/seed handling, `solders`/`solana-py` misuse,
      unchecked transaction construction, secrets reaching agent tool args)
- [ ] GitHub Action with inline PR annotations
- [ ] Intent-mismatch verification, published fixtures
- [ ] Published verification report incl. detection gaps

## License

Apache-2.0. See [LICENSE](LICENSE).

---

*Pantronux Research (Lead: Irfan Achmad Firmansyah) — Indonesia*
