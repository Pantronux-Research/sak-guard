"""Regression tests for the 2026-11-11 Codex/Astra audit findings.

Each test pins one finding from recon/sak-guard-audit/AUDIT_REPORT.md.
The point is that these were *reproducible* bypasses or false positives
before the fix -- so each test fails on the pre-fix tree.
"""

import ast

import pytest

from sak_guard.analyzer import analyze_intent, analyze_patterns
from sak_guard.solana import scan_solana
from sak_guard.strategies import run_strategy

STRATEGIES = ("security-focused", "default", "ast-heavy", "intent-focused")


def _pats(issues):
    return {i.get("pattern") for i in issues if i.get("pattern")}


# ─── SG-08: passed must never be True while a critical finding exists ────────

@pytest.mark.parametrize("strategy", STRATEGIES)
def test_sg08_passed_reflects_solana_findings(strategy):
    """SG-08: `passed` was computed before Solana issues were appended, so a
    critical PS-SOL-1a result shipped with passed=true.

    The assertion requires the finding as well: a conditional check would pass
    vacuously if the rule stopped firing altogether (recheck note).
    """
    code = 'k = Keypair.from_seed(b"01234567890123456789012345678901")\n'
    r = run_strategy(strategy, code, "", "python")
    assert "PS-SOL-1a" in _pats(r["issues"]), (
        f"{strategy}: expected PS-SOL-1a, got {_pats(r['issues'])}"
    )
    assert r["passed"] is False, f"{strategy}: critical issue but passed=True"


# ─── SG-07: every strategy must run the Solana domain pass ───────────────────

@pytest.mark.parametrize("strategy", STRATEGIES)
def test_sg07_all_strategies_run_solana_rules(strategy):
    """SG-07: only security-focused called scan_solana, so --strategy default
    silently disabled the entire domain guardrail."""
    code = 'k = Keypair.from_seed(b"01234567890123456789012345678901")\n'
    r = run_strategy(strategy, code, "", "python")
    assert "PS-SOL-1a" in _pats(r["issues"]), (
        f"{strategy} dropped the Solana rule; got {_pats(r['issues'])}"
    )


# ─── SG-12: public-key constructors are not private key material ─────────────

def test_sg12_pubkey_from_string_is_not_a_secret():
    """SG-12: Pubkey.from_string(<system program id>) is idiomatic public-key
    construction and was reported as critical key material."""
    code = 'p = Pubkey.from_string("11111111111111111111111111111111")\n'
    issues = scan_solana(code)["issues"]
    assert not _pats(issues) & {"PS-SOL-1a"}, (
        f"public key wrongly flagged as secret: {issues}"
    )


def test_sg12_keypair_from_string_still_flags():
    """The counterpart: a Keypair loader with a literal must still be caught."""
    code = 'k = Keypair.from_string("4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw8")\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "private key loader no longer flagged"


# ─── SG-23: eval rule must be AST-aware ──────────────────────────────────────

def test_sg23_literal_eval_is_not_flagged():
    """SG-23: `ast.literal_eval` matched the `eval(` substring and was reported
    critical -- the rule flagged the exact fix it recommends."""
    code = "import ast\nv = ast.literal_eval(text)\n"
    issues = analyze_patterns(code, "python")
    assert not [i for i in issues if i.get("severity") == "critical"
                and "eval" in i.get("description", "").lower()], (
        "literal_eval flagged as unsafe eval"
    )


def test_sg23_spaced_eval_is_flagged():
    """SG-23: `eval (x)` with a space evaded the substring check."""
    code = "v = eval (untrusted)\n"
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("severity") == "critical"
            and "eval" in i.get("description", "").lower()], "spaced eval() evaded"


# ─── SG-09: pathological input must not stall the commit hook ────────────────

def test_sg09_long_literal_concat_is_fast():
    """SG-09: the concat regex backtracked quadratically -- a 30k-term string
    literal took 17-24s at commit time."""
    import time
    code = 'x="' + "a+" * 30000 + '!"\n'
    t0 = time.time()
    analyze_patterns(code, "python")
    assert time.time() - t0 < 2.0, "concat heuristic is still quadratic"


def test_sg09_many_simulate_calls_is_fast():
    """SG-09: the .err check re-walked the tree per call (O(N^2)); 3000
    simulate_transaction calls took 287s."""
    import time
    code = "# solana\n" + "client.simulate_transaction(tx)\n" * 3000
    t0 = time.time()
    scan_solana(code)
    assert time.time() - t0 < 2.0, "simulate rule is still quadratic"


def test_sg03_send_transaction_is_a_provenance_sink():
    """SG-03: send_transaction/send_raw_transaction were absent from SINK_CALLS,
    so model-derived transaction input reached submission unchecked."""
    code = (
        "x = llm.complete(p)\n"
        "client.send_transaction(x, opts=None)\n"
    )
    issues = scan_solana(code)["issues"]
    assert _pats(issues) & {"PS-SOL-3"}, (
        f"model output to send_transaction not flagged: {issues}"
    )


# ════════════════════════════════════════════════════════════════════════════
# Recheck findings (RECHECK_REPORT.md) -- defects found in the first patch.
# ════════════════════════════════════════════════════════════════════════════

# ─── RV-01: the public-key exemption must not be name-based ──────────────────

def test_rv01_renamed_private_loader_still_flags():
    """RV-01: exempting on the receiver's spelling let
    `from solders.keypair import Keypair as Pubkey` read as a public
    constructor while loading a private key."""
    code = (
        "from solders.keypair import Keypair as Pubkey\n"
        'Pubkey.from_base58_string("1111111111111111111111111111111111")\n'
    )
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "renamed private loader evaded the rule"


def test_rv01_unresolved_receiver_fails_closed():
    """An unresolvable receiver must not be assumed public.

    `Solana` is chosen because it passes the PS-SOL applicability gate (a
    Solana-keyword receiver) while resolving to no known type, so this isolates
    the fail-closed classification from the separate gate issue (SG-14).
    """
    code = 'Solana.from_string("11111111111111111111111111111111")\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "unknown receiver was exempted"


# ─── RV-06: public-key constructors stay clean, including aliases ───────────

@pytest.mark.parametrize("code", [
    'from solders.pubkey import Pubkey as Address\nAddress.from_string("11111111111111111111111111111111")\n',
    'from solders.pubkey import Pubkey\nPubkey.from_bytes(b"01234567890123456789012345678901")\n',
    'from solana.publickey import PublicKey\nPublicKey("11111111111111111111111111111111")\n',
])
def test_rv06_public_key_construction_is_clean(code):
    """RV-06: aliased and from_bytes public constructors were false positives."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" not in _pats(issues), f"public key flagged: {issues}"


# ─── RV-04: only a rejecting check counts as validation ─────────────────────

@pytest.mark.parametrize("label,code", [
    ("if with non-rejecting body",
     'x = llm.complete(p)\nif x:\n    print("received")\ntransfer(Pubkey(x), 1)\n'),
    ("ignored boolean predicate",
     "x = llm.complete(p)\nis_allowed(x)\ntransfer(Pubkey(x), 1)\n"),
    ("validator that is never called",
     "x = llm.complete(p)\ndef unused():\n    return is_allowed(x)\ntransfer(Pubkey(x), 1)\n"),
    ("validation invalidated by reassignment",
     "x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
     "x = llm.complete(q)\ntransfer(Pubkey(x), 1)\n"),
])
def test_rv04_non_enforcing_checks_do_not_clear(label, code):
    """RV-04: mentioning the variable is not enforcement; the check must reject."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: bypassed the rule"


def test_rv04_rejecting_check_does_clear():
    """The counterpart: a check that aborts must still clear the value."""
    code = ("x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
            "transfer(Pubkey(x), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" not in _pats(issues), "rejecting check did not clear the value"


# ─── RV-03: a validated value keeps its state through an alias ──────────────

def test_rv03_validated_alias_is_clean():
    """RV-03: `y = x` after validating x must not resurrect the finding."""
    code = ("x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
            "y = x\ntransfer(Pubkey(y), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" not in _pats(issues), f"validated alias false positive: {issues}"


def test_rv03_overwritten_alias_is_unsafe():
    """An alias reassigned from an unvalidated source must flag again."""
    code = ("x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
            "y = x\ny = llm.complete(q)\ntransfer(Pubkey(y), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "reassigned alias stayed cleared"


# ─── RV-05: async, inline, container and qualified API shapes ───────────────

@pytest.mark.parametrize("label,code", [
    ("await", "async def pay():\n    x = await llm.complete(p)\n"
              "    return transfer(Pubkey(x), 1)\n"),
    ("inline call", "transfer(Pubkey(llm.complete(p)), 1)\n"),
    ("container holding a call",
     'x = {"recipient": llm.complete(p)}\ntransfer(Pubkey(x["recipient"]), 1)\n'),
    ("qualified model API",
     "x = client.chat.completions.create(messages=p)\ntransfer(Pubkey(x), 1)\n"),
])
def test_rv05_routine_api_shapes_flag(label, code):
    """RV-05: these are ordinary client shapes and all previously passed."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: not flagged"


# ─── RV-02: alias propagation must stay linear ──────────────────────────────

def test_rv02_long_reverse_alias_chain_is_fast_and_detected():
    """RV-02: the fixpoint rescan was quadratic; 4,000 reverse-ordered aliases
    exceeded a five-second budget. A work queue is linear and still resolves
    the chain, which the original implementation failed to detect at all."""
    import time
    n = 4000
    code = "".join(f"x{i}=x{i+1}\n" for i in range(n))
    code += f"x{n}=llm.complete(p)\ntransfer(Pubkey(x0),1)\n"
    t0 = time.monotonic()
    issues = scan_solana(code)["issues"]
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0, f"alias propagation is still superlinear ({elapsed:.2f}s)"
    assert "PS-SOL-3" in _pats(issues), "long alias chain was not resolved"


# ─── RV-07: no silent coverage loss from a size cutoff ──────────────────────

def test_rv07_repeated_long_literals_are_fast():
    """RV-07: the regex still cost 4.1s on 200 ~1.8 KB lines."""
    import time
    code = "".join('x%d= "%s!"\n' % (i, "a+" * 900) for i in range(200))
    t0 = time.monotonic()
    analyze_patterns(code, "python")
    assert time.monotonic() - t0 < 2.0, "concat rule is still expensive"


def test_rv07_long_legitimate_concatenation_still_reported():
    """RV-07: the length cutoff silently dropped a real diagnostic."""
    code = 'amount=1\nout="' + "a" * 2100 + '"+amount+"!"\n'
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "type_error"], (
        "long concatenation no longer reported"
    )


# ════════════════════════════════════════════════════════════════════════════
# Remaining high-severity findings from the original audit.
# ════════════════════════════════════════════════════════════════════════════

# ─── SG-04: indirect literal key material ───────────────────────────────────

def test_sg04_literal_bound_to_a_name_still_flags():
    """SG-04: `k = b"..."; Keypair.from_seed(k)` embeds the key just as plainly
    as passing the literal inline, but only the inline form used to match."""
    code = 'k = b"01234567890123456789012345678901"\nKeypair.from_seed(k)\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "indirect literal key evaded the rule"


# ─── SG-05: a None option is not a commitment ───────────────────────────────

def test_sg05_none_option_is_not_a_commitment():
    """SG-05: `opts=None` supplied the keyword while supplying no commitment."""
    code = "client.send_transaction(tx, opts=None)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" in _pats(issues), "opts=None counted as a commitment"


def test_sg05_real_commitment_is_clean():
    """The counterpart: an actual commitment option satisfies the rule."""
    code = "client.send_transaction(tx, opts=TxOpts(commitment=Confirmed))\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" not in _pats(issues), "real commitment still flagged"


# ─── SG-06: the .err read must belong to the simulation ─────────────────────

def test_sg06_unrelated_err_does_not_satisfy_the_rule():
    """SG-06: any `.err` in the file used to satisfy the simulation check."""
    code = ("# solana\nr = client.simulate_transaction(tx)\n"
            "print(other.err)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" in _pats(issues), "unrelated .err satisfied the rule"


def test_sg06_checked_and_aborting_is_clean():
    """The counterpart: reading the result's own err and aborting is correct."""
    code = ("# solana\nr = client.simulate_transaction(tx)\n"
            "if r.value.err:\n    raise ValueError('sim failed')\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" not in _pats(issues), "correct simulation check flagged"


def test_sg06_err_read_without_abort_still_flags():
    """Reading .err and ignoring the outcome does not protect the submission."""
    code = ("# solana\nr = client.simulate_transaction(tx)\n"
            "print(r.value.err)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" in _pats(issues), "logging the error counted as checking"


# ─── SG-16: overwrites and scopes ───────────────────────────────────────────

def test_sg16_trusted_overwrite_clears_taint():
    """SG-16: replacing a model value with a trusted one must clear it."""
    code = ("x = llm.complete(p)\nx = TRUSTED_ADDRESS\n"
            "transfer(Pubkey(x), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" not in _pats(issues), "trusted overwrite still flagged"


def test_sg16_same_name_in_other_scope_does_not_leak():
    """SG-16: `x` tainted in one function must not taint `x` in another."""
    code = ("def a():\n    x = llm.complete(p)\n\n"
            "def b():\n    x = SAFE\n    transfer(Pubkey(x), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" not in _pats(issues), "taint crossed a function boundary"


def test_sg16_unoverwritten_value_still_flags():
    """The counterpart: without an overwrite the finding must remain."""
    code = "x = llm.complete(p)\ntransfer(Pubkey(x), 1)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "taint was lost entirely"


# ════════════════════════════════════════════════════════════════════════════
# Fourth-pass findings (FOURTH_PASS_REPORT.md).
# ════════════════════════════════════════════════════════════════════════════

def _run_cli(code, *args):
    """Invoke the CLI on stdin and return (exit, parsed json)."""
    import json
    import subprocess
    import sys
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, "-m", "sak_guard.cli", "-", "--json", *args],
        input=code, capture_output=True, text=True, cwd=str(repo),
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
    )
    try:
        return proc.returncode, json.loads(proc.stdout)
    except Exception:
        return proc.returncode, None


# ─── F4-01: a rule that fails must never read as clean ──────────────────────

def test_f4_01_recursion_input_does_not_fail_open():
    """F4-01: 2,457 bytes of `1*1*1...` made the recursive scope walk raise
    RecursionError; the error was swallowed and the scan reported zero issues,
    exit 0 and passed=true on a real critical model-to-sink flow."""
    code = "# solana\npadding=" + "*".join(["1"] * 1200)
    code += "\nx=llm.complete(p)\ntransfer(Pubkey(x),1)\n"
    exit_code, data = _run_cli(code)
    assert data is not None, "no JSON output"
    report = data["reports"][0]
    assert report["issues"], "reported clean on a critical flow"
    assert report["passed"] is False, "passed=true on a critical flow"
    assert exit_code != 0, "exit 0 on a critical flow"


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_f4_01_no_fail_open_under_any_strategy(strategy):
    """The fail-open reproduced under all four strategies."""
    code = "# solana\npadding=" + "*".join(["1"] * 1200)
    code += "\nx=llm.complete(p)\ntransfer(Pubkey(x),1)\n"
    exit_code, data = _run_cli(code, "--strategy", strategy)
    assert data is not None
    assert data["reports"][0]["passed"] is False, f"{strategy} still fails open"


def test_f4_01_scan_errors_are_surfaced(monkeypatch):
    """A rule that raises must be reported, not swallowed as 'clear'."""
    import sak_guard.solana as sol

    def boom(tree, source):
        raise RuntimeError("synthetic rule failure")

    monkeypatch.setattr(sol, "PATTERNS",
                        [("PS-SOL-X", "synthetic", boom)])
    res = sol.scan_solana('Pubkey("11111111111111111111111111111111")\n')
    assert res["errors"], "rule failure was not surfaced"
    assert any("error:" in v for v in res["patterns"].values())


# ─── F4-02: validation must hold on every path to the sink ──────────────────

@pytest.mark.parametrize("label,code", [
    ("conditional validation",
     "def pay(check_enabled):\n    x = llm.complete(p)\n    if check_enabled:\n"
     "        if x not in ALLOWED:\n            raise ValueError('r')\n"
     "    return transfer(Pubkey(x), 1)\n"),
    ("swallowed rejection",
     "x = llm.complete(p)\ntry:\n    if x not in ALLOWED:\n"
     "        raise ValueError('r')\nexcept ValueError:\n    print('ignored')\n"
     "transfer(Pubkey(x), 1)\n"),
    ("loop validates only first iteration",
     "for i in range(2):\n    x = llm.complete(p)\n    if i == 0:\n"
     "        if x not in ALLOWED:\n            raise ValueError('r')\n"
     "    transfer(Pubkey(x), 1)\n"),
    ("inverted polarity",
     "x = llm.complete(p)\nif x in ALLOWED:\n    raise ValueError('bad')\n"
     "transfer(Pubkey(x), 1)\n"),
])
def test_f4_02_non_dominating_validation(label, code):
    """F4-02: a check that does not dominate the sink is not enforcement."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: bypassed"


# ─── F4-03: overwrite handling ──────────────────────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("optional overwrite",
     "x = llm.complete(p)\nif use_trusted:\n    x = TRUSTED_ADDRESS\n"
     "transfer(Pubkey(x), 1)\n"),
    ("augmented assign",
     'x = llm.complete(p)\nx += ""\ntransfer(Pubkey(x), 1)\n'),
    ("same-line reassignment",
     "x = TRUSTED_ADDRESS\nx = llm.complete(p); transfer(Pubkey(x), 1)\n"),
])
def test_f4_03_taint_not_erased(label, code):
    """F4-03: only an unconditional overwrite clears a value."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: taint wrongly erased"


# ─── F4-04: captures and expression forms ───────────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("module capture in function",
     "x = llm.complete(p)\ndef pay():\n    return transfer(Pubkey(x), 1)\n"),
    ("method on tainted receiver",
     "x = llm.complete(p)\ny = x.strip()\ntransfer(Pubkey(y), 1)\n"),
    ("destructuring",
     "x, metadata = llm.complete(p)\ntransfer(Pubkey(x), 1)\n"),
])
def test_f4_04_scope_and_expressions(label, code):
    """F4-04: lexical capture, receiver provenance and destructuring."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: taint lost"


# ─── F4-05: a fresh model call is never pre-cleared ─────────────────────────

def test_f4_05_fresh_model_output_of_cleared_input():
    """F4-05: clearing the *input* must not clear a new completion."""
    code = ("x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
            "y = llm.complete(x)\ntransfer(Pubkey(y), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "fresh source inherited clearance"


# ─── F4-06: import bindings must honour rebinding ───────────────────────────

@pytest.mark.parametrize("label,code", [
    ("assignment alias",
     "from solders.keypair import Keypair\nAddress = Keypair\n"
     'Address.from_base58_string("1111111111111111111111111111111111")\n'),
    ("rebinding over import",
     "from solders.pubkey import Pubkey\nfrom solders.keypair import Keypair\n"
     "Pubkey = Keypair\n"
     'Pubkey.from_base58_string("1111111111111111111111111111111111")\n'),
])
def test_f4_06_private_ctor_not_exempted(label, code):
    """F4-06: the binding decides, not the spelling."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), f"{label}: private loader exempted"


# ─── F4-07 / F4-08: transaction rules ──────────────────────────────────────

def test_f4_07_logging_error_then_submitting():
    """F4-07: a later ordinary return must not satisfy the simulation rule."""
    code = ("def pay(tx):\n    r = client.simulate_transaction(tx)\n"
            "    print(r.value.err)\n    sig = client.send_transaction(tx)\n"
            "    client.confirm_transaction(sig.value)\n    return sig\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" in _pats(issues), "logging the error counted as checking"


def test_f4_07_async_correct_form_is_clean():
    """F4-07: the legitimate async form was a false positive."""
    code = ("# solana\nasync def pay(tx):\n"
            "    r = await client.simulate_transaction(tx)\n"
            "    if r.value.err:\n        raise ValueError('sim')\n"
            "    sig = await client.send_transaction(tx)\n"
            "    await client.confirm_transaction(sig.value)\n    return sig\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" not in _pats(issues), "correct async form flagged"


def test_f4_08_none_option_through_alias():
    """F4-08: `opts = None` then `opts=opts` supplied no commitment."""
    code = "opts = None\nclient.send_transaction(tx, opts=opts)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" in _pats(issues), "None alias counted as a commitment"


def test_f4_08_confirmation_in_dead_branch():
    """F4-08: `if False:` never executes."""
    code = ("sig = client.send_transaction(tx)\nif False:\n"
            "    client.confirm_transaction(sig.value)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" in _pats(issues), "dead branch satisfied the confirmation"


# ─── F4-09: literal provenance and secret serialization ────────────────────

def test_f4_09_literal_through_second_alias():
    """F4-09: one alias hop was tracked, a second escaped."""
    code = ('k = b"01234567890123456789012345678901"\nseed_bytes = k\n'
            "Keypair.from_seed(seed_bytes)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "second alias hop evaded the rule"


def test_f4_09_secret_hex_logging_is_flagged():
    """F4-09: `hex`/`to_string`/`str` were blanket-exempt as public projections."""
    code = '# solana\nprint(f"{secret.hex()}")\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1d" in _pats(issues), "serialized secret was exempt"


def test_f4_09_public_projection_still_clean():
    """The counterpart: printing a public key is correct code."""
    code = '# solana\nprint(f"{kp.pubkey()}")\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1d" not in _pats(issues), "public projection flagged"


# ─── F4-10: dense workloads must stay bounded ──────────────────────────────

def test_f4_10_dense_assignments_and_sinks():
    """F4-10: 4,000 assignments + 4,000 sinks exceeded a five-second budget."""
    import time
    n = 4000
    code = "".join(f"v{i}=llm.complete(p)\n" for i in range(n))
    code += "".join(f"Pubkey(v{i})\n" for i in range(n))
    t0 = time.monotonic()
    scan_solana(code)
    assert time.monotonic() - t0 < 15.0, "dense workload is still superlinear"


def test_f4_10_clean_dense_file():
    """F4-10: clean code with many constructors was affected too."""
    import time
    n = 8000
    code = "from solders.pubkey import Pubkey\n"
    code += "".join(f"v{i}=0\n" for i in range(n))
    code += 'Pubkey(b"01234567890123456789012345678901")\n' * n
    t0 = time.monotonic()
    scan_solana(code)
    assert time.monotonic() - t0 < 15.0, "clean dense file is still superlinear"


# ─── F4-11: legitimate public-key wrappers ─────────────────────────────────

def test_f4_11_public_wrapper_is_clean():
    """F4-11: a project wrapper around Pubkey.from_string is correct code."""
    code = ("from solders.pubkey import Pubkey\n\nclass Destination:\n"
            "    @classmethod\n    def from_string(cls, text):\n"
            "        return Pubkey.from_string(text)\n\n"
            'destination = Destination.from_string("11111111111111111111111111111111")\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" not in _pats(issues), "public wrapper flagged as secret"


def test_f4_11_private_wrapper_still_flags():
    """The counterpart: a wrapper around a Keypair loader must still flag."""
    code = ("from solders.keypair import Keypair\n\nclass Vault:\n"
            "    @classmethod\n    def from_string(cls, t):\n"
            "        return Keypair.from_string(t)\n\n"
            'Vault.from_string("4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw8")\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "private wrapper exempted"


# ─── F4-13: deep expression must not crash ─────────────────────────────────

def test_f4_13_deep_concatenation_does_not_crash():
    """F4-13: recursive flattening of an Add-chain raised on a small input."""
    code = "amount=1\nout=" + "+".join(['"a"'] * 1200) + "+amount\n"
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "type_error"], (
        "deep concatenation produced no diagnostic"
    )


# ─── F4-12: point-in-time and scope false positives ────────────────────────

@pytest.mark.parametrize("label,code", [
    ("trusted overwrite then alias",
     "x = llm.complete(p)\nx = TRUSTED_ADDRESS\ny = x\n"
     "transfer(Pubkey(y), 1)\n"),
    ("sink before a later source",
     "x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError('r')\n"
     "transfer(Pubkey(x), 1)\nx = llm.complete(q)\n"),
    ("same-line overwrite and sink",
     "x = TRUSTED_ADDRESS; transfer(Pubkey(x), 1)\n"),
    ("trusted parameter shadowing a tainted module name",
     "def a():\n    x = llm.complete(p)\n    return x\n\n"
     "def b(x):\n    y = x\n    return transfer(Pubkey(y), 1)\n"),
])
def test_f4_12_safe_code_not_flagged(label, code):
    """F4-12: point-in-time and scope mistakes produced critical false positives."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" not in _pats(issues), f"{label}: false positive"


def test_f4_12_lexical_capture_still_works():
    """The counterpart: a genuine capture must still be flagged (F4-04)."""
    code = "x = llm.complete(p)\ndef f():\n    return transfer(Pubkey(x), 1)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "capture stopped being detected"


# ════════════════════════════════════════════════════════════════════════════
# The two High findings that had no rule at all: SG-10 and SG-11.
# ════════════════════════════════════════════════════════════════════════════

# ─── SG-10: signer authorization / message integrity (PS-SOL-4) ────────────

def test_sg10_signing_an_unreviewed_deserialized_message():
    """SG-10: signing bytes from the network without inspecting the message
    authorizes a transaction the client never constructed."""
    code = ("from solders.transaction import VersionedTransaction\n"
            "blob = fetch()\n"
            "tx = VersionedTransaction.from_bytes(blob)\n"
            "sig = keypair.sign_message(tx.message)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "unreviewed message signing not flagged"


def test_sg10_signing_model_derived_message():
    """SG-10: a model-supplied message is untrusted by definition."""
    code = "msg = llm.complete(p)\nsig = keypair.sign_message(msg)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "model-derived message signing not flagged"


def test_sg10_inline_deserialize_in_sign_call():
    """SG-10: sign(from_bytes(blob)) is the same defect without a variable."""
    code = ("from solders.transaction import VersionedTransaction\n"
            "sig = keypair.sign_message(VersionedTransaction.from_bytes(blob))\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "inline deserialize not flagged"


def test_sg10_reviewed_message_is_clean():
    """The counterpart: checking the fee payer and instructions is correct."""
    code = ("from solders.transaction import VersionedTransaction\n"
            "tx = VersionedTransaction.from_bytes(blob)\n"
            "if tx.message.account_keys[0] != EXPECTED:\n"
            "    raise ValueError('fee payer')\n"
            "review(tx.message.instructions)\n"
            "sig = keypair.sign_message(tx.message)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" not in _pats(issues), "reviewed message still flagged"


# ─── SG-11: amount bounds and slippage (PS-SOL-5) ──────────────────────────

def test_sg11_unbounded_caller_supplied_amount():
    """SG-11: an uncapped amount lets the caller drain the account."""
    code = "def send(dest, amount):\n    transfer(Pubkey(dest), amount)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), "unbounded amount not flagged"


def test_sg11_amount_from_stdin():
    """SG-11: a value read from input() is untrusted."""
    code = "amt = int(input())\ntransfer(Pubkey(dest), amt)\n"
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), "input()-derived amount not flagged"


def test_sg11_swap_without_minimum_output():
    """The explicit-bound policy applies to a resolved Solana swap API."""
    code = ("from jupiter_python_sdk.jupiter import Jupiter\n"
            "swap = Jupiter.swap\n"
            "def trade(pool, amount):\n    swap(pool, amount)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), "unbounded swap not flagged"


@pytest.mark.parametrize("label,code", [
    ("comparison bound",
     "def send(dest, amount):\n    if amount > MAX:\n"
     "        raise ValueError('cap')\n    transfer(Pubkey(dest), amount)\n"),
    ("min() cap",
     "def send(dest, amount):\n    capped = min(amount, MAX)\n"
     "    transfer(Pubkey(dest), capped)\n"),
    ("literal amount",
     "transfer(Pubkey(dest), 1)\n"),
    ("bounded swap",
     "from jupiter_python_sdk.jupiter import Jupiter\nswap = Jupiter.swap\n"
     "def trade(pool, amount):\n"
     "    swap(pool, amount, min_amount_out=950, slippage_bps=50)\n"),
])
def test_sg11_bounded_amounts_are_clean(label, code):
    """The counterpart: a cap, a literal, or a slippage bound is correct code."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" not in _pats(issues), f"{label}: false positive"


# ─── SG-25: procedures are not missing-return defects ──────────────────────

@pytest.mark.parametrize("label,code", [
    ("procedure", "def save():\n    persist()\n"),
    ("procedure with a call", "def send(dest, amount):\n    transfer(dest, amount)\n"),
])
def test_sg25_procedures_are_not_flagged(label, code):
    """SG-25: `def save(): persist()` is a procedure, not a defect."""
    issues = analyze_patterns(code, "python")
    assert not [i for i in issues if i.get("type") == "bug"], f"{label}: flagged"


@pytest.mark.parametrize("label,code", [
    ("annotated to return", "def compute(x) -> int:\n    total = x + 1\n"),
    ("inconsistent paths",
     "def f(x):\n    if x:\n        return 1\n    print('no')\n"),
    ("bare return mixed", "def g(x):\n    if x:\n        return 1\n    return\n"),
])
def test_sg25_genuine_omissions_still_flagged(label, code):
    """The counterpart: a promised value with no return is still a defect."""
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "bug"], f"{label}: missed"


def test_sg25_return_inside_a_string_does_not_suppress():
    """SG-25: the old check was `'return' not in body`, so a string hid it."""
    code = 'def h(x) -> int:\n    msg = "return the value"\n    total = x\n'
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "bug"], "string suppressed it"


# ════════════════════════════════════════════════════════════════════════════
# Remaining Medium findings (SG-18, SG-19, SG-20, SG-21, SG-22, SG-24, SG-27).
# ════════════════════════════════════════════════════════════════════════════

# ─── SG-21: SQL rule must distinguish interpolation from parameterisation ──

def test_sg21_parameterized_query_is_clean():
    """SG-21: `execute("... id=%s", (v,))` was flagged critical because of `%s`."""
    code = 'cursor.execute("SELECT * FROM t WHERE id=%s", (value,))\n'
    issues = analyze_patterns(code, "python")
    assert not [i for i in issues if i.get("severity") == "critical"], "parameterized query flagged"


@pytest.mark.parametrize("label,code", [
    ("inline f-string", 'cursor.execute(f"SELECT * FROM t WHERE id={v}")\n'),
    ("f-string via a variable",
     'q = f"SELECT * FROM t WHERE id={v}"\ncursor.execute(q)\n'),
    ("concatenation", 'cursor.execute("SELECT * FROM t WHERE id=" + v)\n'),
])
def test_sg21_interpolated_query_is_flagged(label, code):
    """The counterpart: an assembled query is a real injection risk."""
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("severity") == "critical"], f"{label}: missed"


def test_sg21_static_query_is_clean():
    """A constant query with no interpolation is not an injection."""
    issues = analyze_patterns('cursor.execute("SELECT * FROM t")\n', "python")
    assert not [i for i in issues if i.get("severity") == "critical"], "static query flagged"


# ─── SG-22: credential rule must use AST ───────────────────────────────────

def test_sg22_public_label_is_not_a_secret():
    """SG-22: `token = "SOL"` is a ticker, not a credential."""
    issues = analyze_patterns('token = "SOL"\n', "python")
    assert not [i for i in issues if i.get("type") == "security"], "ticker flagged as secret"


@pytest.mark.parametrize("label,code", [
    ("annotated assignment", 'password: str = "hunter2secret"\n'),
    ("api key literal", 'api_key = "sk-abc123456789"\n'),
    ("plain password", 'password = "hunter2secret"\n'),
])
def test_sg22_real_credentials_flagged(label, code):
    """The counterpart: a credential-shaped name with a real value is flagged."""
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "security"], f"{label}: missed"


# ─── SG-24: infinite loop must respect control flow ───────────────────────

@pytest.mark.parametrize("label,code", [
    ("break", "while n > 0:\n    break\n"),
    ("counter update", "while n > 0:\n    n -= 1\n"),
    ("return", "while n > 0:\n    return n\n"),
])
def test_sg24_terminating_loops_are_clean(label, code):
    """SG-24: `while n > 0: break` was reported critical."""
    issues = analyze_patterns(code, "python")
    assert not [i for i in issues if i.get("type") == "bug"], f"{label}: flagged"


def test_sg24_nonterminating_loop_is_flagged():
    """The counterpart: no exit path and no progress is a real hang."""
    issues = analyze_patterns("while n > 0:\n    work()\n", "python")
    assert [i for i in issues if i.get("type") == "bug"], "non-terminating loop missed"


# ─── SG-27: stub detection must be structural ─────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("pass", "def g():\n    pass\n"),
    ("ellipsis", "def h():\n    ...\n"),
    ("NotImplementedError", "def i():\n    raise NotImplementedError\n"),
])
def test_sg27_stubs_are_flagged(label, code):
    """SG-27: a deliberate stub is still an incomplete function."""
    issues = analyze_intent(code, "", "python")
    assert [i for i in issues if i.get("type") == "incomplete"], f"{label}: missed"


def test_sg27_complete_function_with_the_word_pass_is_clean():
    """SG-27: the old check was `"pass" in code`, so this was critical."""
    code = 'def f():\n    return "password"\n'
    issues = analyze_intent(code, "", "python")
    assert not [i for i in issues if i.get("type") == "incomplete"], "false positive"


# ─── SG-18: nothing may be skipped silently ───────────────────────────────

def test_sg18_unsupported_language_is_rejected():
    """SG-18: `--language javascript` used to pass malformed Python as clean."""
    exit_code, data = _run_cli("def broken(", "--language", "javascript")
    assert data is None, "accepted an unsupported language"
    assert exit_code != 0, "exited 0 on an unsupported language"


def test_sg18_empty_target_set_does_not_pass():
    """SG-18: a target set with nothing analysable exited 0."""
    import subprocess
    import sys
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        proc = subprocess.run(
            [sys.executable, "-m", "sak_guard.cli", td],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
            env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
        )
    assert proc.returncode != 0, "empty target set reported success"


# ─── SG-19: input must be bounded ─────────────────────────────────────────

def test_sg19_oversized_input_is_rejected():
    """SG-19: analysis had no input bound at all."""
    import subprocess
    import sys
    import tempfile
    from pathlib import Path
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write("x = 1\n" * 900_000)          # ~5.4 MB
        name = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "sak_guard.cli", name],
            capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
            env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
        )
    finally:
        Path(name).unlink(missing_ok=True)
    assert proc.returncode == 2, "oversized input was not rejected"
    assert "analysis limit" in proc.stderr, proc.stderr[:200]


# ─── SG-20: malformed LLM responses must not crash ────────────────────────

@pytest.mark.parametrize("payload", [
    {"issues": []},
    {"issues": [None]},
    {"issues": ["text"]},
    {"issues": "notalist"},
    {"issues": [{"severity": "BOGUS", "line": "abc"}]},
])
def test_sg20_malformed_llm_response_is_handled(payload):
    """SG-20: `{"issues":[null]}` raised AttributeError in normalization."""
    import sak_guard.analyzer as analyzer

    class _Client:
        def chat(self, system, user):
            return __import__("json").dumps(payload)

    original = analyzer._llm_client
    analyzer._llm_client = _Client()
    try:
        result = analyzer._llm_analyze_intent("x = 1", "intent", "python")
    finally:
        analyzer._llm_client = original
    assert result is None or isinstance(result, list), "malformed response crashed"
    for item in (result or []):
        assert item["severity"] in ("critical", "high", "medium", "low", "info")
        assert isinstance(item["line"], int)


# ─── SG-26: type errors need evidence, not name guessing ──────────────────

def test_sg26_string_variable_is_not_a_type_error():
    """SG-26: `user_id = "42"` holds a string, so concatenation is fine."""
    code = 'user_id = "42"\ns = "id:" + user_id + "!"\n'
    issues = analyze_patterns(code, "python")
    assert not [i for i in issues if i.get("type") == "type_error"], "false positive"


def test_sg26_numeric_variable_is_flagged():
    """The counterpart: a variable that really holds a number."""
    code = 'count = 5\ns = "n:" + count + "!"\n'
    issues = analyze_patterns(code, "python")
    assert [i for i in issues if i.get("type") == "type_error"], "missed"


# ─── SG-28: loader-aware and multi-line security patterns ─────────────────

def test_sg28_yaml_safe_loader_is_clean():
    """SG-28: `yaml.load(s, Loader=yaml.SafeLoader)` is the safe form."""
    issues = run_strategy("security-focused",
                          "yaml.load(s, Loader=yaml.SafeLoader)\n", "", "python")["issues"]
    assert not [i for i in issues if "yaml" in i.get("description", "").lower()], "false positive"


def test_sg28_yaml_bare_load_is_flagged():
    """The counterpart: a bare yaml.load can execute arbitrary code."""
    issues = run_strategy("security-focused", "yaml.load(s)\n", "", "python")["issues"]
    assert [i for i in issues if "yaml" in i.get("description", "").lower()], "missed"


def test_sg28_multiline_shell_true_is_flagged():
    """SG-28: the call split across two lines was invisible to a line scan."""
    issues = run_strategy("security-focused",
                          "subprocess.run(cmd,\n    shell=True)\n", "", "python")["issues"]
    assert [i for i in issues if "shell" in i.get("description", "").lower()], "missed"


# ════════════════════════════════════════════════════════════════════════════
# Fifth-pass findings (FIFTH_PASS_REPORT.md) — H01..H13.
# ════════════════════════════════════════════════════════════════════════════

# ─── H01: an internal error must never be a clean verdict ──────────────────

def test_h01_bare_annotation_does_not_fail_open():
    """H01: `x: str` (AnnAssign with value None) crashed the walk; the caller
    discarded the interpreter error and reported zero issues, exit 0, passed=true
    on a real critical flow. 53 bytes."""
    code = "x: str\ndest=llm.complete(p)\ntransfer(Pubkey(dest),1)\n"
    exit_code, data = _run_cli(code)
    assert data is not None, "no JSON output"
    assert data["reports"][0]["issues"], "reported clean"
    assert data["reports"][0]["passed"] is False, "passed=true on a critical flow"
    assert exit_code != 0, "exit 0 on a critical flow"


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_h01_bare_annotation_under_every_strategy(strategy):
    code = "x: str\ndest=llm.complete(p)\ntransfer(Pubkey(dest),1)\n"
    _exit, data = _run_cli(code, "--strategy", strategy)
    assert data is not None
    assert data["reports"][0]["passed"] is False, f"{strategy} fails open"


def test_h01_analysis_error_surfaces_as_critical():
    """An interpreter failure must become a reported analysis error."""
    import sak_guard.solana as sol

    def boom(tree, source):
        from sak_guard.dataflow import AnalysisError
        raise AnalysisError("synthetic interpreter failure")

    original = sol.ps_sol_3
    sol.PATTERNS = [("PS-SOL-3", "synthetic", boom)]
    try:
        res = sol.scan_solana('Pubkey("11111111111111111111111111111111")\n')
    finally:
        sol.PATTERNS = [("PS-SOL-1", "a", sol.ps_sol_1),
                        ("PS-SOL-2", "b", sol.ps_sol_2),
                        ("PS-SOL-3", "c", original),
                        ("PS-SOL-4", "d", sol.ps_sol_4),
                        ("PS-SOL-5", "e", sol.ps_sol_5)]
    assert res["errors"], "interpreter failure was swallowed"


# ─── H02: reading a message field is not review ───────────────────────────

def test_h02_logging_account_keys_is_not_review():
    """H02: `print(tx.message.account_keys)` imposed no restriction."""
    code = ("from solders.transaction import Transaction\n"
            "def relay(blob, keypair):\n"
            "    tx = Transaction.from_bytes(blob)\n"
            "    print(tx.message.account_keys)\n"
            "    return keypair.sign_message(tx.message_data())\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "logging counted as authorization"


def test_h02_unrelated_object_read_is_not_review():
    """H02: `print(other.instructions)` was not even associated with tx."""
    code = ("tx = Transaction.from_bytes(blob)\n"
            "print(other.instructions)\n"
            "keypair.sign_message(tx.message)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "unrelated read satisfied the rule"


def test_h02_enforcing_comparison_is_review():
    """The counterpart: a rejecting check on the message is authorization."""
    code = ("tx = T.from_bytes(blob)\n"
            "if tx.message.account_keys[0] != EXPECTED:\n"
            "    raise ValueError('fee payer')\n"
            "kp.sign_message(tx.message)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" not in _pats(issues), "enforcing check flagged"


# ─── H03: the documented SDK signing entry points ─────────────────────────

@pytest.mark.parametrize("label,code", [
    ("Transaction.sign",
     "from solders.transaction import Transaction\n"
     "def relay(blob, kp, bh):\n    tx = Transaction.from_bytes(blob)\n"
     "    return tx.sign([kp], bh)\n"),
    ("VersionedTransaction constructor",
     "from solders.transaction import VersionedTransaction\n"
     "def relay(blob, kp):\n    tx = VersionedTransaction.from_bytes(blob)\n"
     "    return VersionedTransaction(tx.message, [kp])\n"),
])
def test_h03_real_signing_apis_are_sinks(label, code):
    """H03: SIGN_CALLS omitted `sign` and the signing constructors."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), f"{label}: not a sink"


# ─── H04: a bound must be an upper bound ──────────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("lower bound only",
     'def pay(amount):\n    if amount < 0:\n        raise ValueError("neg")\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
    ("ignored comparison",
     'def pay(amount):\n    print(amount < 100)\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
    ("max() raises a floor",
     'def pay(amount):\n    print(max(amount, 100))\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
])
def test_h04_non_upper_bounds_do_not_cap(label, code):
    """H04: `amount < 0` permits arbitrarily large positives."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"{label}: accepted as a cap"


def test_h04_upper_bound_is_accepted():
    code = ('def pay(amount):\n    if amount > MAX:\n        raise ValueError("big")\n'
            '    return transfer(Pubkey(DEST), amount)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" not in _pats(issues), "real upper bound flagged"


# ─── H05: amount representations and sources ──────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("conversion wrapper", "def pay(a):\n    return transfer(Pubkey(D), int(a))\n"),
    ("alias of an input source",
     "amount = int(input())\nvalue = amount\ntransfer(Pubkey(D), value)\n"),
    ("TransferParams form",
     "from solders.system_program import transfer, TransferParams\n"
     "def pay(a):\n    return transfer(TransferParams(\n"
     "        from_pubkey=S, to_pubkey=D, lamports=a))\n"),
])
def test_h05_amount_forms_are_flagged(label, code):
    """H05: only a bare Name in position 2 used to be inspected."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"{label}: evaded"


# ─── H06: keyword presence is not output protection ───────────────────────

@pytest.mark.parametrize("label,code", [
    ("None", "swap(POOL, 100, min_amount_out=None)\n"),
    ("zero", "swap(POOL, 100, min_amount_out=0)\n"),
])
def test_h06_degenerate_min_out_is_flagged(label, code):
    """H06: `min_amount_out=None/0` disables the protection."""
    code = "from jupiter_python_sdk.jupiter import Jupiter\nswap = Jupiter.swap\n" + code
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"min_amount_out={label} accepted"


def test_h06_real_slippage_is_clean():
    code = ("from jupiter_python_sdk.jupiter import Jupiter\nswap = Jupiter.swap\n"
            "swap(POOL, 100, min_amount_out=950, slippage_bps=50)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" not in _pats(issues), "real slippage bound flagged"


# ─── H07: exception and finally semantics ─────────────────────────────────

def test_h07_handler_sees_assignment_before_raise():
    """H07: handlers started from try-entry state, losing the unsafe value."""
    code = ('def pay():\n    x = TRUSTED\n    try:\n'
            '        x = llm.complete(p)\n        raise ValueError("f")\n'
            '    except ValueError:\n        return transfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "handler lost the assignment"


def test_h07_finally_runs_on_pending_return():
    """H07: finally was skipped when the body returned."""
    code = ('def pay():\n    x = llm.complete(p)\n    try:\n'
            '        return 0\n    finally:\n        transfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "finally skipped"


# ─── H08: loop exits and convergence ──────────────────────────────────────

@pytest.mark.parametrize("keyword", ["break", "continue"])
def test_h08_loop_exit_keeps_carried_state(keyword):
    """H08: break/continue discarded the body state."""
    code = (f'x = TRUSTED\nfor i in range(1):\n    x = llm.complete(p)\n'
            f'    {keyword}\ntransfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{keyword} lost the assignment"


def test_h08_deep_loop_converges():
    """H08: a three-pass cutoff certified clean beyond the explored states."""
    code = ("def pay():\n    x0=x1=x2=x3=TRUSTED\n    x4 = llm.complete(p)\n"
            "    for i in range(5):\n        x0=x1\n        x1=x2\n        x2=x3\n"
            "        x3=x4\n        transfer(Pubkey(x0), 1)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "deep loop under-approximated"


# ─── H09: supported syntax must be interpreted ────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("sink in an if test",
     'x = llm.complete(p)\nif transfer(Pubkey(x), 1):\n    print("s")\n'),
    ("match case",
     'def pay(flag):\n    match flag:\n        case _:\n'
     '            x = llm.complete(p)\n            return transfer(Pubkey(x), 1)\n'),
    ("BoolOp",
     'x = llm.complete(p) or DEFAULT\ntransfer(Pubkey(x), 1)\n'),
])
def test_h09_syntax_is_not_skipped(label, code):
    """H09: conditions, match and BoolOp were silently underinterpreted."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), f"{label}: skipped"


# ─── H10: clearance must be earned and stay earned ────────────────────────

def test_h10_attacker_controlled_allow_list():
    """H10: `x not in {x}` proves nothing."""
    code = 'x = llm.complete(p)\nif x not in {x}:\n    raise ValueError("r")\ntransfer(Pubkey(x), 1)\n'
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "self-referential allow-list cleared x"


def test_h10_container_mutation_invalidates():
    """H10: writing fresh model output into a cleared container kept clearance."""
    code = ('x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError("r")\n'
            'box = {"recipient": x}\nbox["recipient"] = llm.complete(q)\n'
            'transfer(Pubkey(box["recipient"]), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "mutated container stayed cleared"


# ─── H11: bindings are positional; aliases are a worklist ────────────────

def test_h11_later_import_does_not_rewrite_an_earlier_call():
    """H11: a later public import exempted an earlier private loader."""
    code = ('from solders.keypair import Keypair as C\n'
            'C.from_base58_string("1111111111111111111111111111111111111111111111111111111111111111")\n'
            'from solders.pubkey import Pubkey as C\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "later import exempted the earlier call"


def test_h11_ten_alias_hops_are_resolved():
    """H11: the fixed eight-pass closure stopped short of ten hops."""
    code = ('k0 = b"01234567890123456789012345678901"\n'
            + "".join(f"k{i} = k{i-1}\n" for i in range(1, 11))
            + "Keypair.from_seed(k10)\n")
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "ten alias hops evaded"


# ─── H12: polarity and reachability ──────────────────────────────────────

def test_h12_inverted_simulation_polarity():
    """H12: `if not r.value.err: raise` rejects *successful* simulations."""
    code = ('r = client.simulate_transaction(tx)\nif not r.value.err:\n'
            '    raise ValueError("success")\nsig = client.send_transaction(tx)\n'
            'client.confirm_transaction(sig.value)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2b" in _pats(issues), "inverted polarity counted as a check"


def test_h12_conditional_confirmation_does_not_dominate():
    """H12: `if should_confirm:` may never run."""
    code = ('sig = client.send_transaction(tx)\nif should_confirm:\n'
            '    client.confirm_transaction(sig.value)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" in _pats(issues), "conditional confirmation accepted"


def test_h12_unconditional_confirmation_is_clean():
    code = ('sig = client.send_transaction(tx, opts=O)\n'
            'client.confirm_transaction(sig.value)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-2a" not in _pats(issues), "unconditional confirmation flagged"


# ─── H13: no per-call whole-AST rescans ──────────────────────────────────

def test_h13_many_transfers_is_fast():
    """H13: `_is_bounded` walked the tree per amount; 1,000 transfers (30 KB)
    exceeded six seconds."""
    import time
    code = "amount=int(input())\n" + "transfer(Pubkey(DEST),amount)\n" * 1000
    t0 = time.monotonic()
    scan_solana(code)
    assert time.monotonic() - t0 < 15.0, "amount rule is superlinear"


def test_h13_many_assigned_simulations_is_fast():
    """H13: `_err_guarded_aborts` scanned the tree per assigned result."""
    import time
    code = "".join(f"r{i}=client.simulate_transaction(tx)\n" for i in range(1000))
    t0 = time.monotonic()
    scan_solana(code)
    assert time.monotonic() - t0 < 15.0, "simulation rule is superlinear"


# ─── A security rule must not match its own pattern table ─────────────────

def test_security_patterns_ignore_string_literals_and_comments():
    """`strategies.py` reported six high findings against its own regex table,
    because the patterns are applied to raw source text. String and comment
    contents are masked before matching."""
    code = (
        'PATTERNS = [\n'
        '    (r"subprocess\\.\\w+\\(.*shell\\s*=\\s*True", "shell=True risk"),\n'
        '    (r"os\\.system\\(", "os.system risk"),\n'
        ']\n'
        '# this comment mentions shell=True and os.system( too\n'
    )
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    flagged = [i for i in issues if "shell" in i.get("description", "").lower()
               or "os.system" in i.get("description", "").lower()]
    assert not flagged, f"pattern table flagged itself: {flagged}"


def test_security_patterns_still_catch_real_calls():
    """The counterpart: an actual call is still reported."""
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert [i for i in issues if "shell" in i.get("description", "").lower()], "missed"


def test_own_source_has_no_high_findings():
    """The tool must pass its own gate on its own source."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "sak_guard"
    for path in sorted(root.glob("*.py")):
        issues = scan_solana(path.read_text())["issues"]
        hi = [i for i in issues if i.get("severity") in ("critical", "high")]
        assert not hi, f"{path.name}: {hi}"


# ════════════════════════════════════════════════════════════════════════════
# Sixth-pass findings (SIXTH_PASS_REPORT.md) — F6-H01..H07, F6-M01..M04.
# ════════════════════════════════════════════════════════════════════════════

# ─── F6-H01: token coordinates must use the tokenizer's line convention ────

def test_f6h01_unicode_separator_does_not_hide_a_real_call():
    """A physical U+2028 inside a string made `splitlines()` disagree with the
    tokenizer's row numbering, so a later comment's token blanked an earlier
    executable call."""
    code = ('text="' + chr(0x2028) + '"\n'
            'subprocess.run(cmd,shell=True)\n'
            '# ' + "z" * 60 + "\n")
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert [i for i in issues if "shell" in i.get("description", "").lower()], \
        "the real call was masked away"


def test_f6h01_quoted_call_stays_clean():
    """The counterpart: a quoted fake call is not executable."""
    code = 'text = "subprocess.run(cmd,shell=True)"\n'
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert not [i for i in issues if "shell" in i.get("description", "").lower()]


# ─── F6-H02: a cap protects the value it produces, not its input ───────────

def test_f6h02_unused_min_result_is_not_a_cap():
    """`capped = min(amount, 100)` bounds `capped`, not `amount`."""
    code = ('def pay(amount):\n    capped = min(amount, 100)\n'
            '    return transfer(Pubkey(DEST), amount)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), "an unused cap cleared the original amount"


def test_f6h02_printed_min_result_is_not_a_cap():
    code = ('def pay(amount):\n    print(min(amount, 100))\n'
            '    return transfer(Pubkey(DEST), amount)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), "a printed cap cleared the amount"


def test_f6h02_used_min_result_is_a_cap():
    """The counterpart: sending the capped value is correct."""
    code = ('def pay(amount):\n    capped = min(amount, 100)\n'
            '    return transfer(Pubkey(DEST), capped)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" not in _pats(issues), "a used cap was flagged"


# ─── F6-H03: the check must dominate the sink ─────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("optional outer branch",
     'def pay(amount, on):\n    if on:\n        if amount > 100:\n'
     '            raise ValueError("big")\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
    ("optional predicate",
     'def pay(amount, on):\n    if amount > 100 and on:\n'
     '        raise ValueError("big")\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
    ("swallowed rejection",
     'def pay(amount):\n    try:\n        if amount > 100:\n'
     '            raise ValueError("big")\n    except ValueError:\n'
     '        print("ignored")\n    return transfer(Pubkey(DEST), amount)\n'),
    ("assert has the wrong polarity",
     'def pay(amount):\n    assert amount > 100\n'
     '    return transfer(Pubkey(DEST), amount)\n'),
    ("check in an uncalled helper",
     'def check(amount):\n    if amount > 100:\n        raise ValueError("x")\n'
     'def pay(amount):\n    return transfer(Pubkey(DEST), amount)\n'),
])
def test_f6h03_non_dominating_bound_is_not_a_cap(label, code):
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"{label}: accepted as a cap"


# ─── F6-H04: review must be polar, ordered and scoped ─────────────────────

def test_f6h04_inverted_review_is_not_authorization():
    """`if keys[0] == EXPECTED: raise` rejects the allowed payer and lets every
    other payer through."""
    code = ('from solders.transaction import Transaction\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    if tx.message.account_keys[0] == EXPECTED:\n'
            '        raise ValueError("reject expected payer")\n'
            '    return kp.sign_message(tx.message_data())\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "inverted check counted as review"


def test_f6h04_review_after_signing_does_not_authorize():
    code = ('from solders.transaction import Transaction\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    sig = kp.sign_message(tx.message_data())\n'
            '    if tx.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n    return sig\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "a later check authorized an earlier signature"


def test_f6h04_uncalled_helper_does_not_review():
    code = ('from solders.transaction import Transaction\n'
            'def verify_payer(tx):\n    if tx.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    return kp.sign_message(tx.message_data())\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "an uncalled helper reviewed the caller"


# ─── F6-H05: a handled exception is a normal exit ─────────────────────────

def test_f6h05_handled_exception_does_not_skip_later_sinks():
    """The handler consumes the exception, so execution continues after the try."""
    code = ('def pay():\n    x = llm.complete(p)\n    try:\n'
            '        raise ValueError("recoverable")\n    except ValueError:\n'
            '        print("recovered")\n    return transfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "the post-handler sink was skipped"


def test_f6h05_implicit_exception_reaches_the_handler():
    """A call can raise at any point, so the handler must see the state there."""
    code = ('def pay():\n    x = TRUSTED\n    try:\n        x = llm.complete(p)\n'
            '        risky_call()\n    except ValueError:\n'
            '        return transfer(Pubkey(x), 1)\n    return None\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "handler started from trusted entry state"


# ─── F6-H06: branch and loop exits ────────────────────────────────────────

def test_f6h06_conditional_break_carries_unsafe_state():
    code = ('def pay(flag):\n    x = TRUSTED\n    for i in range(1):\n'
            '        if flag:\n            x = llm.complete(p)\n            break\n'
            '    return transfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "conditional break state was dropped"


def test_f6h06_loop_else_is_interpreted():
    code = ('def pay():\n    x = llm.complete(p)\n    for i in []:\n        print(i)\n'
            '    else:\n        transfer(Pubkey(x), 1)\n    return None\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "loop else was never walked"


def test_f6h06_possible_loop_return_keeps_zero_iteration_path():
    code = ('def pay():\n    x = llm.complete(p)\n    for i in []:\n        return None\n'
            '    return transfer(Pubkey(x), 1)\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-3" in _pats(issues), "zero-iteration path was suppressed"


# ─── F6-H07: key origins are scoped and captured at bind time ─────────────

def test_f6h07_local_import_does_not_shadow_module_binding():
    code = ('from solders.keypair import Keypair as C\n\n'
            'def unused():\n    from solders.pubkey import Pubkey as C\n    return C\n\n'
            'C.from_base58_string('
            '"1111111111111111111111111111111111111111111111111111111111111111")\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "a function-local import shadowed the module binding"


def test_f6h07_alias_captures_its_binding():
    """`Alias = Keypair` keeps the original class after `Keypair` is rebound."""
    code = ('from solders.keypair import Keypair\nAlias = Keypair\n'
            'from solders.pubkey import Pubkey as Keypair\n'
            'Alias.from_base58_string('
            '"1111111111111111111111111111111111111111111111111111111111111111")\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "the alias was resolved at call time"


def test_f6h07_wrapper_classified_by_its_returned_value():
    """A wrapper that makes an incidental public call and returns a private key
    is private."""
    code = ('from solders.keypair import Keypair\nfrom solders.pubkey import Pubkey\n'
            'class Vault:\n    @classmethod\n    def load(cls, text):\n'
            '        Pubkey.from_string(text)\n        return Keypair.from_string(text)\n'
            'Vault.load("4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw8")\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-1a" in _pats(issues), "wrapper classified by an incidental call"


# ─── F6-M01: a called review helper is enforcement ───────────────────────

def test_f6m01_called_review_helper_is_accepted():
    """`verify_payer(tx.message)` enforces the same check the rule accepts inline."""
    code = ('from solders.transaction import Transaction\n'
            'def verify_payer(m):\n    if m.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    verify_payer(tx.message)\n'
            '    return kp.sign_message(tx.message_data())\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" not in _pats(issues), "a called review helper was flagged"


def test_f6m01_helper_without_enforcement_is_not_a_review():
    """The summary comes from the body, not the name."""
    code = ('from solders.transaction import Transaction\n'
            'def verify_payer(m):\n    print(m)\n\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    verify_payer(tx.message)\n'
            '    return kp.sign_message(tx.message_data())\n')
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), "a non-enforcing helper counted as review"


# ─── F6-M02: f-string literal text is not executable code ────────────────

def test_f6m02_fstring_literal_is_not_a_call():
    """`f"subprocess.run(cmd,shell=True)"` is text, not a call."""
    code = 'text = f"subprocess.run(cmd,shell=True) # fake"\n'
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert not [i for i in issues if "shell" in i.get("description", "").lower()]


def test_f6m02_real_call_inside_fstring_expression_is_flagged():
    code = 'import subprocess\ntext = f"{subprocess.run(cmd,shell=True)}"\n'
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert [i for i in issues if "shell" in i.get("description", "").lower()], \
        "a real call inside an f-string expression was missed"


# ─── F6-M03: the loop budget must not reject finite ordinary code ────────

def test_f6m03_shift_chain_completes():
    """A 40-link shift inside a one-iteration loop is finite; the 32-pass budget
    used to report a critical analysis error for it."""
    n = 40
    code = "# solana\ndef shift_once():\n"
    code += "    " + "=".join(f"v{i}" for i in range(n + 1)) + "=0\n"
    code += f"    v{n}=llm.complete(p)\n    for i in range(1):\n"
    code += "".join(f"        v{i}=v{i+1}\n" for i in range(n))
    code += "    return v0\n"
    exit_code, data = _run_cli(code)
    assert data is not None, "no JSON output"
    errs = [i for i in data["reports"][0]["issues"]
            if i.get("type") == "analysis_error"]
    assert not errs, f"finite code reported a non-convergence error: {errs}"


# ─── F6-M04: literal values that rules need must come from the AST ───────

def test_f6m04_all_interfaces_binding_is_flagged():
    """Masking string contents hid the literal the bind-to-all rule looks for."""
    issues = run_strategy("security-focused", 'app.run(host="0.0.0.0")\n', "", "python")["issues"]
    assert [i for i in issues if "all interfaces" in i.get("description", "").lower()], \
        "binding to 0.0.0.0 was missed"


def test_f6m04_comment_mentioning_the_address_is_clean():
    code = '# binding to 0.0.0.0 would be bad\napp.run(host="127.0.0.1")\n'
    issues = run_strategy("security-focused", code, "", "python")["issues"]
    assert not [i for i in issues if "all interfaces" in i.get("description", "").lower()]


# ════════════════════════════════════════════════════════════════════════════
# Seventh-pass findings (SEVENTH_PASS_REPORT.md) — F7-H01..H10, F7-M01.
# ════════════════════════════════════════════════════════════════════════════

# ─── F7-H01: a numeric fact must actually limit the value ─────────────────

@pytest.mark.parametrize("label,code", [
    ("self comparison",
     'def pay(a):\n    if a > a:\n        raise ValueError("big")\n'
     '    return transfer(Pubkey(DEST), a)\n'),
    ("no-op min",
     'def pay(a):\n    a = min(a, a + 1)\n'
     '    return transfer(Pubkey(DEST), a)\n'),
])
def test_f7h01_no_op_limits_are_not_caps(label, code):
    """A relation the value always satisfies bounds nothing."""
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"{label}: accepted as a cap"


def test_f7h01_real_cap_still_accepted():
    code = 'def pay(a):\n    a = min(a, 100)\n    return transfer(Pubkey(DEST), a)\n'
    assert "PS-SOL-5" not in _pats(scan_solana(code)["issues"])


# ─── F7-H02: provenance and every operand ────────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("parameter alias",
     'def pay(a):\n    value = a\n    return transfer(Pubkey(DEST), value)\n'),
    ("untrusted right operand",
     'def pay(a):\n    return transfer(Pubkey(DEST), 1 + a)\n'),
    ("unbounded multiplier",
     'def pay(a, m):\n    if a > 100:\n        raise ValueError("big")\n'
     '    return transfer(Pubkey(DEST), a * m)\n'),
])
def test_f7h02_amount_expressions(label, code):
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-5" in _pats(issues), f"{label}: evaded"


# ─── F7-H03: helper summaries need polarity, path and await ─────────────

@pytest.mark.parametrize("label,code", [
    ("inverted helper check",
     'from solders.transaction import Transaction\n'
     'def verify(m):\n    if m.account_keys[0] == EXPECTED:\n'
     '        raise ValueError("reject expected")\n'
     'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
     '    verify(tx.message)\n    return kp.sign_message(tx.message_data())\n'),
    ("helper check behind another condition",
     'from solders.transaction import Transaction\n'
     'def verify(m):\n    if ON:\n        if m.account_keys[0] != EXPECTED:\n'
     '            raise ValueError("payer")\n'
     'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
     '    verify(tx.message)\n    return kp.sign_message(tx.message_data())\n'),
    ("unawaited async helper",
     'from solders.transaction import Transaction\n'
     'async def verify(m):\n    if m.account_keys[0] != EXPECTED:\n'
     '        raise ValueError("payer")\n'
     'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
     '    verify(tx.message)\n    return kp.sign_message(tx.message_data())\n'),
])
def test_f7h03_helper_summary_is_not_enforcement(label, code):
    issues = scan_solana(code)["issues"]
    assert "PS-SOL-4" in _pats(issues), f"{label}: counted as review"


# ─── F7-H04: every signed message needs the fact ─────────────────────────

def test_f7h04_one_reviewed_item_does_not_authorize_a_batch():
    code = ('from solders.transaction import Transaction\n'
            'def relay(b1, b2, wallet):\n    tx1 = Transaction.from_bytes(b1)\n'
            '    tx2 = Transaction.from_bytes(b2)\n'
            '    if tx1.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n'
            '    return wallet.sign_all_transactions([tx1, tx2])\n')
    assert "PS-SOL-4" in _pats(scan_solana(code)["issues"])


def test_f7h04_all_messages_reviewed_is_clean():
    code = ('from solders.transaction import Transaction\n'
            'def relay(b1, b2, wallet):\n    tx1 = Transaction.from_bytes(b1)\n'
            '    tx2 = Transaction.from_bytes(b2)\n'
            '    if tx1.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("p")\n'
            '    if tx2.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("p")\n'
            '    return wallet.sign_all_transactions([tx1, tx2])\n')
    assert "PS-SOL-4" not in _pats(scan_solana(code)["issues"])


# ─── F7-H05: a dead expression arm must not change state ────────────────

@pytest.mark.parametrize("label,code", [
    ("dead and-arm",
     'x = llm.complete(p)\ny = False and (x := TRUSTED)\n'
     'transfer(Pubkey(x), 1)\n'),
    ("dead conditional arm",
     'x = llm.complete(p)\ny = (x := x) if True else (x := TRUSTED)\n'
     'transfer(Pubkey(x), 1)\n'),
])
def test_f7h05_dead_expression_branch(label, code):
    assert "PS-SOL-3" in _pats(scan_solana(code)["issues"]), f"{label}: cleared taint"


# ─── F7-H06: finally runs on normal completion ──────────────────────────

def test_f7h06_finally_runs_after_normal_completion():
    code = ('x = llm.complete(p)\ntry:\n    print("work")\nfinally:\n'
            '    transfer(Pubkey(x), 1)\n')
    assert "PS-SOL-3" in _pats(scan_solana(code)["issues"])


# ─── F7-H07: break skips loop else ──────────────────────────────────────

def test_f7h07_break_does_not_run_else():
    code = ('x = TRUSTED\nfor i in range(1):\n    x = llm.complete(p)\n    break\n'
            'else:\n    x = TRUSTED\ntransfer(Pubkey(x), 1)\n')
    assert "PS-SOL-3" in _pats(scan_solana(code)["issues"])


# ─── F7-H08: facts identify the field and the shared object ─────────────

def test_f7h08_checking_one_field_does_not_authorize_another():
    code = ('plan = json.loads(llm.complete(p))\n'
            'if plan["recipient"] not in ALLOWED:\n    raise ValueError("r")\n'
            'transfer(Pubkey(plan["other_recipient"]), 1)\n')
    assert "PS-SOL-3" in _pats(scan_solana(code)["issues"])


def test_f7h08_mutation_through_an_alias_invalidates():
    code = ('x = llm.complete(p)\nif x not in ALLOWED:\n    raise ValueError("r")\n'
            'box = {"recipient": x}\nother = box\n'
            'other["recipient"] = llm.complete(q)\n'
            'transfer(Pubkey(box["recipient"]), 1)\n')
    assert "PS-SOL-3" in _pats(scan_solana(code)["issues"])


def test_f7h08_exact_checked_field_is_clean():
    code = ('plan = json.loads(llm.complete(p))\n'
            'if plan["recipient"] not in ALLOWED:\n    raise ValueError("r")\n'
            'transfer(Pubkey(plan["recipient"]), 1)\n')
    assert "PS-SOL-3" not in _pats(scan_solana(code)["issues"])


# ─── F7-H09: addition chains must stay linear ───────────────────────────

def test_f7h09_addition_chain_is_linear():
    """Flattening every Add node re-walked the same subtree, so a long chain cost
    O(n^2): 8,000 terms (16 KB) exceeded ten seconds.

    Only run where the parser can build the tree. CPython before 3.12 raises
    RecursionError during AST construction for a chain this deep, so on those
    versions the quadratic path is unreachable and the property cannot be
    measured. `test_f7h09_oversized_chain_never_reports_clean` covers what the
    tool must do on those versions instead.
    """
    import sys
    import time

    if sys.version_info < (3, 12):
        pytest.skip("CPython <3.12 cannot parse a chain this deep")

    code = "value=" + "+".join(["1"] * 8000) + "\n"
    t0 = time.monotonic()
    analyze_patterns(code, "python")
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, f"addition chain is still quadratic ({elapsed:.1f}s)"


def test_f7h09_oversized_chain_never_reports_clean():
    """A chain deep enough to defeat the parser must fail closed.

    CPython 3.11 raises RecursionError during AST construction well before 3.12+
    does, so this input is a clean scan on some versions and a parse failure on
    others. Either is acceptable. A traceback, or a passing verdict from an
    analysis that never completed, is not.
    """
    import subprocess
    import sys

    code = "value=" + "+".join(["1"] * 8000) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "sak_guard.cli", "-", "--fail-on", "never"],
        input=code, capture_output=True, text=True, timeout=120,
    )
    assert "Traceback" not in proc.stderr, f"uncaught exception:\n{proc.stderr}"
    assert proc.returncode in (0, 2), f"unexpected exit {proc.returncode}"
    if proc.returncode == 2:
        assert "analysis_error" in proc.stdout, "parse failure was not reported as analysis_error"



# ─── F7-H10: a disabled bound through a name ────────────────────────────

@pytest.mark.parametrize("label,code", [
    ("aliased zero", 'minimum = 0\nswap(POOL, 100, min_amount_out=minimum)\n'),
    ("aliased None", 'minimum = None\nswap(POOL, 100, min_amount_out=minimum)\n'),
])
def test_f7h10_disabled_bound_through_alias(label, code):
    code = "from jupiter_python_sdk.jupiter import Jupiter\nswap = Jupiter.swap\n" + code
    assert "PS-SOL-5" in _pats(scan_solana(code)["issues"]), f"{label}: accepted"


# ─── F7-M01: legitimate review facts are preserved ──────────────────────

def test_f7m01_keyword_review_helper():
    code = ('from solders.transaction import Transaction\n'
            'def verify(message):\n    if message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    verify(message=tx.message)\n'
            '    return kp.sign_message(tx.message_data())\n')
    assert "PS-SOL-4" not in _pats(scan_solana(code)["issues"])


def test_f7m01_awaited_review_helper():
    code = ('from solders.transaction import Transaction\n'
            'async def verify(m):\n    if m.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n'
            'async def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    await verify(tx.message)\n'
            '    return kp.sign_message(tx.message_data())\n')
    assert "PS-SOL-4" not in _pats(scan_solana(code)["issues"])


def test_f7m01_alias_of_a_reviewed_transaction():
    code = ('from solders.transaction import Transaction\n'
            'def relay(blob, kp):\n    tx = Transaction.from_bytes(blob)\n'
            '    if tx.message.account_keys[0] != EXPECTED:\n'
            '        raise ValueError("payer")\n    alias = tx\n'
            '    return kp.sign_message(alias.message_data())\n')
    assert "PS-SOL-4" not in _pats(scan_solana(code)["issues"])
