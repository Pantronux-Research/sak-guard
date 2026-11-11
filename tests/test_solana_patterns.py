"""Milestone 2 acceptance: the Solana pattern bank matrix.

This is the test the grant is judged on. Every cell matters, including the `clear`
ones: a pattern that fires on a clean fixture is a false-positive generator, and a
security tool that cries wolf gets switched off.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sak_guard.solana import scan_solana, PATTERNS  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent

# (fixture, {pattern: expected verdict})
MATRIX = {
    "vulnerable_solana_keys.py": {"PS-SOL-1": "found"},
    "clean_solana_keys.py":      {"PS-SOL-1": "clear", "PS-SOL-3": "clear"},
    "vulnerable_solana_rpc.py":  {"PS-SOL-2": "found"},
    "clean_solana_rpc.py":       {"PS-SOL-2": "clear", "PS-SOL-3": "clear"},
    "vulnerable_solana_llm.py":  {"PS-SOL-3": "found"},
    "clean_solana_llm.py":       {"PS-SOL-3": "clear", "PS-SOL-2": "clear"},
    # SG-10: signer / message integrity.
    "vulnerable_solana_signing.py": {"PS-SOL-4": "found"},
    "clean_solana_signing.py":      {"PS-SOL-4": "clear"},
    # SG-11: amount bounds and slippage.
    "vulnerable_solana_amounts.py": {"PS-SOL-5": "found"},
    "clean_solana_amounts.py":      {"PS-SOL-5": "clear"},
}


def _scan(name):
    return scan_solana((FIXTURES / name).read_text())


@pytest.mark.parametrize("fixture,expect", sorted(MATRIX.items()))
def test_fixture_matrix(fixture, expect):
    verdicts = _scan(fixture)["patterns"]
    for pid, want in expect.items():
        assert verdicts.get(pid) == want, (
            f"{fixture}: {pid} expected {want}, got {verdicts.get(pid)}"
        )


def test_clean_fixtures_produce_no_findings_at_all():
    """Stronger than the matrix: a clean fixture must be globally silent."""
    for name in ("clean_solana_keys.py", "clean_solana_rpc.py", "clean_solana_llm.py"):
        issues = _scan(name)["issues"]
        assert not issues, f"{name} is expected clean but flagged: " \
                           f"{sorted({i['pattern'] for i in issues})}"


def test_every_pattern_reports_a_verdict():
    """No pattern may be silent -- 'clear' and 'never ran' must be distinguishable."""
    for name in MATRIX:
        verdicts = _scan(name)["patterns"]
        for pid, _desc, _fn in PATTERNS:
            assert pid in verdicts, f"{name}: {pid} emitted no verdict"


def test_non_solana_input_is_n_a_not_clear():
    """Generic Python must be 'n/a', never a clean Solana verdict."""
    verdicts = scan_solana("import os\nx = 1\n")["patterns"]
    assert set(verdicts.values()) == {"n/a"}, verdicts


def test_pattern_registry_never_crashes_the_scan():
    """A malformed file must not take down the run."""
    r = scan_solana("def broken(:\n")
    assert "syntax_error" in r
    assert r["issues"] == []


def test_cli_flags_solana_findings_end_to_end():
    """The wiring works: a Solana vuln exits 1 through the real CLI."""
    r = subprocess.run(
        [sys.executable, "-m", "sak_guard.cli",
         str(FIXTURES / "vulnerable_solana_keys.py")],
        capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 1, r.stdout
    assert "PS-SOL-1" in r.stdout or "key material" in r.stdout.lower()


def test_cli_passes_clean_solana_fixture():
    r = subprocess.run(
        [sys.executable, "-m", "sak_guard.cli",
         str(FIXTURES / "clean_solana_keys.py")],
        capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stdout


# --- regression: the base-bank division rule must not read `/` inside strings ---
DIV_CASES_MUST_FIRE = [
    "def f(a, b):\n    return a / b\n",
    "x = total / count\n",
]
DIV_CASES_MUST_BE_CLEAN = [
    'client = Client("https://api.mainnet-beta.solana.com")\n',   # the original bug
    'p = "a/b/c"\n',
    'r = re.compile(r"^/api/v1")\n',
    "x = total / 2\n",                                            # literal divisor
]


def _div_hits(src):
    from sak_guard.analyzer import analyze_patterns
    return [i for i in analyze_patterns(src, "python")
            if "Division" in i.get("description", "")]


@pytest.mark.parametrize("src", DIV_CASES_MUST_FIRE)
def test_real_division_still_flagged(src):
    assert _div_hits(src), f"real division no longer detected: {src!r}"


@pytest.mark.parametrize("src", DIV_CASES_MUST_BE_CLEAN)
def test_slash_inside_string_is_not_division(src):
    """Regression: a `/` in a URL, path or regex is not the division operator.

    The rule used to scan raw source lines, so `Client("https://api...")` was reported
    as "Division by variable without zero-check" because `/api` matched. It is now gated
    on ast.BinOp(ast.Div).
    """
    assert not _div_hits(src), f"false positive on a string literal: {src!r}"


def test_clean_solana_fixtures_have_zero_findings():
    """The medium warning must be gone from every clean Solana fixture."""
    for name in ("clean_solana_keys.py", "clean_solana_rpc.py", "clean_solana_llm.py"):
        r = subprocess.run(
            [sys.executable, "-m", "sak_guard.cli", str(FIXTURES / name)],
            capture_output=True, text=True, cwd=REPO)
        assert r.returncode == 0, f"{name}: exit {r.returncode}\n{r.stdout}"
        assert "Division" not in r.stdout, f"{name} still reports a division warning:\n{r.stdout}"
