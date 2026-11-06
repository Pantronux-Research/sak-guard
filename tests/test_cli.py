"""sak-guard test suite.

Runs under pytest (`python -m pytest -v tests/`) and standalone
(`python3 tests/test_cli.py`) so the checks are usable without installing pytest.

Everything here asserts on the SUBPROCESS EXIT CODE, not on internals. The contract
this tool sells is an exit status a CI job can branch on, so that is what gets tested.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"


def run(target, *extra):
    """Invoke the CLI as a subprocess, the way CI and pre-commit do."""
    return subprocess.run(
        [sys.executable, "-m", "sak_guard.cli", str(target), *extra],
        capture_output=True, text=True, cwd=REPO,
    )


def run_stdin(source, *extra):
    return subprocess.run(
        [sys.executable, "-m", "sak_guard.cli", "-", *extra],
        input=source, capture_output=True, text=True, cwd=REPO,
    )


def test_vulnerable_fixture_is_flagged():
    """A linter that cannot fail on known-bad input is worse than no linter."""
    r = run(FIXTURES / "vulnerable_api.py")
    assert r.returncode == 1, f"expected exit 1, got {r.returncode}\n{r.stdout}"
    assert "Hardcoded secret" in r.stdout
    assert "eval()" in r.stdout


def test_shell_injection_detected_by_default_strategy():
    """Regression guard for the defect that made --strategy default the wrong default.

    The base analyzer bank contains no os.system / shell=True pattern at all, so a
    CLI defaulting to it reports CLEAN on subprocess(shell=True). This asserts the
    shipped default actually catches it.
    """
    r = run(FIXTURES / "vulnerable_api.py")
    assert "shell=True" in r.stdout, (
        "shell injection not reported by the default strategy -- the default has "
        "regressed to the base bank, which does not look for it"
    )
    assert r.returncode == 1


def test_clean_fixture_passes():
    r = run(FIXTURES / "clean_api.py")
    assert r.returncode == 0, f"expected exit 0, got {r.returncode}\n{r.stdout}"


def test_stdin_pipe_os_system():
    r = run_stdin('import os\nos.system("rm -rf " + input())\n')
    assert r.returncode == 1
    assert "os.system" in r.stdout


def test_fail_on_never_reports_but_passes():
    r = run(FIXTURES / "vulnerable_api.py", "--fail-on", "never")
    assert r.returncode == 0, "--fail-on never must never fail the build"
    assert "Hardcoded secret" in r.stdout, "still expected to REPORT the findings"


@pytest.mark.parametrize("threshold,expected", [
    ("critical", 1), ("high", 1), ("medium", 1), ("low", 1), ("any", 1),
])
def test_exit_code_matrix_on_vulnerable_input(threshold, expected):
    """Every threshold below `never` must fail on known-vulnerable input.

    A severity table missing "critical" once fell through to an "unknown" fallback and
    let vulnerable input exit 0. This matrix is the guard.
    """
    r = run(FIXTURES / "vulnerable_api.py", "--fail-on", threshold)
    assert r.returncode == expected


def test_clean_fixture_passes_every_threshold():
    for threshold in ("critical", "high", "medium", "low", "any"):
        r = run(FIXTURES / "clean_api.py", "--fail-on", threshold)
        assert r.returncode == 0, f"clean input failed at --fail-on {threshold}"


def test_json_output_is_valid_json():
    import json
    r = run(FIXTURES / "vulnerable_api.py", "--json")
    payload = json.loads(r.stdout)
    assert payload["total_issues"] >= 3
    assert payload["worst_severity"] == "critical"


def test_fixtures_carry_no_local_or_network_dependency():
    """The corpus must audit the same way on a reviewer's machine as on ours.

    A fixture referencing an absolute path, an internal host, or a URL would make the
    suite environment-dependent and quietly unportable.
    """
    import re
    bad = re.compile(r"192\.168\.|10\.\d+\.\d+\.|100\.\d+\.\d+\.|/home/|/tmp/"
                     r"|localhost|127\.0\.0\.1|https?://")
    # The *_solana_* fixtures deliberately contain an RPC endpoint and key-shaped
    # strings: that is the CONTENT under audit, not a dependency of this test run.
    # Excluded by name so the rule keeps its teeth for every other fixture.
    for f in FIXTURES.glob("*.py"):
        if "_solana_" in f.name:
            continue
        text = f.read_text()
        assert not bad.search(text), f"{f.name} contains an environment-specific reference"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "--no-header",
                          "-p", "no:cacheprovider"]))
