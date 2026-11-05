"""One runnable check. No framework -- plain asserts, run with `python3 tests/test_cli.py`.

Asserts the two directions that matter: the mock-vulnerable fixture must be FLAGGED
including shell injection, and the clean fixture must PASS. A linter that cannot fail
on known-bad input is worse than no linter.
"""
import subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


def run(target, *extra):
    return subprocess.run([sys.executable, "-m", "sak_guard.cli", str(target), *extra],
                          capture_output=True, text=True, cwd=HERE.parent)


def main():
    r = run(FIX / "vulnerable_api.py")
    assert r.returncode == 1, f"vulnerable fixture must exit 1, got {r.returncode}"
    for needle in ("Hardcoded secret", "eval()", "shell=True"):
        assert needle in r.stdout, f"missed {needle!r} in output:\n{r.stdout}"
    print("  ok  vulnerable fixture: 3 findings incl. shell injection, exit 1")

    r = run(FIX / "clean_api.py")
    assert r.returncode == 0, f"clean fixture must exit 0, got {r.returncode}\n{r.stdout}"
    assert "clean" in r.stdout.lower()
    print("  ok  clean fixture: no findings, exit 0")

    r = run(FIX / "vulnerable_api.py", "--fail-on", "never")
    assert r.returncode == 0, "--fail-on never must never fail the build"
    print("  ok  --fail-on never: reports but passes")

    r = subprocess.run([sys.executable, "-m", "sak_guard.cli", "-"],
                       input='import os\nos.system("rm -rf " + input())\n',
                       capture_output=True, text=True, cwd=HERE.parent)
    assert r.returncode == 1 and "os.system" in r.stdout, "stdin os.system must be caught"
    print("  ok  stdin pipe: os.system caught, exit 1")

    print("\n  all checks passed")


if __name__ == "__main__":
    main()
