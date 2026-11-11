#!/usr/bin/env python3
"""sak-guard -- static security and intent audit for Solana agent code.

The engine (AST parsing, a security regex bank, and an optional LLM
intent-mismatch pass) is stdlib-only and runs as a plain local command: no HTTP,
no server, no account.

    sak-guard path/to/file.py               # audit a file
    sak-guard src/ --fail-on low            # a tree
    cat transaction_client.py | sak-guard -  # Python source on stdin
    sak-guard f.py --json                   # machine-readable

Exit status: 0 clean (or below --fail-on), 1 findings at/above --fail-on,
2 usage/IO/incomplete-analysis error. Suitable as a pre-commit hook and in CI.

The optional LLM intent pass is off unless --use-llm is given, and it reads its
provider settings from the environment (LLM_PROVIDER / LLM_MODEL / LLM_API_KEY /
LLM_BASE_URL), so no credentials are baked in here.

Scope: Python client and agent code -- the layer where agents hold keys and build
transactions. On-chain Rust programs are covered by the program linters.

Design note: one file, stdlib argparse, no config format. The engine decides
severity; this only filters and reports.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


from .limits import MAX_SOURCE_BYTES, failure

# The base analyze_code() bank covers secrets and eval() but NOT shell injection;
# that lives in the security-focused strategy's extra patterns (subprocess
# shell=True, os.system). A security auditor should default to the bank that
# actually looks for command injection.
STRATEGIES = ("default", "security-focused", "ast-heavy", "intent-focused")

# Analysis is bounded on purpose: a commit hook must not run indefinitely on a
# generated or vendored file, and an unbounded read is also an unbounded memory
# commitment. 4 MiB is far beyond any hand-written module.
ANALYSIS_TIMEOUT_SECONDS = 15


class SourceTooLarge(Exception):
    """Raised when an input exceeds MAX_SOURCE_BYTES."""

    def __init__(self, label: str, size: int):
        super().__init__(
            f"{label}: source is {size} bytes, over the {MAX_SOURCE_BYTES}-byte "
            "analysis limit"
        )
        self.label = label
        self.size = size

PROG = "sak-guard"

SEV_RANK = {"critical": -1, "high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}
FAIL_AT = {"critical": -1, "high": 0, "medium": 1, "low": 2, "any": 4, "never": -2}
PY_EXT = {".py"}
FILLER = ("__pycache__", ".venv", "venv", ".git", "node_modules", "build", "dist")


class BadPath(Exception):
    """A path argument did not exist. Carries the offending raw path."""


def iter_targets(paths):
    """Expand files/dirs, skipping vendored and bytecode trees.

    Raises BadPath for a path that is neither a file nor a directory. The previous
    version only printed a warning and yielded nothing, so the run ended with no
    findings and exited 0 -- a typo'd path reported SUCCESS. That is the worst
    possible failure for a pre-commit hook: the guard reports "clean" on a repo it
    never read. The README documents exit 2 for a usage/IO error, and this is it.
    """
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*.py")):
                if not any(part in FILLER for part in f.parts):
                    yield f
        else:
            raise BadPath(raw)


def audit(code, intent, language, use_llm, strategy="security-focused"):
    """Call the engine. Returns (issues, confidence, passed)."""
    request = {"strategy": strategy, "code": code, "intent": intent,
               "language": language, "use_llm": use_llm}
    try:
        # -I prevents a scanned checkout's sak_guard.py, sitecustomize.py or
        # PYTHONPATH from replacing our worker. Pin the parent package location.
        bootstrap = "import runpy,sys; sys.path.insert(0,sys.argv[1]); runpy.run_module('sak_guard.worker',run_name='__main__')"
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", bootstrap,
                               str(Path(__file__).resolve().parent.parent)],
                              input=json.dumps(request), text=True,
                              encoding="utf-8", capture_output=True,
                              timeout=60 if use_llm else ANALYSIS_TIMEOUT_SECONDS)
        if proc.returncode:
            r = failure(f"analysis worker exited {proc.returncode}")
        else:
            r = json.loads(proc.stdout)
            if not isinstance(r, dict) or not isinstance(r.get("issues"), list):
                r = failure("analysis worker returned an invalid report schema")
    except subprocess.TimeoutExpired:
        r = failure("analysis worker exceeded its time budget")
    except (OSError, ValueError):
        r = failure("analysis worker failed to return a valid report")
    return r.get("issues") or [], r.get("confidence"), r.get("passed")


def fmt_issue(i):
    sev = str(i.get("severity", "unknown")).lower()
    line = i.get("line")
    where = f":{line}" if line else ""
    kind = i.get("type") or i.get("category") or "issue"
    desc = i.get("description") or i.get("message") or ""
    sug = i.get("suggestion")
    out = f"  [{sev}]{where} {kind}: {desc}"
    if sug:
        out += f"\n      fix: {sug}"
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Static security and intent audit for Solana agent code "
                    "(no server, no runtime dependency).",
    )
    ap.add_argument("paths", nargs="*", help="files or dirs; '-' reads stdin")
    ap.add_argument("--intent", default="",
                    help="natural-language description the code should satisfy")
    ap.add_argument("--language", default="python", choices=["python"],
                    help="source language (only python is analysed)")
    ap.add_argument("--strategy", default="security-focused", choices=STRATEGIES,
                    help="analysis strategy (default: security-focused)")
    ap.add_argument("--use-llm", action="store_true",
                    help="enable the optional LLM intent pass (needs LLM_* env)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=sorted(FAIL_AT),
                    help="exit non-zero at/above this severity (default: high)")
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    a = ap.parse_args(argv)

    if not a.paths:
        ap.error("give at least one path, or '-' for stdin")

    threshold = FAIL_AT[a.fail_on]
    reports, worst, total = [], 99, 0

    def run(label, code):
        nonlocal worst, total
        # Bound the work. Analysis is linear now, but an unbounded input is still
        # an unbounded commit hook, and a caller should be told rather than wait
        # (SG-19).
        if len(code) > MAX_SOURCE_BYTES:
            raise SourceTooLarge(label, len(code))
        issues, conf, passed = audit(code, a.intent, a.language, a.use_llm, a.strategy)
        total += len(issues)
        for i in issues:
            worst = min(worst, SEV_RANK.get(str(i.get("severity", "")).lower(), 4))
        reports.append({"target": label, "issues": issues,
                        "confidence": conf, "passed": passed})

    scanned = 0
    if "-" in a.paths:
        try:
            stream = getattr(sys.stdin, "buffer", None)
            if stream is not None:
                raw = stream.read(MAX_SOURCE_BYTES + 1)
                if len(raw) > MAX_SOURCE_BYTES:
                    raise SourceTooLarge("<stdin>", len(raw))
                code = raw.decode("utf-8")
            else:
                code = sys.stdin.read(MAX_SOURCE_BYTES + 1)
                if len(code.encode("utf-8")) > MAX_SOURCE_BYTES:
                    raise SourceTooLarge("<stdin>", len(code.encode("utf-8")))
            run("<stdin>", code)
            scanned += 1
        except (SourceTooLarge, OSError, UnicodeError) as e:
            print(f"{PROG}: {e}", file=sys.stderr)
            return 2
        a.paths = [p for p in a.paths if p != "-"]

    try:
        targets = list(iter_targets(a.paths))
    except BadPath as e:
        print(f"{PROG}: no such path: {e}", file=sys.stderr)
        return 2

    for f in targets:
        # An explicitly named file is scanned whatever its suffix; only
        # directory discovery filters by extension. Silently skipping a file the
        # caller asked for reported "clean" for code that was never read (SG-18).
        try:
            with f.open("rb") as source:
                raw = source.read(MAX_SOURCE_BYTES + 1)
            if len(raw) > MAX_SOURCE_BYTES:
                raise SourceTooLarge(str(f), len(raw))
            run(str(f), raw.decode("utf-8"))
            scanned += 1
        except SourceTooLarge as e:
            print(f"{PROG}: {e}", file=sys.stderr)
            return 2
        except (OSError, UnicodeError) as e:
            print(f"{PROG}: cannot read {f}: {e}", file=sys.stderr)
            return 2

    if scanned == 0:
        print(f"{PROG}: no analysable targets were found", file=sys.stderr)
        return 2

    if a.json:
        print(json.dumps({"reports": reports, "total_issues": total,
                          "worst_severity": [k for k, v in SEV_RANK.items() if v == worst][0]
                          if worst != 99 else None,
                          "fail_on": a.fail_on}, indent=2))
    else:
        for r in reports:
            if not r["issues"]:
                if not a.quiet:
                    print(f"{r['target']}: clean")
                continue
            print(f"{r['target']}: {len(r['issues'])} issue(s)"
                  f" (confidence {r['confidence']})")
            for i in sorted(r["issues"],
                            key=lambda x: SEV_RANK.get(str(x.get("severity", "")).lower(), 4)):
                print(fmt_issue(i))
        if not a.quiet:
            print(f"\n{total} issue(s) across {len(reports)} target(s); "
                  f"fail-on={a.fail_on}")

    if any(i.get("type") == "analysis_error" for r in reports for i in r["issues"]):
        return 2
    return 1 if worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
