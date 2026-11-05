#!/usr/bin/env python3
"""sec-audit -- the ALM verification core as a standalone local auditor.

The engine (AST parsing, security regex banks, optional LLM intent check) was
originally only reachable through an HTTP worker transport, which meant using it
required running a server and POSTing to it. This is the same engine as a plain
CLI: no HTTP, no server, no registration.

    ./sec-audit path/to/file.py                 # audit a file
    ./sec-audit src/ --fail-on low              # a tree
    git diff -U0 | ./sec-audit -                # stdin
    ./sec-audit f.py --json                     # machine-readable

Exit status: 0 clean (or below --fail-on), 1 findings at/above --fail-on,
2 usage/IO error. Suitable as a pre-commit hook.

The optional LLM intent pass is off unless --use-llm is given, and it reads its
provider settings from the environment (LLM_PROVIDER / LLM_MODEL / LLM_API_KEY /
LLM_BASE_URL), so no credentials are baked in here.

ponytail: one file, stdlib argparse, no config format. The engine decides
severity; this only filters and reports. Add a config file when someone needs
per-directory thresholds -- not before.
"""
import argparse
import json
import sys
from pathlib import Path


from .analyzer import analyze_code
from .strategies import run_strategy

# The base analyze_code() bank covers secrets and eval() but NOT shell injection;
# that lives in the security-focused strategy's extra patterns (subprocess
# shell=True, os.system). A security auditor should default to the bank that
# actually looks for command injection.
STRATEGIES = ("default", "security-focused", "ast-heavy", "intent-focused")

SEV_RANK = {"critical": -1, "high": 0, "medium": 1, "low": 2, "info": 3, "unknown": 4}
FAIL_AT = {"critical": -1, "high": 0, "medium": 1, "low": 2, "any": 4, "never": -2}
PY_EXT = {".py"}
FILLER = ("__pycache__", ".venv", "venv", ".git", "node_modules", "build", "dist")


def iter_targets(paths):
    """Expand files/dirs, skipping vendored and bytecode trees."""
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*.py")):
                if not any(part in FILLER for part in f.parts):
                    yield f
        else:
            print(f"sec-audit: no such path: {raw}", file=sys.stderr)


def audit(code, intent, language, use_llm, strategy="security-focused"):
    """Call the engine. Returns (issues, confidence, passed)."""
    if strategy == "default":
        r = analyze_code(code=code, intent=intent, language=language, use_llm=use_llm)
    else:
        r = run_strategy(strategy, code, intent, language)
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
        prog="sec-audit",
        description="Standalone security/intent audit of source files (no server).",
    )
    ap.add_argument("paths", nargs="*", help="files or dirs; '-' reads stdin")
    ap.add_argument("--intent", default="",
                    help="natural-language description the code should satisfy")
    ap.add_argument("--language", default="python")
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
        issues, conf, passed = audit(code, a.intent, a.language, a.use_llm, a.strategy)
        total += len(issues)
        for i in issues:
            worst = min(worst, SEV_RANK.get(str(i.get("severity", "")).lower(), 4))
        reports.append({"target": label, "issues": issues,
                        "confidence": conf, "passed": passed})

    if "-" in a.paths:
        run("<stdin>", sys.stdin.read())
        a.paths = [p for p in a.paths if p != "-"]

    for f in iter_targets(a.paths):
        if a.language == "python" and f.suffix not in PY_EXT:
            continue
        try:
            run(str(f), f.read_text(encoding="utf-8", errors="replace"))
        except OSError as e:
            print(f"sec-audit: cannot read {f}: {e}", file=sys.stderr)
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

    return 1 if worst <= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
