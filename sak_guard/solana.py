"""Solana pattern bank -- the detection rules that make sak-guard a Solana tool.

Scope, stated honestly: this inspects **Python client and agent code**, not on-chain Rust
programs. Programs are covered by Trail of Bits' solana-lints and the Anchor/native
scanners; the Python layer where agents hold keys and build transactions is not covered
by anything, and that is what this module is for.

Design rules (see docs/SOLANA_PATTERN_BANK_SPEC.md):
  - never execute or import the code under audit -- AST and regex only
  - prefer AST where the distinction is structural
  - every pattern has a positive and a negative fixture
  - every registered pattern emits a verdict (`found` / `clear` / `n/a`), so a clean
    result is distinguishable from a pattern that never ran
  - severity is honest; heuristics are medium, not critical

Ids are stable and cited by fixtures and the verification report.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional

# --- names whose value is key material ---------------------------------------
KEY_NAMES = re.compile(r"(secret|priv|private|seed|mnemonic|keypair|skey|key)\b", re.I)
# --- names whose value plausibly came from a model ---------------------------
LLM_NAMES = re.compile(
    r"(llm|model|openai|anthropic|complet|chat|agent|gpt|claude|gemini|ollama|"
    r"response|reply|answer|plan|suggestion|proposal|infer|prompt)", re.I,
)
# --- calls that submit a transaction -----------------------------------------
SEND_CALLS = re.compile(r"(send_transaction|send_raw_transaction|send_and_confirm|"
                        r"sendTransaction|sign_and_send)", re.I)
SIMULATE_CALLS = re.compile(r"(simulate_transaction|simulateTransaction)", re.I)
CONFIRM_CALLS = re.compile(r"(confirm_transaction|get_signature_statuses|"
                           r"confirmTransaction|await_confirmation)", re.I)
BLOCKHASH_CALLS = re.compile(r"(get_latest_blockhash|get_recent_blockhash|"
                             r"getLatestBlockhash)", re.I)
# --- calls that consume untrusted input as an address or amount --------------
SINK_CALLS = re.compile(r"(Pubkey|PublicKey|transfer|transfer_checked|Instruction|"
                        r"create_transfer_transaction|to_pubkey)", re.I)
# --- things that make a blockhash go stale ------------------------------------
SLOW_CALLS = re.compile(r"(complete|create|chat|generate|invoke|request|send|recv|"
                        r"sleep|wait|call_model|run_agent)", re.I)


def _is_literal(node: ast.AST) -> bool:
    """A constant, or a container/join of constants -- i.e. material in the source."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return bool(node.elts) and all(isinstance(e, ast.Constant) and
                                       isinstance(e.value, (int, bytes))
                                       for e in node.elts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("join", "format", "encode"):
            return bool(node.args) and all(_is_literal(a) for a in node.args)
    if isinstance(node, ast.JoinedStr):                     # f-string
        return any(_is_literal(v) for v in node.values
                   if isinstance(v, ast.Constant))
    return False


def _names(node: ast.AST) -> set:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    return getattr(f, "id", "")


def _kwarg(node: ast.Call, name: str):
    for k in node.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_64_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and _call_name(node) == "bytes" and node.args:
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and arg.value == 64:
            return True
    if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) == 64:
        return all(isinstance(e, ast.Constant) for e in node.elts)
    return False


# ---------------------------------------------------------------------------
# PS-SOL-1 -- unsafe key material handling
# ---------------------------------------------------------------------------
KEY_LOADERS = re.compile(r"(from_base58_string|from_seed|from_string|from_bytes|"
                         r"b58decode|from_private_key|Keypair|keypair_from_seed)", re.I)


def ps_sol_1(tree: ast.AST, source: str) -> List[Dict]:
    """Literal key material: in source, or reaching a log line."""
    out: List[Dict] = []

    for node in ast.walk(tree):
        # 1a / 1e -- a loader called with a literal, or a 64-element literal
        if isinstance(node, ast.Call) and KEY_LOADERS.search(_call_name(node)):
            for a in list(node.args) + [k.value for k in node.keywords]:
                if _is_literal(a) or _is_64_constant(a):
                    out.append({
                        "type": "solana",
                        "severity": "critical",
                        "pattern": "PS-SOL-1a",
                        "line": getattr(node, "lineno", 0),
                        "description": "Key material passed to "
                                       f"{_call_name(node)}() as a literal in source",
                        "suggestion": "Load from a secret manager, or a file with "
                                      "tightened permissions. Never inline a key.",
                    })
                    break

        # 1b -- a mnemonic-shaped string literal
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            words = node.value.split()
            if len(words) in (12, 24) and all(w.isalpha() and w.islower()
                                              for w in words):
                out.append({
                    "type": "solana",
                    "severity": "critical",
                    "pattern": "PS-SOL-1b",
                    "line": getattr(node, "lineno", 0),
                    "description": f"A {len(words)}-word mnemonic appears as a literal",
                    "suggestion": "Never embed a recovery phrase. Read it from secure "
                                  "storage at runtime.",
                })

        # 1d -- key-like name interpolated into a log / f-string / format
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    for n in _names(v.value):
                        if KEY_NAMES.search(n):
                            out.append({
                                "type": "solana",
                                "severity": "critical",
                                "pattern": "PS-SOL-1d",
                                "line": getattr(node, "lineno", 0),
                                "description": f"Key-like value '{n}' interpolated "
                                               "into an f-string (likely logged)",
                                "suggestion": "Never log key material. Log an "
                                              "identifier or a fingerprint instead.",
                            })
                            break

    # 1c -- literal base58 decode bound to a key-like name
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if (isinstance(t, ast.Name) and KEY_NAMES.search(t.id)
                        and isinstance(node.value, ast.Call)
                        and _call_name(node.value) == "b58decode"):
                    if node.value.args and _is_literal(node.value.args[0]):
                        out.append({
                            "type": "solana",
                            "severity": "critical",
                            "pattern": "PS-SOL-1c",
                            "line": getattr(node, "lineno", 0),
                            "description": f"base58-decoded literal bound to '{t.id}'",
                            "suggestion": "Read key bytes from secure storage.",
                        })
    return out


# ---------------------------------------------------------------------------
# PS-SOL-2 -- solders / solana-py misuse
# ---------------------------------------------------------------------------
def ps_sol_2(tree: ast.AST, source: str) -> List[Dict]:
    """2a no confirmation, 2b ignored simulation, 2c stale blockhash."""
    out: List[Dict] = []
    all_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    confirm_lines = [getattr(n, "lineno", 0) for n in all_calls
                     if CONFIRM_CALLS.search(_call_name(n))]

    for node in all_calls:
        name = _call_name(node)
        line = getattr(node, "lineno", 0)

        # 2a -- send without a commitment option and without a confirm anywhere after
        if SEND_CALLS.search(name):
            has_commit = any((k.arg or "") in
                             ("commitment", "preflight_commitment", "opts",
                              "confirm", "await_confirmation")
                             for k in node.keywords)
            later_confirm = [c for c in confirm_lines if c >= line]
            if not has_commit and not later_confirm:
                out.append({
                    "type": "solana",
                    "severity": "high",
                    "pattern": "PS-SOL-2a",
                    "line": line,
                    "description": f"{name}() with no commitment and no confirmation "
                                   "call -- success here means submitted, not landed",
                    "suggestion": "Pass a commitment, and confirm the signature "
                                  "(confirm_transaction / get_signature_statuses).",
                })

        # 2b -- simulation result never checked for .err
        if SIMULATE_CALLS.search(name):
            checked = False
            for parent in ast.walk(tree):
                for child in ast.walk(parent):
                    if isinstance(child, ast.Attribute) and child.attr == "err":
                        checked = True
                if checked:
                    break
            if not checked:
                out.append({
                    "type": "solana",
                    "severity": "high",
                    "pattern": "PS-SOL-2b",
                    "line": line,
                    "description": f"{name}() result is never checked for .err -- "
                                   "a failed simulation can still be submitted",
                    "suggestion": "Raise or abort when result.value.err is set.",
                })

    # 2c -- blockhash fetched, then slow work, then send
    bh = [n for n in all_calls if BLOCKHASH_CALLS.search(_call_name(n))]
    sends = [n for n in all_calls if SEND_CALLS.search(_call_name(n))]
    for b in bh:
        bline = getattr(b, "lineno", 0)
        for s in sends:
            sline = getattr(s, "lineno", 0)
            if sline <= bline:
                continue
            between = [c for c in all_calls
                       if bline < getattr(c, "lineno", 0) < sline
                       and SLOW_CALLS.search(_call_name(c))
                       and not BLOCKHASH_CALLS.search(_call_name(c))]
            if between:
                out.append({
                    "type": "solana",
                    "severity": "medium",
                    "pattern": "PS-SOL-2c",
                    "line": sline,
                    "description": "Blockhash fetched at line %d, then %s() at line %d, "
                                   "then send -- blockhashes expire in ~60-90s"
                                   % (bline, _call_name(between[0]),
                                      getattr(between[0], "lineno", 0)),
                    "suggestion": "Refetch the blockhash immediately before signing, or "
                                  "retry on BlockhashNotFound.",
                })
                break

    # de-duplicate (2a/2c can both flag one send line)
    seen, uniq = set(), []
    for i in out:
        k = (i["pattern"], i["line"])
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    return uniq


# ---------------------------------------------------------------------------
# PS-SOL-3 -- model output reaching an address sink
# ---------------------------------------------------------------------------
def _tainted_names(tree: ast.AST) -> set:
    """Names assigned from a model-ish source, plus json.loads of one."""
    tainted = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        # The value is very often a subscript, not a bare call:
        #   dest = json.loads(plan)["recipient"]   -> Subscript(value=Call(json.loads))
        #   plan = llm.complete(prompt)            -> Call
        # Peel subscripts and attribute/call chains down to the originating call, or the
        # most common real shape is invisible.
        src = node.value
        while isinstance(src, (ast.Subscript, ast.Attribute)):
            src = src.value
        if isinstance(src, ast.Call):
            origin = ""
            if isinstance(src.func, ast.Attribute):
                origin = src.func.attr
            elif isinstance(src.func, ast.Name):
                origin = src.func.id
            # json.loads(<model call>)
            inherited = any(isinstance(a, ast.Name) and a.id in tainted
                            for a in src.args)
            if origin in ("loads", "json") or src.func.__class__ is ast.Name:
                for a in src.args:
                    if isinstance(a, ast.Call):
                        origin += " " + _call_name(a)
            # taint propagates: plan = llm.complete(...)  ->  dest = json.loads(plan).x
            if LLM_NAMES.search(origin) or inherited:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
    return tainted


def ps_sol_3(tree: ast.AST, source: str) -> List[Dict]:
    """Model output -> Pubkey / transfer / RPC with no validation in between."""
    out: List[Dict] = []
    tainted = _tainted_names(tree)
    if not tainted:
        return out

    # a name is "validated" if some if/assert/raise uses it before the sink
    validated_lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.Assert)):
            for n in _names(node.test):
                if n in tainted:
                    validated_lines.add(getattr(node, "lineno", 0))
        if isinstance(node, ast.Raise) and node.exc is not None:
            for n in _names(node.exc):
                if n in tainted:
                    validated_lines.add(getattr(node, "lineno", 0))
        if isinstance(node, ast.Call) and _call_name(node) in (
                "validate", "check", "is_allowed", "allowed", "assert_allowed"):
            validated_lines.add(getattr(node, "lineno", 0))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not SINK_CALLS.search(_call_name(node)):
            continue
        line = getattr(node, "lineno", 0)
        # names read at the sink that are tainted
        used = set()
        for n in _names(node):
            if n in tainted:
                used.add(n)
        for k in node.keywords:
            if k.arg in ("to", "recipient", "destination", "dest", "amount"):
                for n in _names(k.value):
                    if n in tainted:
                        used.add(n)
        if not used:
            continue
        if any(v <= line for v in validated_lines):
            continue
        out.append({
            "type": "solana",
            "severity": "critical",
            "pattern": "PS-SOL-3",
            "line": line,
            "description": f"Model-derived value ({', '.join(sorted(used))}) reaches "
                           f"{_call_name(node)}() with no validation in between",
            "suggestion": "Validate against an allow-list (or a strict schema) before "
                          "the value reaches Pubkey/transfer. Fail closed.",
        })

    seen, uniq = set(), []
    for i in out:
        k = (i["pattern"], i["line"], i["description"])
        if k not in seen:
            seen.add(k)
            uniq.append(i)
    return uniq


# ---------------------------------------------------------------------------
# registry -- every pattern reports a verdict, so "clean" is distinguishable
# ---------------------------------------------------------------------------
PATTERNS = [
    ("PS-SOL-1",  "unsafe key/mnemonic/seed handling",       ps_sol_1),
    ("PS-SOL-2",  "solders / solana-py misuse",              ps_sol_2),
    ("PS-SOL-3",  "model output into address/RPC sink",      ps_sol_3),
]


def scan_solana(code: str) -> Dict:
    """Run every pattern. Returns issues plus a per-pattern verdict table.

    The verdict table is the point: `clear` means the pattern ran and found nothing,
    `n/a` means it could not apply (no Solana constructs at all), and neither is the
    same as a pattern that was never executed.
    """
    result: Dict = {"issues": [], "patterns": {}}
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        result["patterns"] = {p[0]: "n/a" for p in PATTERNS}
        result["syntax_error"] = str(e)
        return result

    src_lower = code.lower()
    looks_solana = any(k in src_lower for k in
                       ("solders", "solana", "pubkey", "keypair", "blockhash",
                        "send_transaction", "lamport"))
    if not looks_solana:
        result["patterns"] = {p[0]: "n/a" for p in PATTERNS}
        return result

    for pid, _desc, fn in PATTERNS:
        try:
            found = fn(tree, code)
        except Exception as e:                       # a pattern must never crash a scan
            result["patterns"][pid] = f"error: {type(e).__name__}"
            continue
        result["issues"].extend(found)
        result["patterns"][pid] = "found" if found else "clear"
    return result
