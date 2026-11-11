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
import bisect
import re
from collections import deque
from typing import Dict, List, Optional

# scope key -> enclosing scope key. Filled by _scope_map so a binding lookup can
# walk outward from a function to the module (sixth-pass F6-H07).
class _Scopes(dict):
    def __init__(self):
        super().__init__()
        self.parents = {None: None}
        self.outer = {None: None}


class _Bindings(dict):
    pass

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
# Transaction submission belongs here too: model output reaching
# send_transaction() is the last point a client can refuse it (SG-03).
SINK_CALLS = re.compile(r"(Pubkey|PublicKey|transfer|transfer_checked|Instruction|"
                        r"create_transfer_transaction|to_pubkey|send_transaction|"
                        r"send_raw_transaction|sendTransaction|sign_and_send)", re.I)

# --- key constructors, classified by RESOLVED type ---------------------------
# Exempting on the receiver's spelling is a bypass: `from solders.keypair import
# Keypair as Pubkey` then `Pubkey.from_base58_string(<secret>)` reads as a public
# constructor while loading a private key (RV-01). Classification therefore goes
# through the import bindings, and anything whose origin cannot be resolved is
# treated as private (fail closed).
PUBLIC_TYPES = frozenset({
    "solders.pubkey.pubkey", "solana.publickey.publickey",
    # Canonical shorthand in standalone snippets; explicit rebinding remains
    # unknown, and an opaque imported class cannot gain this exemption by name.
    "pubkey", "publickey",
})
PRIVATE_TYPE_HINTS = ("keypair", "signer", "wallet")
# Loaders that exist on both types; the receiver decides which it is.
SHARED_LOADERS = re.compile(r"^(from_string|from_base58|from_base58_string|"
                            r"from_bytes|from_seed)$", re.I)
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


def _dotted(node: ast.AST) -> str:
    """Full dotted path of a callee: `client.chat.completions.create`.

    Taking only the final attribute (`.create`) hides the receiver chain, so the
    most common model API shape never matched a source name (RV-05).
    """
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _binding_events(tree: ast.AST) -> dict:
    """scope -> name -> [(line, origin-or-None)] in source order.

    Bindings are both positional and lexical.

    *Positional*: a single final map applied every import and assignment to the
    whole file, so a later public import exempted an earlier private call.

    *Lexical*: a `from solders.pubkey import Pubkey as C` inside an unused
    function used to overwrite the module-level private binding of `C`, because
    every binding landed in one map (sixth-pass F6-H07). Each function scope gets
    its own table and lookup walks outward.

    `None` records a rebinding to something that is not a plain name, which
    erases any known origin.
    """
    scopes = _scope_map(tree)
    events = _Bindings()
    events.parents = scopes.parents
    events.scopes = scopes
    events.absolute = set()
    parents = {id(child): node for node in _iter_all(tree)
               for child in ast.iter_child_nodes(node)}

    def add(scope, name, line, origin, *, absolute=False):
        table = events.setdefault(scope, {})
        table.setdefault(name, []).append((line, origin))
        if absolute:
            events.absolute.add((scope, name, line))

    def bind(scope, target, value, position):
        if isinstance(target, ast.Name):
            origin = _dotted(value) if isinstance(value, (ast.Name, ast.Attribute)) else None
            add(scope, target.id, position, origin or None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for left, right in zip(target.elts, value.elts):
                    bind(scope, left, right, position)
            else:
                for left in target.elts:
                    bind(scope, left, None, position)
        elif isinstance(target, ast.Starred):
            bind(scope, target.value, None, position)

    for node in _iter_all(tree):
        line = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        scope = scopes.get(id(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            namespace = scopes.get(id(parents.get(id(node))))
            add(namespace, node.name, line, None)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                add(id(node), a.arg, line, None)
            for a in (node.args.vararg, node.args.kwarg):
                if a:
                    add(id(node), a.arg, line, None)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for a in node.names:
                if a.name == "*":
                    continue
                add(scope, a.asname or a.name, line,
                    f"{mod}.{a.name}" if mod else a.name, absolute=True)
        elif isinstance(node, ast.Import):
            for a in node.names:
                head = a.name.split(".")[0]
                add(scope, a.asname or head, line, a.name if a.asname else head,
                    absolute=True)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if isinstance(node, ast.AnnAssign) and node.value is None:
                continue  # annotations alone do not rebind an imported value
            value = None if isinstance(node, ast.AugAssign) else getattr(node, "value", None)
            if isinstance(node, ast.NamedExpr):
                target_scope = scopes.get(id(node.target))
                if target_scope != scope:
                    value = None  # a comprehension walrus binds in an outer scope
                scope = target_scope
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                bind(scope, t, value, line)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.iter, (ast.List, ast.Tuple)) and not node.iter.elts:
                continue
            value = node.iter.elts[0] if isinstance(node.iter, (ast.List, ast.Tuple)) and len(node.iter.elts) == 1 else None
            bind(scope, node.target, value, line)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(scope, item.optional_vars, None, line)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            add(scope, node.name, line, None)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in node.generators:
                bind(scope, generator.target, None, line)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            add(scope, node.name, line, None)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(scope, node.rest, line, None)
    events.positions = {}
    for scope, table in events.items():
        for name, lst in table.items():
            lst.sort(key=lambda e: e[0])
            events.positions[(scope, name)] = [e[0] for e in lst]
    return events


def _lookup(events: dict, scope, name: str, line: int):
    """(scope, origin) of the binding for `name` visible at `line` in `scope`."""
    cur = scope
    if isinstance(line, int):
        line = (line, 10**9)
    seen = 0
    while seen < 32:
        table = events.get(cur) or {}
        hist = table.get(name)
        if hist:
            index = bisect.bisect_right(events.positions[(cur, name)], line) - 1
            if index >= 0:
                origin = hist[index][1]
                return cur, origin if origin is not None else "@unknown:" + name
        if cur is None:
            break
        cur = events.parents.get(cur)
        seen += 1
    return None, None


def _origin_at(events: dict, name: str, line: int, scope=None,
               depth: int = 0) -> str:
    """Resolve `name` to its fully-qualified origin as of `line`.

    An alias is resolved at the line where it *captured* its value, not at the
    call's line: after `Alias = Keypair` and a later rebinding of `Keypair`,
    `Alias` still refers to the original class (sixth-pass F6-H07).
    """
    if depth > 12:
        return "@unknown:" + name
    if isinstance(line, int):
        line = (line, 10**9)
    if "." in name:
        head, tail = name.split(".", 1)
        return _origin_at(events, head, line, scope, depth + 1) + "." + tail
    scope_key, origin = _lookup(events, scope, name, line)
    if origin is None:
        return name
    # Resolve the origin at the point it was bound, in the scope that bound it.
    table = events.get(scope_key) or {}
    index = bisect.bisect_right(events.positions.get((scope_key, name), []), line) - 1
    bind_line = table[name][index][0] if index >= 0 else line
    if (scope_key, name, bind_line) in events.absolute:
        return origin
    if origin == name:
        before = (bind_line[0], bind_line[1] - 1)
        if _lookup(events, scope_key, name, before)[1] is None:
            return "@unknown:" + name
        return _origin_at(events, name, before, scope_key, depth + 1)
    return _origin_at(events, origin, bind_line, scope_key, depth + 1)


def _iter_all(root):
    if root is None:
        return
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _class_index(tree: ast.AST) -> Dict[tuple, ast.AST]:
    """(class_name, method_name) -> method node. Built once per file.

    Calling `_class_method_kind` per call site made the key rule quadratic: it
    walked the whole tree to find the class, for every Call node in the file.
    """
    out: Dict[tuple, ast.AST] = {}
    for node in _iter_all(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault((node.name, item.name), item)
    return out


def _class_method_kind(tree: ast.AST, class_name: str, method_name: str,
                       events: dict, depth: int = 0,
                       index: Optional[dict] = None) -> str:
    """Classify a wrapper method by what it RETURNS.

    A project often wraps the SDK: `class Destination: from_string ->
    Pubkey.from_string`. The receiver resolves to no known type, so treating it
    as private flags correct code (F4-11).

    The classification must follow the *returned* value. A wrapper that loads a
    private key, performs an unrelated public construction and then returns the
    private key is private; an earlier version classified whichever known
    constructor call its traversal happened to reach first (sixth-pass F6-H07).
    """
    if depth > 3:
        return "unknown"
    if index is None:
        index = _class_index(tree)
    item = index.get((class_name, method_name))
    if item is None:
        return "unknown"

    kinds = set()
    for sub in _iter_all(item):
        if not isinstance(sub, ast.Return) or sub.value is None:
            continue
        if events.scopes.get(id(sub)) != id(item):
            continue  # nested functions do not determine this method's return
        value = sub.value
        if isinstance(value, ast.Call):
            kind = _classify_key_ctor(value, events, tree, depth + 1,
                                      scope=events.scopes.get(id(value)), index=index)
            kinds.add(kind)
        else:
            kinds.add("unknown")
    if "private" in kinds:
        return "private"
    if kinds and kinds <= {"public", "non-key"}:
        return "public"
    return "unknown"


def _classify_key_ctor(node: ast.Call, events: dict, tree: Optional[ast.AST] = None,
                       depth: int = 0, scope=None,
                       index: Optional[dict] = None) -> str:
    """'public' | 'private' | 'unknown' for a key-constructor call.

    The *binding as of this call's line, in this scope* decides, never the local
    spelling. An unresolved receiver is 'unknown', which the caller treats as
    private so a renamed private loader can never be exempted (RV-01) -- unless
    the receiver is a class in this file whose method demonstrably returns a
    public key (F4-11).
    """
    f = node.func
    if not isinstance(f, ast.Attribute):
        return "unknown"

    recv = f.value
    recv_name = _dotted(recv)
    line = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))

    # A project wrapper is classified before the loader-name gate: `Vault.load`
    # matches no SDK loader name, but its method may return private material
    # (sixth-pass F6-H07).
    if tree is not None and isinstance(recv, ast.Name) and not SHARED_LOADERS.match(f.attr):
        kind = _class_method_kind(tree, recv.id, f.attr, events, depth, index)
        if kind != "unknown":
            return kind

    if not SHARED_LOADERS.match(f.attr):
        return "unknown"

    resolved = _origin_at(events, recv_name, line, scope).lower()
    if resolved.startswith("@unknown:"):
        if tree is not None and isinstance(recv, ast.Name):
            return _class_method_kind(tree, recv.id, f.attr, events, depth, index)
        return "unknown"
    if resolved in ("int", "str", "bytes", "bytearray", "builtins.int", "builtins.bytes", "uuid.uuid", "decimal.decimal"):
        return "non-key"
    # strip a module prefix so `solders.pubkey.Pubkey` reads as the type name
    tail = resolved.rsplit(".", 1)[-1]

    if any(h in tail for h in PRIVATE_TYPE_HINTS):
        return "private"
    if resolved in PUBLIC_TYPES:
        return "public"

    # Not a known type: is it a wrapper class defined in this file?
    if tree is not None and isinstance(recv, ast.Name):
        return _class_method_kind(tree, recv.id, f.attr, events, depth)
    return "unknown"



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
    bindings = _binding_events(tree)
    scopes = _scope_map(tree)
    _, material = _analysis_facts(tree)
    class_index = _class_index(tree)
    mnemonic_context = set()
    for stmt in _iter_all(tree):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if any(re.search(r"mnemonic|recovery_phrase|seed_phrase", n, re.I)
                   for target in targets for n in _names(target)):
                mnemonic_context.update(id(n) for n in _iter_all(getattr(stmt, "value", None)) if isinstance(n, ast.Constant))
        elif isinstance(stmt, ast.Call) and re.search(r"mnemonic|recovery_phrase|seed_phrase", _call_name(stmt), re.I):
            mnemonic_context.update(id(n) for n in _iter_all(stmt) if isinstance(n, ast.Constant))

    for node in ast.walk(tree):
        # 1a / 1e -- a loader called with a literal, or a 64-element literal.
        # A project wrapper (`Vault.load(text)`) is a loader too when the class
        # method returns private material, even though its name matches no
        # loader regex (sixth-pass F6-H07).
        if isinstance(node, ast.Call):
            ctor_kind = _classify_key_ctor(node, bindings, tree,
                                           scope=scopes.get(id(node)),
                                           index=class_index)
            is_loader = bool(KEY_LOADERS.search(_call_name(node))) or \
                ctor_kind == "private"
            if _call_name(node) == "b58decode":
                is_loader = False  # decoding public data does not create a key
            if is_loader and ctor_kind not in ("public", "non-key"):
                from .dataflow import UNKNOWN
                literal_args = {id(e) for e, info in material.arguments.get(id(node), [])
                                if info.embedded and (info.constant is UNKNOWN or isinstance(info.constant, (str, bytes)))}
                for a in list(node.args) + [k.value for k in node.keywords]:
                    if _is_literal(a) or _is_64_constant(a) or id(a) in literal_args:
                        out.append({
                            "type": "solana",
                            "severity": "critical" if ctor_kind == "private" else "high",
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
            if id(node) in mnemonic_context and len(words) in (12, 15, 18, 21, 24) and all(w.isalpha() and w.islower()
                                              for w in words):
                out.append({
                    "type": "solana",
                    "severity": "high",
                    "pattern": "PS-SOL-1b",
                    "line": getattr(node, "lineno", 0),
                    "description": f"A {len(words)}-word mnemonic appears as a literal",
                    "suggestion": "Never embed a recovery phrase. Read it from secure "
                                  "storage at runtime.",
                })

        # 1d -- key-like name interpolated into a log / f-string / format
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if not isinstance(v, ast.FormattedValue):
                    continue
                # A PUBLIC key is meant to be printed. `logger.info(f"{kp.pubkey()}")`
                # is correct code; only the secret must never be interpolated.
                # `hex`/`to_string`/`str` were exempt too, which let
                # `print(f"{secret.hex()}")` through -- those serialize whatever
                # they are given, so they stay flagged (F4-09).
                _expr = v.value
                if (isinstance(_expr, ast.Call)
                        and isinstance(_expr.func, ast.Attribute)
                        and _expr.func.attr in ("pubkey", "public_key")):
                    continue
                if True:
                    for n in _names(v.value):
                        if KEY_NAMES.search(n):
                            out.append({
                                "type": "solana",
                                "severity": "high" if re.search(r"secret|private|seed|mnemonic", n, re.I) else "medium",
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
    scopes = _scope_map(tree)
    all_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    _, rpc_analysis = _analysis_facts(tree)

    for node in all_calls:
        name = _call_name(node)
        line = getattr(node, "lineno", 0)
        scope = scopes.get(id(node))
        if id(node) in rpc_analysis.rpc_unawaited:
            out.append({"type": "solana", "severity": "high", "pattern": "PS-SOL-2d", "line": line,
                        "description": f"AsyncClient.{name}() is not awaited on every completing path",
                        "suggestion": "Await the RPC operation before relying on its result or confirmation."})

        # 2a -- send without a commitment option and without a confirmation that
        # is actually reachable from the same scope (SG-05). The supplied value
        # is evaluated, not just its literal form: `opts = None` then
        # `opts=opts` supplied nothing (F4-08).
        if SEND_CALLS.search(name):
            if id(node) in rpc_analysis.rpc_unsafe:
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

        # 2b -- simulation result never checked for .err. The rejection must be
        # *driven by* this simulation's own error attribute: a later ordinary
        # return, an unrelated raise, or dead code does not enforce (F4-07/F4-08).
        if SIMULATE_CALLS.search(name):
            checked = id(node) not in rpc_analysis.rpc_unsafe
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

    # 2c is explicitly advisory: the latest fetch and possible slow work in the
    # same scope, including multiple operations on one physical line. This is a
    # linear sweep after sorting, rather than fetches x sends x every call.
    recent = {}
    for call in sorted(all_calls, key=lambda c: (c.lineno, c.col_offset)):
        scope = scopes.get(id(call))
        name = _call_name(call)
        if BLOCKHASH_CALLS.search(name):
            recent[scope] = (call, None)
        elif scope in recent:
            blockhash, slow = recent[scope]
            if SLOW_CALLS.search(name):
                recent[scope] = (blockhash, call)
            if SEND_CALLS.search(name) and slow is not None:
                out.append({"type": "solana", "severity": "medium",
                            "pattern": "PS-SOL-2c", "line": call.lineno,
                            "description": f"Possible stale blockhash: fetch at line {blockhash.lineno}, "
                                           f"then { _call_name(slow)}(), then submission",
                            "suggestion": "Check the transaction's actual blockhash lifetime; refetch immediately before signing."})

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


def _scope_map(tree: ast.AST) -> dict:
    """id(node) -> enclosing scope key (a function's id, or None at module level).

    Lookup parents are per-scan. Comprehensions and lambdas have their own local
    names; a comprehension's first iterable is evaluated in its outer scope.

    Iterative on purpose: the previous recursive walk descended into expression
    nodes and hit the interpreter recursion limit on a 2.4 KB input, and the
    resulting RecursionError was swallowed, so the scan reported clean on code it
    never analysed (F4-01).
    """
    scopes = _Scopes()
    scopes[id(tree)] = None
    stack = [(tree, None)]
    comprehensions = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    introduces_scope = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                        ast.Lambda) + comprehensions
    class_scopes = set()
    comprehension_scopes = set()
    first_iterables = {}
    while stack:
        node, scope = stack.pop()
        for child in ast.iter_child_nodes(node):
            outer = first_iterables.get(id(child), scope)
            if isinstance(node, ast.NamedExpr) and child is node.target:
                while outer in comprehension_scopes:
                    outer = scopes.outer[outer]
            if isinstance(child, introduces_scope):
                scopes[id(child)] = id(child)
                parent = scopes.parents.get(outer) if outer in class_scopes and not isinstance(child, ast.ClassDef) else outer
                scopes.parents[id(child)] = parent
                scopes.outer[id(child)] = outer
                if isinstance(child, ast.ClassDef):
                    class_scopes.add(id(child))
                if isinstance(child, comprehensions):
                    comprehension_scopes.add(id(child))
                    if child.generators:
                        first_iterables[id(child.generators[0].iter)] = outer
                stack.append((child, id(child)))
            else:
                scopes[id(child)] = outer
                stack.append((child, outer))
    return scopes


def _model_call(node: ast.AST) -> bool:
    """Is this a call to a model API? Qualified receivers count (RV-05)."""
    if not isinstance(node, ast.Call):
        return False
    return bool(LLM_NAMES.search(_dotted(node.func)))


def _is_model_source(node: ast.AST, state) -> bool:
    """Interpreter callback: is this expression a fresh untrusted source?"""
    return _model_call(node)


def ps_sol_3(tree: ast.AST, source: str) -> List[Dict]:
    """Model output reaching an address/transaction sink unvalidated.

    Delegates to the control-flow interpreter. The previous implementation
    ordered events by line number, which is not a semantics: a validator inside a
    branch, a swallowed exception, an optional overwrite or a loop that validates
    once all let an unsafe value through (F4-02, F4-03), and the per-sink rescan
    of every assignment was quadratic (F4-10).
    """
    out: List[Dict] = []
    from .dataflow import Interpreter, flow_insensitive_taint

    seed = flow_insensitive_taint(tree, _is_model_source)
    interp = Interpreter(tree, _is_model_source, {}, initial_taint=seed)
    analysis = interp.run()

    seen_lines = set()
    for call, state, _scope in analysis.sinks:
        if not SINK_CALLS.search(_call_name(call)):
            continue
        line = getattr(call, "lineno", 0)

        unsafe = [expr for expr, info in analysis.arguments.get(id(call), [])
                  if info.tainted and not info.cleared]
        if not unsafe:
            continue
        if line in seen_lines:
            continue
        seen_lines.add(line)

        label = ", ".join(sorted(set().union(*(_names(a) for a in unsafe)))) or "inline model call"
        out.append({
            "type": "solana",
            "severity": "critical",
            "pattern": "PS-SOL-3",
            "line": line,
            "description": f"Model-derived value ({label}) reaches "
                           f"{_call_name(call)}() with no validation in between",
            "suggestion": "Validate against an allow-list (or a strict schema) before "
                          "the value reaches Pubkey/transfer. Fail closed.",
        })
    return out



# ---------------------------------------------------------------------------
# registry -- every pattern reports a verdict, so "clean" is distinguishable
# ---------------------------------------------------------------------------
# --- signing / message integrity (PS-SOL-4) ----------------------------------
# The documented SDK entry points, not guessed aliases: solders `Transaction.sign`
# and signing during `VersionedTransaction(...)` construction are real signing
# APIs and were missing entirely (fifth-pass H03).
SIGN_CALLS = re.compile(r"^(sign|sign_message|sign_transaction|sign_all_transactions|"
                        r"signTransaction|partial_sign|sign_versioned|sign_message_data)$",
                        re.I)
SIGN_CTORS = {"Transaction", "VersionedTransaction", "LegacyTransaction"}
DESERIALIZE_CALLS = re.compile(r"(from_bytes|deserialize|from_string_bytes)", re.I)
# Fields whose value a policy check must constrain before signing. Reading one is
# not authorization on its own (fifth-pass H02).
MESSAGE_FIELDS = re.compile(r"^(instructions|account_keys|header|fee_payer|"
                            r"compiled_instructions|recent_blockhash)$")

# --- account / economic constraints (PS-SOL-5) -------------------------------
AMOUNT_TRANSFER = re.compile(r"^(transfer|transfer_checked|transferChecked)$", re.I)
SWAP_CALLS = re.compile(r"^(swap|swap_exact|swapExact|swap_exact_in|swap_exact_out|jupiter_swap)$", re.I)
# Namespace evidence is mandatory: ordinary swap/route identifiers are not DeFi
# operations. These package roots describe supported Solana client namespaces;
# the exact method name still has to match, even on a resolved SDK receiver.
SWAP_MODULE_ROOTS = frozenset({"jupiter_python_sdk", "solana_agent_kit", "solana_agentkit"})
MIN_OUT_KWARGS = {"min_amount_out", "minimum_amount_out", "min_out",
                  "min_output_amount", "minOutputAmount", "minimum_output"}
SLIPPAGE_KWARGS = {"slippage", "slippage_bps", "slippageBps", "max_slippage"}
# Sources whose value is attacker- or user-controlled by construction.
UNTRUSTED_SOURCES = re.compile(r"^(input|argv|environ|getenv|json|loads|"
                               r"request|form|args|params|query|read)$", re.I)

# Calls that wrap a value without changing where it came from.
TRANSPARENT_CALLS = {"int", "float", "str", "Decimal", "round", "abs",
                     "identity", "strip", "lower", "upper", "format"}


class _SwapContext:
    """Resolve swap API context without inferring it from a callee's spelling.

    Import/callable aliases resolve at their binding position. Receiver object
    identities come from the interpreter, so copying an SDK instance retains
    its context while rebinding it to an unrelated router does not.
    """

    def __init__(self, tree, analysis):
        self.bindings = _binding_events(tree)
        self.scopes = _scope_map(tree)
        self.nodes = {id(n): n for n in _iter_all(tree)
                      if isinstance(n, (ast.Call, ast.arg))}
        self.analysis = analysis

    def origin(self, expr, position, scope):
        dotted = _dotted(expr)
        return _origin_at(self.bindings, dotted, position, scope) if dotted else ""

    @staticmethod
    def solana_origin(name):
        return name.split(".", 1)[0] in SWAP_MODULE_ROOTS

    def matches(self, call):
        if id(call) not in self.analysis.arguments:
            return False
        position = (call.lineno, call.col_offset)
        scope = self.scopes.get(id(call))
        origin = self.origin(call.func, position, scope)
        method = origin.rsplit(".", 1)[-1]
        if not SWAP_CALLS.fullmatch(method):
            return False
        if self.solana_origin(origin):
            return True
        if isinstance(call.func, ast.Attribute):
            info = self.analysis.receivers.get(id(call))
        else:
            info = self.analysis.states.get(id(call), {}).get(getattr(call.func, "id", ""))
        if info is None:
            return False
        for token in info.objects:
            node = self.nodes.get(token)
            if isinstance(node, ast.Call):
                expr = node.func
            elif isinstance(node, ast.arg):
                expr = node.annotation
            else:
                continue
            node_scope = self.scopes.get(id(node))
            node_position = (node.lineno, node.col_offset)
            if self.solana_origin(self.origin(expr, node_position, node_scope)):
                return True
        return False






def _analysis_facts(tree: ast.AST):
    """Run the interpreter once and return (sink states by id, analysis).

    PS-SOL-4 and PS-SOL-5 both need facts at a program point, and the
    interpreter is what establishes them. Computing them once here also avoids
    rebuilding the model seed per rule (fifth-pass H13).
    """
    from .dataflow import Interpreter

    cached = getattr(tree, "_sak_external_analysis", None)
    if cached is not None:
        return cached.states, cached

    def external(node, state):
        if _is_model_source(node, state):
            return True
        if isinstance(node, ast.Attribute) and node.attr in ("argv", "environ"):
            return True
        if not isinstance(node, ast.Call):
            return False
        name = _call_name(node)
        return bool(DESERIALIZE_CALLS.search(name) or UNTRUSTED_SOURCES.match(name))

    analysis = Interpreter(tree, external, {}, parameter_taint=True).run()
    tree._sak_external_analysis = analysis
    return analysis.states, analysis




def ps_sol_4(tree: ast.AST, source: str) -> List[Dict]:
    """PS-SOL-4 -- signing an unreviewed or externally supplied message.

    A client that signs whatever it is handed authorizes transactions it never
    inspected. Nothing in PS-SOL-1..3 covered signer/message integrity (SG-10).

    "Reviewed" is a fact the interpreter establishes on the path that does not
    reject: `if msg.account_keys[0] != EXPECTED: raise` reviews `msg` for the
    code after it. That makes polarity, ordering and scope automatic -- an
    inverted check, a check after signing, and a check in an uncalled helper all
    fail to produce the fact (sixth-pass F6-H04).
    """
    out: List[Dict] = []
    states, _analysis = _analysis_facts(tree)

    seen = set()
    for node in _iter_all(tree):
        if not isinstance(node, ast.Call):
            continue
        line = getattr(node, "lineno", 0)
        cname = _call_name(node)

        signing = bool(SIGN_CALLS.search(cname))
        # `VersionedTransaction(tx.message, [kp])` signs during construction.
        if (not signing and cname in SIGN_CTORS
                and isinstance(node.func, ast.Name) and node.args):
            signing = True
        if not signing or line in seen:
            continue

        operands = _analysis.arguments.get(id(node), [])
        # Transaction.sign() signs its receiver, Keypair.sign_message() signs
        # its first argument. Constructors sign their message argument.
        if cname.lower() in ("sign", "partial_sign") and isinstance(node.func, ast.Attribute):
            messages = [(node.func.value, _analysis.receivers.get(id(node)))]
        elif node.args:
            messages = operands[:1]
        else:
            messages = [(e, i) for (e, i), kw in zip(operands, node.keywords)
                        if kw.arg in ("message", "transaction", "transactions", "tx", "data")]
        unsafe = [(e, i) for e, i in messages
                  if i is not None and i.tainted and not i.reviewed]
        if not unsafe:
            continue
        signed_names = set().union(*(_names(e) for e, _ in unsafe))
        kind = "externally supplied message"
        out.append({
            "type": "solana",
            "severity": "high",
            "pattern": "PS-SOL-4",
            "line": line,
            "description": f"{cname}() signs a {kind} "
                           f"({', '.join(sorted(signed_names)) or 'inline value'}) "
                           "without a policy check on its instructions or account keys",
            "suggestion": "Verify the fee payer and expected signers, and enforce a "
                          "check on message.instructions / account_keys, before "
                          "signing. Never sign a transaction you did not construct.",
        })
        seen.add(line)
    return out




def ps_sol_5(tree: ast.AST, source: str) -> List[Dict]:
    """PS-SOL-5 -- unbounded amounts and resolved swaps without explicit bounds.

    SG-11: no rule covered amount bounds, slippage or trusted program selection.

    The bound is read from the interpreter's state at the sink, so it must have
    been established on every path that reaches the transfer. A cap computed and
    then ignored, an optional or swallowed check, or a check in another scope
    all leave the value unbounded (sixth-pass F6-H02/F6-H03).
    """
    out: List[Dict] = []
    states, _analysis = _analysis_facts(tree)
    swaps = _SwapContext(tree, _analysis)
    seen = set()

    for node in _iter_all(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        line = getattr(node, "lineno", 0)

        if AMOUNT_TRANSFER.match(name or "") or _has_transfer_params(node):
            operands = _analysis.arguments.get(id(node), [])
            exprs = _amount_exprs(node)
            if len(node.args) == 1 and not exprs:
                exprs = node.args[:1]  # separately constructed TransferParams
            infos = {id(e): i for e, i in operands}
            for a in exprs:
                info = infos.get(id(a))
                if info is None:
                    # A nested TransferParams supplies its own keyword facts.
                    for sub in node.args:
                        if isinstance(sub, ast.Call):
                            info = dict((id(e), i) for e, i in _analysis.arguments.get(id(sub), [])).get(id(a))
                            if info is not None:
                                break
                if info is None or not info.tainted or info.bounded:
                    continue
                if line in seen:
                    break
                out.append({
                    "type": "solana",
                    "severity": "high",
                    "pattern": "PS-SOL-5",
                    "line": line,
                    "description": f"{name}() sends a caller-supplied amount "
                                   f"('{', '.join(sorted(_names(a))) or 'inline input'}') with no upper bound "
                                   "before the transfer",
                    "suggestion": "Clamp the amount against an explicit maximum and "
                                  "convert with exact integer decimals before sending.",
                })
                seen.add(line)
                break

        if swaps.matches(node):
            if line in seen:
                continue
            if _has_effective_output_bound(node, _analysis):
                continue
            out.append({
                "type": "solana",
                "severity": "high",
                "pattern": "PS-SOL-5",
                "line": line,
                "description": f"{name}() has no statically verified explicit "
                               "minimum-output or slippage bound",
                "suggestion": "Pass a real min_amount_out / slippage value and verify "
                              "the pool and program id are trusted.",
            })
            seen.add(line)
    return out


def _has_transfer_params(node: ast.Call) -> bool:
    """`transfer(TransferParams(...))` -- the documented solders one-arg form."""
    return any(_call_name(a) == "TransferParams" for a in node.args
               if isinstance(a, ast.Call))


def _amount_exprs(node: ast.Call):
    """Every expression that supplies a transfer amount."""
    out = []
    if _has_transfer_params(node):
        for a in node.args:
            if not isinstance(a, ast.Call):
                continue
            for k in a.keywords:
                if k.arg in ("lamports", "amount", "value"):
                    out.append(k.value)
        return out
    if len(node.args) >= 2:
        out.append(node.args[1])
    for k in node.keywords:
        if k.arg in ("amount", "lamports", "value"):
            out.append(k.value)
    return out








def _has_effective_output_bound(node: ast.Call, analysis) -> bool:
    """Is a min-output or slippage value actually supplied and non-degenerate?

    Keyword presence alone proves nothing: `min_amount_out=None` and
    `min_amount_out=0` both disable the protection while looking like a bound,
    and so does a name that holds either value.
    """
    from .dataflow import UNKNOWN
    import math

    facts = {id(e): i for e, i in analysis.arguments.get(id(node), [])}
    for k in node.keywords:
        if k.arg not in (MIN_OUT_KWARGS | SLIPPAGE_KWARGS):
            continue
        info = facts.get(id(k.value))
        if info is None or info.constant is UNKNOWN:
            continue
        value = info.constant
        if (isinstance(value, (int, float)) and not isinstance(value, bool)
                and value > 0 and (not isinstance(value, float) or math.isfinite(value))):
            return True
    return False


PATTERNS = [
    ("PS-SOL-1",  "unsafe key/mnemonic/seed handling",       ps_sol_1),
    ("PS-SOL-2",  "solders / solana-py misuse",              ps_sol_2),
    ("PS-SOL-3",  "model output into address/RPC sink",      ps_sol_3),
    ("PS-SOL-4",  "signing an unreviewed message",           ps_sol_4),
    ("PS-SOL-5",  "unbounded amount / missing slippage",     ps_sol_5),
]


def scan_solana(code: str) -> Dict:
    """Run every pattern. Returns issues plus a per-pattern verdict table.

    The verdict table is the point: `clear` means the pattern ran and found nothing,
    `n/a` means it could not apply (no Solana constructs at all), and neither is the
    same as a pattern that was never executed.
    """
    result: Dict = {"issues": [], "patterns": {}, "errors": []}
    try:
        from .limits import validate_source
        tree = validate_source(code)
    except SyntaxError as e:
        result["patterns"] = {p[0]: "n/a" for p in PATTERNS}
        result["syntax_error"] = str(e)
        result["errors"].append(f"Syntax error: {e}")
        return result
    except Exception as e:
        result["patterns"] = {p[0]: "error" for p in PATTERNS}
        result["errors"].append(f"{type(e).__name__}: {e}")
        return result

    # Every supported API shape participates in applicability. Source comments
    # and string contents cannot silently enable/disable a required rule.
    looks_solana = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in SWAP_MODULE_ROOTS | {"solders", "solana"}:
            looks_solana = True
        elif isinstance(node, ast.Import) and any(a.name.split(".")[0] in SWAP_MODULE_ROOTS | {"solders", "solana"} for a in node.names):
            looks_solana = True
        elif isinstance(node, ast.Name) and re.search(r"mnemonic|recovery_phrase|seed_phrase|keypair|pubkey", node.id, re.I):
            looks_solana = True
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            looks_solana |= any(rx.search(name) for rx in (
                SIGN_CALLS, SINK_CALLS, SEND_CALLS, SIMULATE_CALLS, KEY_LOADERS,
                BLOCKHASH_CALLS, CONFIRM_CALLS, DESERIALIZE_CALLS))
        elif isinstance(node, ast.JoinedStr) and any(KEY_NAMES.search(n) for n in _names(node)):
            looks_solana = True
        if looks_solana:
            break
    if not looks_solana:
        result["patterns"] = {p[0]: "n/a" for p in PATTERNS}
        return result

    for pid, _desc, fn in PATTERNS:
        try:
            found = fn(tree, code)
        except Exception as e:                       # a pattern must never crash a scan
            # Record it AND surface it, with the message: a rule that failed to
            # run is not a rule that found nothing, and the reason (e.g. which
            # loop did not converge) is what makes the failure actionable.
            result["patterns"][pid] = f"error: {type(e).__name__}"
            detail = str(e) or type(e).__name__
            result["errors"].append(f"{pid}: {detail}")
            continue
        result["issues"].extend(found)
        result["patterns"][pid] = "found" if found else "clear"
    return result
