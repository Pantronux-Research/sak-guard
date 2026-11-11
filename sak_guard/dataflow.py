"""Control-flow-aware provenance analysis for sak-guard.

An abstract interpreter over each scope's statement list.

**Facts are keyed by access path.** State maps ``"x"``, ``"x['recipient']"`` and
``"x.attr"`` to ``Info``, so a check on one field does not authorize another, and
a write through a subscript is a write to that field rather than to a fresh name
(seventh-pass F7-H08). Aliases (`box` / `other = box`) share a mutation set, so a
write through any of them invalidates every one.

**Info carries four facts:** ``tainted``, ``cleared`` (policy-checked),
``bounded`` (has an upper bound) and ``reviewed`` (its message was constrained).
A fact is set where the code establishes it and merges conservatively at joins,
so reachability, polarity and ordering come out of the control flow rather than
out of pattern matching.

**A bound needs an independent limit.** ``if amount > amount: raise`` never
rejects anything, and ``min(amount, amount + 1)`` is the identity on integers, so
neither is a cap: the limiting operand must not itself reference the value being
bounded (F7-H01). Arithmetic propagates the conjunction of its operands' bounds,
so a bounded amount times an unbounded multiplier is unbounded (F7-H02).

**Exits are a set.** A block can leave through several routes at once. ``finally``
runs on every one of them including normal completion, and ``else`` runs only on
non-``break`` completion (F7-H06/F7-H07).

**Expression side effects follow Python's evaluation rules.** The right operand of
``and``/``or`` runs only when the left does not decide the value, and the unused
arm of a conditional expression never runs, so a dead arm cannot clear taint
(F7-H05).

Traversal is iterative everywhere: a recursive walk over expression nodes blew the
interpreter's recursion limit on a 2.4 KB input and the resulting
``RecursionError`` was swallowed, so the scanner reported clean on code it had
failed to analyse (F4-01).
"""

import ast
import math
from .limits import MAX_ANALYSIS_STEPS
from typing import Dict, List, Optional, Set, Tuple

# Calls that cap their first argument. Only the RESULT is bounded, and only when
# the limit is independent of the value.
CAPPING_CALLS = {"min"}
READ_ONLY_CALLS = {
    "min", "max", "int", "float", "str", "bytes", "bool", "len", "tuple",
    "print", "info", "debug", "warning", "error", "message_data", "to_bytes",
    "pubkey", "public_key", "Pubkey", "PublicKey", "from_string", "from_bytes",
    "loads", "dumps", "TransferParams", "Instruction", "Transaction",
    "VersionedTransaction", "transfer", "transfer_checked", "sign", "partial_sign",
    "sign_message", "sign_transaction", "sign_all_transactions", "signTransaction",
    "send_transaction", "send_raw_transaction", "confirm_transaction",
    "get_signature_statuses", "simulate_transaction", "get_latest_blockhash",
}
# Fields a policy check must constrain before signing.
MESSAGE_FIELDS = {"instructions", "account_keys", "header", "fee_payer",
                  "compiled_instructions", "recent_blockhash"}

# Loop iteration bound. The fixpoint makes at least one link of progress per
# pass, so a chain of N assignments needs ~N passes; 128 covers ordinary code
# while still bounding a pathological input. Exceeding it means the analysis did
# not converge, which is reported (with the loop's line) rather than treated as
# a clean result.
MAX_LOOP_PASSES = 128
UNKNOWN = object()


class AnalysisError(RuntimeError):
    """The interpreter could not finish. Never report this as a clean result."""


# ─── access paths ────────────────────────────────────────────────────────────

def _path_key(node) -> Optional[str]:
    """Stable key for a Name / constant-subscript / attribute chain.

    `x` -> "x", `x["k"]` -> "x['k']", `x.a` -> "x.a". A non-constant subscript
    has no stable key, so a check cannot authorize a different element.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _path_key(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        base = _path_key(node.value)
        if base is None:
            return None
        sl = node.slice
        if isinstance(sl, ast.Constant):
            return f"{base}[{sl.value!r}]"
        return None
    return None


def _base_of(key: str) -> str:
    """The root name of a path key."""
    for i, ch in enumerate(key):
        if ch in ".[":
            return key[:i]
    return key


def _under_base(key: str, base: str) -> bool:
    return key == base or key.startswith(base + ".") or key.startswith(base + "[")


class Info:
    """What is known about one access path at one program point."""

    __slots__ = ("tainted", "cleared", "bounded", "reviewed", "origins", "constant", "objects", "review_fields", "numeric", "embedded")

    def __init__(self, tainted: bool = False, cleared: bool = False,
                 bounded: bool = False, reviewed: bool = False,
                 origins=frozenset(), constant=UNKNOWN, objects=frozenset(), review_fields=frozenset(), numeric=False, embedded=False):
        self.tainted = tainted
        # cleared  == passed a policy check on every path reaching here
        # bounded  == known to have an upper bound on every path reaching here
        # reviewed == its message was constrained on every path reaching here
        self.cleared = cleared
        self.bounded = bounded
        self.reviewed = reviewed
        self.origins = frozenset(origins)
        self.constant = constant
        self.objects = frozenset(objects)
        self.review_fields = frozenset(review_fields)
        self.numeric = numeric
        self.embedded = embedded

    def copy(self) -> "Info":
        return Info(self.tainted, self.cleared, self.bounded, self.reviewed,
                    self.origins, self.constant, self.objects, self.review_fields, self.numeric, self.embedded)

    def __eq__(self, other):
        return (isinstance(other, Info)
                and self.tainted == other.tainted
                and self.cleared == other.cleared
                and self.bounded == other.bounded
                and self.reviewed == other.reviewed
                and self.origins == other.origins
                and self.constant == other.constant
                and self.objects == other.objects
                and self.review_fields == other.review_fields
                and self.numeric == other.numeric
                and self.embedded == other.embedded)

    def __repr__(self):
        bits = [f for f in ("tainted", "cleared", "bounded", "reviewed")
                if getattr(self, f)]
        return f"Info({','.join(bits) or 'clean'})"


def _with(info: Info, **kw) -> Info:
    return Info(kw.get("tainted", info.tainted),
                kw.get("cleared", info.cleared),
                kw.get("bounded", info.bounded),
                kw.get("reviewed", info.reviewed),
                kw.get("origins", info.origins),
                kw.get("constant", info.constant),
                kw.get("objects", info.objects),
                kw.get("review_fields", info.review_fields),
                kw.get("numeric", info.numeric),
                kw.get("embedded", info.embedded))


def join_info(infos):
    infos = list(infos)
    if not infos:
        return Info()
    tainted = [i for i in infos if i.tainted]
    first = infos[0].constant
    return Info(any(i.tainted for i in infos),
                all(i.cleared for i in tainted) if tainted else False,
                all(i.bounded for i in infos),
                all(i.reviewed for i in tainted) if tainted else False,
                frozenset().union(*(i.origins for i in infos)),
                first if all(i.constant == first for i in infos) else UNKNOWN,
                frozenset().union(*(i.objects for i in infos)),
                frozenset().union(*(i.review_fields for i in infos)),
                all(i.numeric for i in infos), any(i.embedded for i in infos))


def merge(a: Dict[str, Info], b: Dict[str, Info]) -> Dict[str, Info]:
    """Join two paths.

    Provenance survives if either path has it -- an unsafe value on one route is
    still unsafe. A *fact* survives only if both paths established it, because
    the join cannot know which route ran.
    """
    out = {}
    for key in set(a) | set(b):
        # A missing field fact can mean that a mutation invalidated it. Its
        # enclosing object's provenance still applies on that path; treating it
        # as fresh clean data preserves a stale clearance from the other path.
        ia = a.get(key, a.get(_base_of(key), Info()))
        ib = b.get(key, b.get(_base_of(key), Info()))
        out[key] = join_info((ia, ib))
    return out


def _join_all(states: List[Dict[str, Info]]) -> Dict[str, Info]:
    if not states:
        return {}
    out = dict(states[0])
    for s in states[1:]:
        out = merge(out, s)
    return out


def _iter_nodes(root):
    """Iterative pre-order walk. No recursion anywhere in this module."""
    if root is None:
        return
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _names(node: Optional[ast.AST]) -> Set[str]:
    if node is None:
        return set()
    return {n.id for n in _iter_nodes(node) if isinstance(n, ast.Name)}


def _assign_targets(node: ast.AST) -> List[str]:
    """Every name bound by an assignment, including tuple/list patterns."""
    out: List[str] = []

    def collect(t):
        stack = [t]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ast.Name):
                out.append(cur.id)
            elif isinstance(cur, (ast.Tuple, ast.List)):
                stack.extend(cur.elts)
            elif isinstance(cur, ast.Starred):
                stack.append(cur.value)

    if isinstance(node, ast.Assign):
        for t in node.targets:
            collect(t)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        collect(node.target)
    return out


def _store_paths(node: ast.AST) -> List[str]:
    """Access paths written through a subscript/attribute store."""
    out = []
    targets = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    for t in targets:
        if isinstance(t, (ast.Subscript, ast.Attribute)):
            key = _path_key(t)
            if key:
                out.append(key)
    return out


def _root_name(node: Optional[ast.AST]) -> Optional[str]:
    """Base Name of a subscript/attribute chain: `a.b[0]` -> 'a'."""
    cur = node
    while isinstance(cur, (ast.Subscript, ast.Attribute)):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def _limit_is_independent(test: ast.AST, name: str) -> bool:
    """Does the limiting operand avoid referencing `name`?

    `amount > amount` and `amount > amount + 1` never reject an ordinary value,
    so they are not caps (seventh-pass F7-H01).
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Name) and left.id == name:
        return name not in _names(right)
    if isinstance(right, ast.Name) and right.id == name:
        return name not in _names(left)
    return False


def _numeric_operand(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) \
        and not isinstance(node.value, bool)


def _bounded_when_false(test: ast.AST) -> Optional[str]:
    """Name upper-bounded when `test` evaluates to False."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    op = test.ops[0]
    left, right = test.left, test.comparators[0]
    if isinstance(op, (ast.Gt, ast.GtE)) and isinstance(left, ast.Name):
        if isinstance(right, (ast.Constant, ast.Name)):
            if isinstance(right, ast.Constant) and not _numeric_operand(right):
                return None
            if not _limit_is_independent(test, left.id):
                return None
            return left.id
    if isinstance(op, (ast.Lt, ast.LtE)) and isinstance(right, ast.Name):
        if isinstance(left, (ast.Constant, ast.Name)):
            if isinstance(left, ast.Constant) and not _numeric_operand(left):
                return None
            if not _limit_is_independent(test, right.id):
                return None
            return right.id
    return None


def _bounded_when_true(test: ast.AST) -> Optional[str]:
    """Name upper-bounded when `test` evaluates to True."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    op = test.ops[0]
    left, right = test.left, test.comparators[0]
    if isinstance(op, (ast.Lt, ast.LtE)) and isinstance(left, ast.Name):
        if isinstance(right, (ast.Constant, ast.Name)):
            if isinstance(right, ast.Constant) and not _numeric_operand(right):
                return None
            if not _limit_is_independent(test, left.id):
                return None
            return left.id
    if isinstance(op, (ast.Gt, ast.GtE)) and isinstance(right, ast.Name):
        if isinstance(left, (ast.Constant, ast.Name)):
            if isinstance(left, ast.Constant) and not _numeric_operand(left):
                return None
            if not _limit_is_independent(test, right.id):
                return None
            return right.id
    return None


def _reviewed_keys(test: ast.AST) -> Set[str]:
    """Access paths whose message field was constrained by this comparison."""
    out = set()
    for n in _iter_nodes(test):
        if isinstance(n, ast.Attribute) and n.attr in MESSAGE_FIELDS:
            value = n.value
            if isinstance(value, ast.Attribute) and value.attr == "message":
                value = value.value
            key = _path_key(value)
            if key:
                out.add(key)
    return out


def _review_polarity(test: ast.AST) -> Optional[bool]:
    """Which truth value of `test` means the message matched the expectation.

    `msg.account_keys[0] != EXPECTED` is True when the payer is *wrong*, so the
    fall-through path is the reviewed one. `== EXPECTED` is the opposite, and
    treating it as review would authorize every payer except the expected one.
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    if not _reviewed_keys(test):
        return None
    op = test.ops[0]
    if isinstance(op, ast.NotEq):
        return False        # False == matched
    if isinstance(op, ast.Eq):
        return True         # True == matched
    return None


def _rejects(body: List[ast.stmt]) -> bool:
    return any(isinstance(s, (ast.Raise, ast.Return, ast.Continue, ast.Break))
               for s in body)


def _negation_fact(test: ast.AST, tainted: Set[str]) -> Dict[str, bool]:
    """Which paths are policy-cleared when `test` is False.

    Only a membership test against a *trusted* collection establishes a policy
    fact. `x not in {x}` proves nothing. `x in ALLOWED` being false means the
    value is the disallowed one, so it never clears.
    """
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        if isinstance(test.ops[0], ast.NotIn):
            if _names(test.comparators[0]) & tainted:
                return {}
            key = _path_key(test.left)
            return {key: True} if key else {}
        if isinstance(test.ops[0], ast.In):
            return {}
    return {}


def _positive_fact(test: ast.AST, tainted: Set[str]) -> Dict[str, bool]:
    """Which paths are policy-cleared when `test` is True."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        if isinstance(test.ops[0], ast.In):
            if _names(test.comparators[0]) & tainted:
                return {}
            key = _path_key(test.left)
            return {key: True} if key else {}
        if isinstance(test.ops[0], ast.NotIn):
            return {}
    # A function's spelling alone is not a validation contract.
    return {}


def _review_helper_params(tree: ast.AST) -> Dict[str, Dict[int, str]]:
    """function name -> {param index: param name} it provably enforces.

    A helper is a review helper only if its body *unconditionally* rejects when
    the parameter's message field is wrong. Polarity is checked (`== EXPECTED:
    raise` rejects the *allowed* payer, so it is not enforcement), a check nested
    under another condition is not unconditional, and an `async` helper enforces
    nothing unless its caller awaits it (seventh-pass F7-H03).
    """
    out: Dict[str, Dict[int, str]] = {}
    definitions = {}
    shadowed = set()
    for node in _iter_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions[node.name] = definitions.get(node.name, 0) + 1
            shadowed.update(a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            shadowed.update(_assign_targets(node))
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                shadowed.add(node.target.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            shadowed.update(a.asname or a.name.split(".")[0] for a in node.names)
    for node in _iter_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in shadowed or definitions[node.name] != 1:
            continue
        params = [a.arg for a in node.args.posonlyargs + node.args.args]
        if not params:
            continue
        enforced: Dict[int, str] = {}
        writes = set()
        for sub in _iter_nodes(node):
            if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                writes.update(_assign_targets(sub))
                writes.update(_base_of(k) for k in _store_paths(sub))
        for stmt in node.body:
            if isinstance(stmt, (ast.Return, ast.Raise)):
                break
            if not isinstance(stmt, ast.If):
                # A preceding conditional return or swallowed rejection prevents
                # this intentionally narrow summary from proving enforcement.
                if any(isinstance(n, (ast.Return, ast.Try, ast.With, ast.For, ast.While))
                       for n in _iter_nodes(stmt)):
                    break
                continue
            if not stmt.body or not isinstance(stmt.body[0], ast.Raise):
                if any(isinstance(n, ast.Return) for n in _iter_nodes(stmt)):
                    break
                continue
            if _review_polarity(stmt.test) is not False:
                continue          # only `!= EXPECTED: raise` enforces
            left, right = stmt.test.left, stmt.test.comparators[0]
            if _reviewed_keys(left) and _reviewed_keys(right):
                continue
            actual, expected = (left, right) if _reviewed_keys(left) else (right, left)
            if _names(expected) & (set(params) | writes):
                continue
            for i, p in enumerate(params):
                if p in _reviewed_keys(actual) and p not in writes:
                    enforced[i] = p
        if enforced:
            out[node.name] = enforced
    return out


def _async_helper_names(tree: ast.AST) -> Set[str]:
    return {n.name for n in _iter_nodes(tree)
            if isinstance(n, ast.AsyncFunctionDef)}


class Exits:
    """Every route a block can leave through, with the state on each."""

    __slots__ = ("normal", "returns", "raises", "breaks", "continues")

    def __init__(self):
        self.normal: Optional[Dict[str, Info]] = None
        self.returns: List[Dict[str, Info]] = []
        self.raises: List[Dict[str, Info]] = []
        self.breaks: List[Dict[str, Info]] = []
        self.continues: List[Dict[str, Info]] = []

    def all_states(self) -> List[Dict[str, Info]]:
        out = []
        if self.normal is not None:
            out.append(self.normal)
        out.extend(self.returns)
        out.extend(self.raises)
        out.extend(self.breaks)
        out.extend(self.continues)
        return out

    def __repr__(self):
        return (f"Exits(normal={self.normal is not None}, r={len(self.returns)}, "
                f"x={len(self.raises)}, b={len(self.breaks)}, "
                f"c={len(self.continues)})")


def _normal(state) -> Exits:
    e = Exits()
    e.normal = state
    return e


class Analysis:
    """Result of walking one module."""

    def __init__(self):
        self.sinks: List[Tuple[ast.Call, Dict[str, Info], object]] = []
        self.states: Dict[int, Dict[str, Info]] = {}
        self.arguments: Dict[int, List[Tuple[ast.AST, Info]]] = {}
        self.receivers: Dict[int, Info] = {}
        self.rpc_unsafe = set()
        self.rpc_unawaited = set()
        self.values = {}

    def state_for(self, node: ast.AST) -> Optional[Dict[str, Info]]:
        return self.states.get(id(node))


def flow_insensitive_taint(tree: ast.AST, is_model_origin) -> Set[str]:
    """Names that derive from a model source, independent of statement order.

    The interpreter is a forward pass, so a reverse-ordered alias chain would
    need one iteration per link. This worklist resolves it in
    O(assignments + references) and seeds the interpreter.
    """
    assigns = []
    pending = [tree]
    while pending:
        node = pending.pop()
        if node is not tree and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(node))
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            value = getattr(node, "value", None)
            if value is None:
                continue
            targets = _assign_targets(node)
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                targets.append(node.target.id)
            targets += [_base_of(key) for key in _store_paths(node)]
            if targets:
                assigns.append((targets, value))
    if not assigns:
        return set()

    dependents: Dict[str, List[int]] = {}
    for idx, (_targets, value) in enumerate(assigns):
        for n in _names(value):
            dependents.setdefault(n, []).append(idx)

    tainted: Set[str] = set()
    done: Set[int] = set()
    queue = [i for i, (_t, v) in enumerate(assigns)
             if any(is_model_origin(part, {}) for part in _iter_nodes(v))]
    head = 0
    while head < len(queue):
        idx = queue[head]
        head += 1
        if idx in done:
            continue
        done.add(idx)
        targets, _value = assigns[idx]
        for t in targets:
            if t in tainted:
                continue
            tainted.add(t)
            for j in dependents.get(t, ()):
                if j not in done:
                    queue.append(j)
    return tainted


class Interpreter:
    def __init__(self, tree: ast.AST, is_model_origin, bindings: dict,
                 initial_taint: Optional[Set[str]] = None, parameter_taint=False):
        self.tree = tree
        self.is_model_origin = is_model_origin
        self.bindings = bindings
        self.result = Analysis()
        self.initial_taint = initial_taint or set()
        self.parameter_taint = parameter_taint
        self.current_scope = None
        self.exception_states = []
        self.steps = 0
        self.captures = {}
        self.defaults = {}
        self.write_serial = 0
        self.last_writes = {}
        self.review_call_values = {}
        self.async_client_names = {a.asname or a.name for sub in _iter_nodes(tree)
                                   if isinstance(sub, ast.ImportFrom) and sub.module == "solana.rpc.async_api"
                                   for a in sub.names if a.name in ("AsyncClient", "Client")}
        self.async_client_objects = set()
        self.pending_rpc = {}
        self.scope_parents = {}
        self.scope_nodes = {None: tree}
        self.future_taint = {}
        pending = [(tree, None)]
        while pending:
            sub, scope = pending.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.scope_parents[id(sub)] = scope
                self.scope_nodes[id(sub)] = sub
                scope = id(sub)
            pending.extend((child, scope) for child in ast.iter_child_nodes(sub))
        self.scope_exits: Dict[object, Dict[str, Info]] = {}
        self.review_helpers = _review_helper_params(tree)
        self.async_helpers = _async_helper_names(tree)
        self.rebound_calls = set()
        self.helper_expectations = {}
        for sub in _iter_nodes(tree):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.rebound_calls.add(sub.name)
                self.rebound_calls.update(a.arg for a in sub.args.args + sub.args.kwonlyargs + sub.args.posonlyargs)
                if sub.name in self.review_helpers:
                    expected = []
                    for stmt in sub.body:
                        if isinstance(stmt, ast.If) and _review_polarity(stmt.test) is False:
                            left, right = stmt.test.left, stmt.test.comparators[0]
                            expected.append(right if _reviewed_keys(left) else left)
                    self.helper_expectations[sub.name] = expected
            elif isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                self.rebound_calls.update(_assign_targets(sub))
        # Every path key ("x['k']") ever written. Kept so invalidation does not
        # have to scan the whole state per assignment.
        self.path_keys: Set[str] = set()
        self.paths_by_base = {}
        for node in _iter_nodes(tree):
            if isinstance(node, (ast.Subscript, ast.Attribute)):
                key = _path_key(node)
                if key and ("[" in key or "." in key):
                    self.path_keys.add(key)
                    self.paths_by_base.setdefault(_base_of(key), set()).add(key)

    # -- aliases -----------------------------------------------------------
    def _alias_group(self, name: str, state) -> Set[str]:
        origins = state.get(name, Info()).objects
        if not origins:
            return {name}
        self._charge(len(state))
        return {k for k, info in state.items()
                if _base_of(k) == k and info.objects & origins} | {name}


    def _invalidate(self, state, base: str, keep: Optional[str] = None,
                    whole_group: bool = False):
        """Drop the facts for `base` (and, optionally, its aliases).

        A plain assignment rebinds one name: `x0 = x1` is a value copy, so
        invalidating the whole alias group would erase the *source's* provenance
        and lose a reverse-ordered alias chain. A store *through* an object
        (`other["k"] = v`) mutates shared state, so that case invalidates every
        alias of the base.
        """
        names = self._alias_group(base, state) if whole_group else {base}
        for name in names:
            for key in self.paths_by_base.get(name, ()):
                if not _under_base(key, name):
                    continue
                if keep is not None and key == keep:
                    continue
                state.pop(key, None)
            if keep != name:
                state.pop(name, None)

    # -- helper summaries --------------------------------------------------
    def _apply_helper_reviews(self, call: ast.Call, state,
                              awaited: bool = False) -> None:
        """Apply a review helper's postcondition to the argument it checks.

        The summary comes from the helper's own body, so the name alone proves
        nothing. Keyword arguments bind like positional ones, and an `async`
        helper only runs when the call is awaited -- creating a coroutine
        executes nothing (seventh-pass F7-H03/F7-M01).
        """
        f = call.func
        name = f.id if isinstance(f, ast.Name) else ""
        params = self.review_helpers.get(name)
        if not params:
            return
        if name in self.async_helpers and not awaited:
            return
        if any(self._eval(expr, state).tainted for expr in self.helper_expectations.get(name, ())):
            return

        captured = self.review_call_values.get(id(call))
        if captured is None:
            return
        arguments, serials, scope = captured

        def mark(expr, info, serial):
            if isinstance(expr, ast.Attribute) and expr.attr == "message":
                expr = expr.value
            key = _path_key(expr)
            if not key:
                return
            # Argument evaluation can rebind or mutate an earlier argument.
            # The helper reviewed the captured value, not that later binding.
            base = _base_of(key)
            if self.last_writes.get((scope, base), 0) > serial:
                return
            current = state.get(key, info)
            state[key] = _with(current, reviewed=True)

        for i, (a, info) in enumerate(arguments[:len(call.args)]):
            if i in params:
                mark(a, info, serials[i])
        for i, kw in enumerate(call.keywords, len(call.args)):
            if kw.arg and kw.arg in params.values():
                mark(kw.value, arguments[i][1], serials[i])

    # -- public ------------------------------------------------------------
    def run(self) -> Analysis:
        try:
            self._run_module()
        except RecursionError as exc:
            raise AnalysisError("RecursionError while walking the module") from exc
        except AnalysisError:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed
            raise AnalysisError(
                f"{type(exc).__name__} while walking the module: {exc}") from exc
        return self.result

    # -- scopes ------------------------------------------------------------
    def _run_module(self):
        entry = {n: Info(True, origins={n}) for n in self.initial_taint}
        exits = self._exec_body(self.tree.body, entry, None)
        self._complete_rpc(exits)
        self.scope_exits[None] = exits.normal if exits.normal is not None else entry
        for node in _iter_nodes(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent = self.scope_parents.get(id(node))
                base = self.scope_exits.get(parent, self.scope_exits.get(None, {}))
                captured = self.captures.get(id(node))
                if captured is not None:
                    base = merge(base, captured)
                entry = self._func_entry(node, base)
                exits = self._exec_body(node.body,
                                        entry,
                                        id(node))
                routes = exits.all_states()
                self.scope_exits[id(node)] = _join_all(routes) if routes else entry
                self._complete_rpc(exits)

    def _func_entry(self, node, base: Dict[str, Info]) -> Dict[str, Info]:
        """Entry state for a function: drop names it binds itself."""
        local = {a.arg for a in node.args.args}
        local |= {a.arg for a in node.args.kwonlyargs}
        local |= {a.arg for a in node.args.posonlyargs}
        if node.args.vararg:
            local.add(node.args.vararg.arg)
        if node.args.kwarg:
            local.add(node.args.kwarg.arg)
        pending = list(node.body)
        while pending:
            sub = pending.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local.add(sub.name)
                continue
            if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                local.update(_assign_targets(sub))
            elif isinstance(sub, (ast.For, ast.AsyncFor)):
                local.update(_assign_targets(
                    ast.Assign(targets=[sub.target], value=sub.iter)))
            pending.extend(ast.iter_child_nodes(sub))
        out = {k: v for k, v in base.items() if _base_of(k) not in local}
        for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            out[f"@param:{a.arg}"] = Info(True)
        # Parameters belong to this scope; a same-spelled parameter in another
        # function must not poison a trusted module constant.
        if self.parameter_taint:
            args = node.args
            for a in args.posonlyargs + args.args + args.kwonlyargs:
                out[a.arg] = Info(True, origins={id(a)}, objects={id(a)})
            for a in (args.vararg, args.kwarg):
                if a:
                    out[a.arg] = Info(True, origins={id(a)}, objects={id(a)})
        for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            ann = a.annotation
            if isinstance(ann, ast.Name) and ann.id in ("int", "float"):
                out[a.arg] = _with(out.get(a.arg, Info()), numeric=True)
        for name, info in self.defaults.get(id(node), {}).items():
            out[name] = join_info((out.get(name, Info()), info))
        return out

    # -- statement dispatch ------------------------------------------------
    def _exec_body(self, stmts, state, scope) -> Exits:
        acc = Exits()
        cur = state
        for stmt in stmts:
            if cur is None:
                break
            self.current_scope = scope
            e = self._exec_stmt(stmt, cur, scope)
            acc.returns.extend(e.returns)
            acc.raises.extend(e.raises)
            acc.breaks.extend(e.breaks)
            acc.continues.extend(e.continues)
            cur = e.normal
        acc.normal = cur
        return acc

    def _exec_stmt(self, stmt, state, scope) -> Exits:
        self._charge()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in stmt.decorator_list:
                self._eval(decorator, state)
            positional = stmt.args.posonlyargs + stmt.args.args
            pairs = list(zip(positional[len(positional) - len(stmt.args.defaults):], stmt.args.defaults))
            pairs += list(zip(stmt.args.kwonlyargs, stmt.args.kw_defaults))
            self.defaults[id(stmt)] = {a.arg: self._eval(default, state)
                                       for a, default in pairs if default is not None}
            self._charge(len(state))
            self.captures[id(stmt)] = dict(state)
            return _normal(state)

        if isinstance(stmt, ast.ClassDef):
            self._charge(len(state))
            exits = self._exec_body(stmt.body, dict(state), id(stmt))
            self.scope_exits[id(stmt)] = _join_all(exits.all_states())
            return _normal(state)

        if isinstance(stmt, ast.If):
            return self._exec_if(stmt, state, scope)

        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            return self._exec_loop(stmt, state, scope)

        if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            return self._exec_try(stmt, state, scope)

        if isinstance(stmt, ast.Match):
            return self._exec_match(stmt, state, scope)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                info = self._eval(item.context_expr, state)
                if item.optional_vars is not None:
                    self._write_target(item.optional_vars, info, state)
            inner = self._exec_body(stmt.body, state, scope)
            # __exit__ may suppress an exception. Keep the normal continuation
            # unless the manager is known not to suppress; never drop its state.
            routes = ([inner.normal] if inner.normal is not None else []) + inner.raises
            inner.normal = _join_all(routes) if routes else None
            return inner

        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(stmt, ast.AnnAssign) and stmt.value is None:
                # A bare annotation does not store a value, but Python still
                # evaluates a subscript/attribute target's base and index.
                self._eval_store_target(stmt.target, state)
                return _normal(state)
            return _normal(self._exec_assign(stmt, state, scope))

        if isinstance(stmt, ast.Expr):
            self._record_sinks(stmt.value, state, scope)
            return _normal(state)

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._record_sinks(stmt.value, state, scope)
            e = Exits()
            e.returns.append(state)
            return e

        if isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._record_sinks(stmt.exc, state, scope)
            e = Exits()
            e.raises.append(state)
            return e

        if isinstance(stmt, ast.Break):
            e = Exits()
            e.breaks.append(state)
            return e

        if isinstance(stmt, ast.Continue):
            e = Exits()
            e.continues.append(state)
            return e

        if isinstance(stmt, ast.Assert):
            # `assert cond` rejects when cond is FALSE, and it is removable under
            # -O, so it never establishes a security fact here.
            self._record_sinks(stmt.test, state, scope)
            return _normal(state)

        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._write_target(target, None, state)
            return _normal(state)

        self._record_sinks(stmt, state, scope)
        return _normal(state)

    def _tainted(self, state) -> Set[str]:
        return {_base_of(k) for k, i in state.items() if i.tainted} | {
            k.split(":", 1)[1] for k in state if k.startswith("@param:")}

    def _exec_if(self, stmt: ast.If, state, scope) -> Exits:
        self._charge(len(state) * 2)
        self._record_sinks(stmt.test, state, scope)

        body_state = dict(state)
        else_state = dict(state)

        # A bound needs an independent limit, and holds on the branch that does
        # not reject.
        if _rejects(stmt.body):
            bound = _bounded_when_false(stmt.test)
            if bound and self._valid_limit(stmt.test, bound, state):
                else_state[bound] = _with(else_state.get(bound, Info()), bounded=True)
        elif _rejects(stmt.orelse):
            bound = _bounded_when_true(stmt.test)
            if bound and self._valid_limit(stmt.test, bound, state):
                body_state[bound] = _with(body_state.get(bound, Info()), bounded=True)

        error, failed_when_true = self._error_test(stmt.test)
        successful = None
        if error is not None and _rejects(stmt.body) and failed_when_true:
            successful = else_state
        elif error is not None and _rejects(stmt.orelse) and not failed_when_true:
            successful = body_state
        if successful is not None:
            value = self._eval(error, state)
            for token in value.objects:
                key = f"@sim:{token}"
                if key in successful:
                    successful[key] = _with(successful[key], cleared=True)

        matched = _review_polarity(stmt.test)
        if matched is not None and self._independent_review(stmt.test, state):
            keys = _reviewed_keys(stmt.test)
            target = None
            if _rejects(stmt.body) and matched is False:
                target = else_state
            elif _rejects(stmt.orelse) and matched is True:
                target = body_state
            if target is not None:
                for k in keys:
                    info = target.get(k, target.get(_base_of(k), Info()))
                    fields = {n.attr for n in _iter_nodes(stmt.test)
                              if isinstance(n, ast.Attribute) and n.attr in MESSAGE_FIELDS}
                    target[k] = _with(info, reviewed=True, review_fields=fields)

        tainted = self._tainted(state)
        body_state = self._apply_facts(body_state, _positive_fact(stmt.test, tainted))
        else_state = self._apply_facts(else_state, _negation_fact(stmt.test, tainted))

        known = self._truth(stmt.test)
        body = self._exec_body(stmt.body, body_state, scope) if known is not False else Exits()
        other = self._exec_body(stmt.orelse, else_state, scope) if known is not True else Exits()

        out = Exits()
        out.returns.extend(body.returns)
        out.returns.extend(other.returns)
        out.raises.extend(body.raises)
        out.raises.extend(other.raises)
        out.breaks.extend(body.breaks)
        out.breaks.extend(other.breaks)
        out.continues.extend(body.continues)
        out.continues.extend(other.continues)

        normals = [s for s in (body.normal, other.normal) if s is not None]
        out.normal = _join_all(normals) if normals else None
        return out

    def _exec_loop(self, stmt, state, scope) -> Exits:
        carried = dict(state)
        converged = False
        break_states: List[Dict[str, Info]] = []
        return_states: List[Dict[str, Info]] = []
        raise_states: List[Dict[str, Info]] = []

        for _ in range(MAX_LOOP_PASSES):
            self._charge(len(state) + len(carried))
            entry = merge(state, carried)
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                info = self._eval(stmt.iter, entry)
                body = dict(entry)
                self._write_target(stmt.target, _with(
                    info, cleared=False, bounded=False, reviewed=False), body)
            else:
                self._record_sinks(stmt.test, entry, scope)
                body = dict(entry)

            inner = self._exec_body(stmt.body, body, scope)
            break_states = list(inner.breaks)
            return_states = list(inner.returns)
            raise_states = list(inner.raises)

            backs = ([inner.normal] if inner.normal is not None else []) + inner.continues
            back = _join_all(backs) if backs else dict(entry)
            new_carried = merge(carried, back)
            if new_carried == carried:
                carried = new_carried
                converged = True
                break
            carried = new_carried

        if not converged:
            raise AnalysisError(
                f"loop at line {getattr(stmt, 'lineno', 0)} did not converge "
                f"within {MAX_LOOP_PASSES} passes")

        out = Exits()
        out.returns.extend(return_states)
        out.raises.extend(raise_states)

        # A `break` skips `else` entirely, so break states must not be joined
        # with the completion route before the else body runs (F7-H07).
        completed: Optional[Dict[str, Info]] = merge(entry, carried)

        if stmt.orelse:
            inner = self._exec_body(stmt.orelse, dict(completed), scope)
            out.returns.extend(inner.returns)
            out.raises.extend(inner.raises)
            out.breaks.extend(inner.breaks)
            out.continues.extend(inner.continues)
            completed = inner.normal

        routes = ([completed] if completed is not None else []) + break_states
        out.normal = _join_all(routes) if routes else None
        return out

    def _exec_match(self, stmt: ast.Match, state, scope) -> Exits:
        subject = self._eval(stmt.subject, state)
        out = Exits()
        normals: List[Dict[str, Info]] = []
        for case in stmt.cases:
            new = dict(state)
            for sub in _iter_nodes(case.pattern):
                if isinstance(sub, ast.MatchAs) and sub.name:
                    new[sub.name] = _with(subject, cleared=False, reviewed=False)
                if isinstance(sub, ast.MatchStar) and sub.name:
                    new[sub.name] = _with(subject, cleared=False, reviewed=False)
                if isinstance(sub, ast.MatchMapping) and sub.rest:
                    new[sub.rest] = _with(subject, cleared=False, reviewed=False)
            if case.guard is not None:
                self._record_sinks(case.guard, new, scope)
                self._eval(case.guard, new)
            inner = self._exec_body(case.body, new, scope)
            out.returns.extend(inner.returns)
            out.raises.extend(inner.raises)
            out.breaks.extend(inner.breaks)
            out.continues.extend(inner.continues)
            if inner.normal is not None:
                normals.append(inner.normal)
        normals.append(dict(state))               # no case matched
        out.normal = _join_all(normals)
        return out

    def _exec_try(self, stmt, state, scope) -> Exits:
        self._charge(len(state) * 2)
        self.exception_states.append(dict(state))
        body = self._exec_body(stmt.body, dict(state), scope)
        intermediate = self.exception_states.pop()

        # A handler is reachable from the entry state, from any explicit raise,
        # and from any operation in the body that can raise implicitly (F6-H05).
        handler_entry = _join_all(
            [state, intermediate] + body.raises + ([body.normal] if body.normal is not None else []))

        out = Exits()
        out.returns.extend(body.returns)
        out.raises.extend(body.raises)
        out.breaks.extend(body.breaks)
        out.continues.extend(body.continues)
        normals: List[Dict[str, Info]] = []
        if body.normal is not None:
            normals.append(body.normal)

        if stmt.orelse and body.normal is not None:
            inner = self._exec_body(stmt.orelse, dict(body.normal), scope)
            out.returns.extend(inner.returns)
            out.raises.extend(inner.raises)
            out.breaks.extend(inner.breaks)
            out.continues.extend(inner.continues)
            normals = [inner.normal] if inner.normal is not None else []

        # A handled exception is a normal exit: the handler consumed it.
        for handler in stmt.handlers:
            inner = self._exec_body(handler.body, dict(handler_entry), scope)
            out.returns.extend(inner.returns)
            out.raises.extend(inner.raises)
            out.breaks.extend(inner.breaks)
            out.continues.extend(inner.continues)
            if inner.normal is not None:
                normals.append(inner.normal)

        # A handler can itself raise, and an exception need not match a handler.
        # Both pending routes still execute finally. Clearing raises here lost
        # every sink reached through a re-raising handler.

        merged = _join_all(normals) if normals else None

        # finally runs on EVERY route, including normal completion. Holding the
        # normal route in a local variable until after this block meant
        # `try: work() finally: transfer(...)` was never analysed (F7-H06).
        if stmt.finalbody:
            pending = out
            out = Exits()
            normal_routes = []
            routes = [("normal", merged)] if merged is not None else []
            for kind in ("returns", "raises", "breaks", "continues"):
                routes.extend((kind, s) for s in getattr(pending, kind))
            for kind, route in routes:
                inner = self._exec_body(stmt.finalbody, dict(route), scope)
                for exit_kind in ("returns", "raises", "breaks", "continues"):
                    getattr(out, exit_kind).extend(getattr(inner, exit_kind))
                if inner.normal is not None:
                    if kind == "normal":
                        normal_routes.append(inner.normal)
                    else:
                        getattr(out, kind).append(inner.normal)
            merged = _join_all(normal_routes) if normal_routes else None

        out.normal = merged
        return out

    def _exec_assign(self, stmt, state, scope):
        if isinstance(stmt, ast.AugAssign):
            base = _root_name(stmt.target)
            group = self._alias_group(base, state) if base else set()
            # Augmented assignment captures and reads the target before RHS
            # evaluation, which may rebind its original root name.
            prev = self._eval(stmt.target, state)
            rhs = self._eval(stmt.value, state)
            info = join_info((prev, rhs))
            info = _with(info, cleared=False, reviewed=False, constant=UNKNOWN)
            self._write_target(stmt.target, info, state, captured=group, evaluate=False)
        else:
            info = self._eval(stmt.value, state)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                self._write_target(target, info, state)
        return state

    def _eval_store_target(self, target, state):
        """Evaluate an lvalue without reading or replacing the value it holds."""
        if isinstance(target, ast.Subscript):
            self._eval(target.value, state)
            self._eval(target.slice, state)
        elif isinstance(target, ast.Attribute):
            self._eval(target.value, state)

    def _write_target(self, target, info, state, captured=None, evaluate=True):
        if isinstance(target, ast.Starred):
            self._write_target(target.value, info, state)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._write_target(element, info, state)
            return
        if isinstance(target, ast.Name):
            self._invalidate(state, target.id)
            if info is not None:
                state[target.id] = info.copy()
            self._track_write(target.id, info or Info())
            return
        base = _root_name(target)
        group = set(captured or ())
        if base:
            group.update(self._alias_group(base, state))
        if evaluate:
            self._eval_store_target(target, state)
        if not base:
            return
        # Include both captured aliases and current aliases when evaluating the
        # target or RHS rebinds its root. Losing the former leaves stale facts on
        # the object that Python actually mutates.
        group.update(self._alias_group(base, state))
        prior = {name: state.get(name, Info()) for name in group}
        key = _path_key(target)
        suffix = key[len(base):] if key else None
        for name in group:
            self._invalidate(state, name)
        for name, old in prior.items():
            value = join_info((old, info)) if info is not None else old
            state[name] = _with(value, cleared=False, reviewed=False, bounded=False)
            self._track_write(name, state[name])
            if suffix and info is not None:
                path = name + suffix
                state[path] = info.copy()
                self._track_write(path, info)

    def _track_write(self, key, info):
        self.write_serial += 1
        self.last_writes[(self.current_scope, _base_of(key))] = self.write_serial
        for summary in self.exception_states:
            summary[key] = join_info((summary.get(key, Info()), info))

    def _error_test(self, test):
        if isinstance(test, ast.Attribute) and test.attr == "err":
            return test.value, True
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            expr, polarity = self._error_test(test.operand)
            return expr, not polarity
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            if isinstance(test.left, ast.Attribute) and test.left.attr == "err":
                rhs = test.comparators[0]
                if isinstance(rhs, ast.Constant) and rhs.value is None:
                    if isinstance(test.ops[0], (ast.IsNot, ast.NotEq)):
                        return test.left.value, True
                    if isinstance(test.ops[0], (ast.Is, ast.Eq)):
                        return test.left.value, False
        return None, False

    def _complete_rpc(self, exits):
        for state in ([exits.normal] if exits.normal is not None else []) + exits.returns:
            for key, value in state.items():
                if key.startswith(("@sim:", "@send:", "@await:")) and value.tainted and not value.cleared:
                    self.result.rpc_unsafe.add(int(key.split(":", 1)[1]))
                    if key.startswith("@await:"):
                        self.result.rpc_unawaited.add(int(key.split(":", 1)[1]))

    def _rpc_call(self, call, arguments, state, forced=False):
        name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
        normalized = name.replace("_", "").lower()
        receiver = self.result.receivers.get(id(call), Info())
        if (not forced and receiver.objects & self.async_client_objects
                and normalized in {"simulatetransaction", "sendtransaction", "sendrawtransaction", "confirmtransaction", "getsignaturestatuses", "getlatestblockhash"}):
            self.pending_rpc[id(call)] = (call, arguments)
            state[f"@await:{id(call)}"] = Info(True)
            self._track_write(f"@await:{id(call)}", state[f"@await:{id(call)}"])
            return
        if normalized in {"simulatetransaction"}:
            key = f"@sim:{id(call)}"
            state[key] = Info(True)
            self._track_write(key, state[key])
        if normalized in {"sendtransaction", "sendrawtransaction", "sendandconfirm", "signandsend"}:
            for key, info in state.items():
                if key.startswith("@sim:"):
                    self._charge()
                    if info.tainted and not info.cleared:
                        self.result.rpc_unsafe.add(int(key.split(":", 1)[1]))
            facts = {id(e): i for e, i in arguments}
            configured = any(k.arg in {"commitment", "preflight_commitment", "opts", "confirm", "await_confirmation"}
                             and id(k.value) in facts
                             and not facts[id(k.value)].tainted
                             and facts[id(k.value)].constant not in (None, False)
                             for k in call.keywords)
            key = f"@send:{id(call)}"
            state[key] = Info(True, configured)
            self._track_write(key, state[key])
        if normalized in {"confirmtransaction", "awaitconfirmation", "getsignaturestatuses"}:
            for _, info in arguments:
                for token in info.objects:
                    key = f"@send:{token}"
                    if key in state:
                        state[key] = _with(state[key], cleared=True)

    def _valid_limit(self, test, name, state):
        other = test.comparators[0] if isinstance(test.left, ast.Name) and test.left.id == name else test.left
        value = self._eval(other, state)
        source = state.get(name, Info())
        return self._trusted_limit(value) and not (source.origins & value.origins)

    def _trusted_limit(self, info):
        if info.tainted and not info.bounded:
            return False
        if info.constant is UNKNOWN:
            return True
        return (isinstance(info.constant, (int, float))
                and not isinstance(info.constant, bool)
                and (not isinstance(info.constant, float) or math.isfinite(info.constant)))

    def _independent_review(self, test, state):
        if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
            return False
        left, right = test.left, test.comparators[0]
        if _reviewed_keys(left) and _reviewed_keys(right):
            return False
        value, expected = (left, right) if _reviewed_keys(left) else (right, left)
        actual_info = self._eval(value, state)
        expected_info = self._eval(expected, state)
        return not expected_info.tainted and not (actual_info.origins & expected_info.origins)

    def _opaque_mutations(self, call, arguments, receiver, state):
        name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
        if (name in READ_ONLY_CALLS and name not in self.rebound_calls) or name in self.review_helpers or self.is_model_origin(call, state):
            return
        expressions = [e for e, _ in arguments]
        if isinstance(call.func, ast.Attribute):
            expressions.append(call.func.value)
        mutator = name in {"update", "append", "extend", "insert", "setdefault", "__setitem__", "clear", "pop"}
        incoming = join_info(i for _, i in arguments)
        for expr in expressions:
            base = _root_name(expr)
            if base is None or base not in state:
                continue
            group = self._alias_group(base, state)
            prior = {a: state.get(a, Info()) for a in group}
            self._invalidate(state, base, whole_group=True)
            touched = {n.attr for n in _iter_nodes(expr)
                       if isinstance(n, ast.Attribute) and n.attr in MESSAGE_FIELDS}
            for a in group:
                value = join_info((prior[a], incoming)) if mutator else prior[a]
                unaffected = (bool(touched) and bool(value.review_fields)
                              and not (touched & value.review_fields))
                state[a] = _with(value, cleared=False,
                                 reviewed=value.reviewed if unaffected else False)
                self._track_write(a, state[a])


    def _record_sinks(self, node, state, scope):
        # `x: str` is an AnnAssign whose value is None; without this guard the
        # walk crashed and the rule reported clean on unanalysed source.
        if node is None:
            return
        self.current_scope = scope
        self._eval(node, state)

    def _apply_facts(self, state, facts):
        if not facts:
            return state
        new = dict(state)
        for key, cleared in facts.items():
            if key in new:
                if new[key].tainted:
                    new[key] = _with(new[key], cleared=cleared)
                continue
            # `plan["recipient"]` checked before any assignment to that path:
            # derive the fact from the base, or the check is silently dropped and
            # using the checked field looks unsafe.
            base = _base_of(key)
            if base in new and new[base].tainted:
                new[key] = _with(new[base], cleared=cleared)
        return new

    # -- expression evaluation --------------------------------------------
    def _eval(self, node, state) -> Info:
        if node is None:
            return Info()
        try:
            return self._eval_inner(node, state)
        except RecursionError as exc:
            raise AnalysisError(f"expression at line {getattr(node, 'lineno', 0)} exceeds analysis depth") from exc

    def _eval_inner(self, node, state) -> Info:
        self._charge()
        info = self._eval_value(node, state)
        if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            old = self.result.values.get(id(node))
            self.result.values[id(node)] = join_info((old, info)) if old is not None else info.copy()
        return info

    def _eval_value(self, node, state) -> Info:
        if isinstance(node, (ast.Attribute, ast.Subscript)) and self.is_model_origin(node, state):
            return Info(True, origins={id(node)}, objects={id(node)})
        if isinstance(node, ast.Constant):
            numeric = (isinstance(node.value, (int, float))
                       and not isinstance(node.value, bool)
                       and (not isinstance(node.value, float) or math.isfinite(node.value)))
            return Info(bounded=numeric, constant=node.value, numeric=numeric, embedded=True)
        if isinstance(node, ast.Await):
            info = self._eval_inner(node.value, state)
            for token in info.objects:
                if token in self.pending_rpc:
                    key = f"@await:{token}"
                    if key in state:
                        state[key] = _with(state[key], cleared=True)
                    call, arguments = self.pending_rpc[token]
                    self._rpc_call(call, arguments, state, forced=True)
            if isinstance(node.value, ast.Call):
                self._apply_helper_reviews(node.value, state, awaited=True)
            return info
        if isinstance(node, ast.Name):
            return state.get(node.id, Info()).copy()
        if isinstance(node, ast.Subscript):
            # Python captures the container before evaluating the index. The
            # index may rebind that same name through a walrus assignment.
            original = self._eval_inner(node.value, state)
            index = self._eval_inner(node.slice, state)
            key = _path_key(node)
            if key and key in state:
                return state[key].copy()
            base = _path_key(node.value)
            current = state.get(base, original)
            info = (join_info((original, current))
                    if original.objects & current.objects else original)
            if index.tainted:
                info = join_info((info, index))
            # An unknown index must never reuse a whole-value clearance.
            return _with(info, cleared=False, reviewed=False) if key is None else info
        if isinstance(node, ast.Attribute):
            key = _path_key(node)
            if key and key in state:
                return state[key].copy()
            base = _path_key(node.value)
            if base and base in state:
                return state[base].copy()
            return self._eval_inner(node.value, state)
        if isinstance(node, ast.Call):
            fname = (node.func.id if isinstance(node.func, ast.Name)
                     else getattr(node.func, "attr", ""))
            if isinstance(node.func, ast.Name) and fname in self.async_client_names:
                self.async_client_objects.add(id(node))
            receiver = Info()
            if isinstance(node.func, ast.Attribute):
                receiver = self._eval_inner(node.func, state)
            arguments = []
            serials = []
            for a in list(node.args) + [k.value for k in node.keywords]:
                arguments.append((a, self._eval_inner(a, state)))
                serials.append(self.write_serial)
            self.review_call_values[id(node)] = (arguments, serials, self.current_scope)
            previous = self.result.arguments.get(id(node))
            if previous is not None:
                arguments_for_report = [(a, join_info((i, old[1])))
                                        for (a, i), old in zip(arguments, previous)]
            else:
                arguments_for_report = arguments
            self.result.arguments[id(node)] = arguments_for_report
            self.result.receivers[id(node)] = join_info(
                (self.result.receivers.get(id(node), receiver), receiver))
            # Retain only paths this call reads. This snapshot is for diagnostics;
            # security rules consume the argument facts above, at evaluation time.
            used = {name: state[name] for name in _names(node) if name in state}
            old = self.result.states.get(id(node))
            self.result.states[id(node)] = merge(old, used) if old is not None else used
            self.result.sinks.append((node, used, self.current_scope))
            self._apply_helper_reviews(node, state)
            self._opaque_mutations(node, arguments, receiver, state)
            self._rpc_call(node, arguments, state)
            if isinstance(node.func, ast.Lambda):
                local = dict(state)
                params = node.func.args.posonlyargs + node.func.args.args
                for a, (_, info) in zip(params, arguments):
                    local[a.arg] = info
                for kw, (_, info) in zip(node.keywords, arguments[len(node.args):]):
                    if kw.arg:
                        local[kw.arg] = info
                return self._eval_inner(node.func.body, local)
            if self.is_model_origin(node, state):
                return Info(True, origins={id(node)}, objects={id(node)})
            parts = [i for _, i in arguments]
            if isinstance(node.func, ast.Attribute):
                parts.append(receiver)
            tainted = any(p.tainted for p in parts)
            tainted_parts = [p.cleared for p in parts if p.tainted]
            cleared = bool(tainted_parts) and all(tainted_parts)
            if fname not in {"Pubkey", "PublicKey", "from_string", "from_bytes", "bytes", "to_bytes", "message_data",
                              "transfer", "transfer_checked", "create_transfer_transaction", "Instruction"}:
                cleared = False
            bounded = False
            if (fname in CAPPING_CALLS and isinstance(node.func, ast.Name)
                    and fname not in self.rebound_calls and len(node.args) >= 2):
                # The limit must be independent of the value it limits:
                # `min(amount, amount + 1)` is the identity, not a cap (F7-H01).
                first, limit = arguments[0][1], arguments[1][1]
                if (self._trusted_limit(limit)
                        and not (first.origins & limit.origins)
                        and not (_names(node.args[1]) & _names(node.args[0]))):
                    bounded = True
            constant = UNKNOWN
            if fname in ("int", "float") and len(arguments) == 1:
                c = arguments[0][1].constant
                if isinstance(c, (str, int, float)) and len(str(c)) < 100:
                    try:
                        constant = int(c) if fname == "int" else float(c)
                        bounded = self._trusted_limit(Info(constant=constant))
                    except (ValueError, OverflowError):
                        pass
            reviewed = bool(parts) and all(p.reviewed for p in parts if p.tainted)
            if fname not in ("message_data", "bytes", "to_bytes"):
                reviewed = False
            if fname == "TransferParams":
                amounts = [i for k, (_, i) in zip(node.keywords, arguments) if k.arg in ("lamports", "amount", "value")]
                bounded = bool(amounts) and all(i.bounded for i in amounts)
            literal_parts = [i for _, i in arguments] if fname in ("b58decode", "fromhex") else parts
            return Info(tainted, cleared, bounded, reviewed,
                        frozenset().union(*(p.origins for p in parts)), constant,
                        {id(node)}, numeric=fname in ("int", "float") and fname not in self.rebound_calls,
                        embedded=fname in {"bytes", "bytearray", "b58decode", "encode", "decode", "fromhex", "join", "format"}
                        and bool(literal_parts) and all(p.embedded for p in literal_parts))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            infos = [self._eval_inner(e, state) for e in node.elts]
            return _with(join_info(infos), objects={id(node)}, embedded=all(i.embedded for i in infos))
        if isinstance(node, ast.Dict):
            infos, values = [], []
            for k, v in zip(node.keys, node.values):
                if k is not None:
                    infos.append(self._eval_inner(k, state))
                value = self._eval_inner(v, state)
                values.append(value)
                infos.append(value)
            # Keys are data too (iteration exposes them); numeric bounds on
            # transfer-parameter values remain independent of their field names.
            return _with(join_info(infos), objects={id(node)},
                         bounded=bool(values) and all(i.bounded for i in values),
                         numeric=bool(values) and all(i.numeric for i in values),
                         embedded=all(i.embedded for i in infos))
        if isinstance(node, ast.FormattedValue):
            infos = [self._eval_inner(node.value, state)]
            if node.format_spec is not None:
                infos.append(self._eval_inner(node.format_spec, state))
            return join_info(infos)
        if isinstance(node, ast.JoinedStr):
            infos = [self._eval_inner(v, state) for v in node.values
                     if isinstance(v, ast.FormattedValue)]
            info = join_info(infos)
            return _with(info, tainted=info.tainted or self.is_model_origin(node, state),
                         cleared=False, reviewed=False, bounded=False, numeric=False,
                         embedded=all(i.embedded for i in infos))
        if isinstance(node, ast.BinOp):
            # Flatten expression traversal, not its semantics. Large generated
            # arithmetic chains must not exhaust Python's call stack.
            stack, infos = [node], []
            while stack:
                cur = stack.pop()
                if isinstance(cur, ast.BinOp):
                    stack.append(cur.right)
                    stack.append(cur.left)
                else:
                    infos.append(self._eval_inner(cur, state))
            info = join_info(infos)
            return _with(info, tainted=info.tainted or self.is_model_origin(node, state),
                         cleared=False, reviewed=False, constant=UNKNOWN, objects=frozenset(),
                         embedded=all(i.embedded for i in infos))
        if isinstance(node, ast.BoolOp):
            return self._eval_boolop(node, state)
        if isinstance(node, ast.UnaryOp):
            return self._eval_inner(node.operand, state)
        if isinstance(node, ast.Compare):
            infos = [self._eval_inner(node.left, state)]
            skipped = []
            for index, comparator in enumerate(node.comparators):
                if index:
                    skipped.append(dict(state))
                infos.append(self._eval_inner(comparator, state))
            if skipped:
                merged = _join_all(skipped + [state])
                state.clear()
                state.update(merged)
            return _with(join_info(infos), cleared=False, reviewed=False, numeric=False)
        if isinstance(node, ast.IfExp):
            return self._eval_ifexp(node, state)
        if isinstance(node, ast.Starred):
            return self._eval_inner(node.value, state)
        if isinstance(node, ast.NamedExpr):
            info = self._eval_inner(node.value, state)
            key = _path_key(node.target)
            if key:
                self._invalidate(state, key)
                state[key] = info.copy()
                self._track_write(key, info)
            return info
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            first = self._eval_inner(node.generators[0].iter, state)
            local = dict(state)
            serial = self.write_serial
            if isinstance(node, ast.GeneratorExp):
                # A generator reads its free variables when consumed, possibly
                # after a later rebind. Include the scope's possible sources;
                # ordinary eager comprehensions still use their current state.
                if self.current_scope not in self.future_taint:
                    root = self.scope_nodes[self.current_scope]
                    self.future_taint[self.current_scope] = flow_insensitive_taint(
                        ast.Module(body=root.body, type_ignores=[]), self.is_model_origin)
                deferred = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
                deferred += [c for g in node.generators for c in g.ifs]
                deferred += [g.iter for g in node.generators[1:]]
                free = set().union(*(_names(expr) for expr in deferred))
                free &= self.future_taint[self.current_scope]
                for name in free:
                    self._invalidate(local, name)
                    local[name] = Info(True, origins={name})
            bound = set()
            for index, generator in enumerate(node.generators):
                value = first if index == 0 else self._eval_inner(generator.iter, local)
                if isinstance(generator.iter, (ast.List, ast.Tuple, ast.Set)) and not generator.iter.elts:
                    return Info(objects={id(node)})
                for t in _assign_targets(ast.Assign(targets=[generator.target], value=generator.iter)):
                    bound.add(t)
                    local[t] = _with(value, cleared=False, bounded=False, reviewed=False)
                for cond in generator.ifs:
                    self._eval_inner(cond, local)
                    if self._truth(cond) is False:
                        return Info(objects={id(node)})
            if isinstance(node, ast.DictComp):
                key = self._eval_inner(node.key, local)
                value = self._eval_inner(node.value, local)
                info = _with(join_info((key, value)), bounded=value.bounded,
                             numeric=value.numeric)
            else:
                info = self._eval_inner(node.elt, local)
            # Walrus writes escape the comprehension; mutations affect shared
            # objects too. The loop variable itself stays local. Keep the entry
            # path because the iterable may have zero items at runtime.
            touched = {name for (scope, name), stamp in self.last_writes.items()
                       if scope == self.current_scope and stamp > serial and name not in bound}
            if touched:
                merged = merge(state, local)
                for key, value in merged.items():
                    if _base_of(key) in touched:
                        state[key] = value
            return info
        if isinstance(node, ast.Lambda):
            local = dict(state)
            for a in node.args.args + node.args.kwonlyargs + node.args.posonlyargs:
                local[a.arg] = Info(True, origins={id(a)}, objects={id(a)})
            return self._eval_inner(node.body, local)
        # Unknown expression forms must propagate their operands. This also
        # visits executable f-string fields on every supported Python version.
        if isinstance(node, ast.AST):
            return join_info(self._eval_inner(c, state) for c in ast.iter_child_nodes(node))
        return Info()

    def _charge(self, amount=1):
        self.steps += amount
        if self.steps > MAX_ANALYSIS_STEPS:
            raise AnalysisError(f"analysis work budget ({MAX_ANALYSIS_STEPS} steps) exhausted")

    def _truth(self, node) -> Optional[bool]:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return None

    def _eval_boolop(self, node: ast.BoolOp, state) -> Info:
        """Short-circuit: only the operands that can run affect the state."""
        infos: List[Info] = []
        is_and = isinstance(node.op, ast.And)
        skipped = []
        for index, v in enumerate(node.values):
            infos.append(self._eval_inner(v, state))
            known = self._truth(v)
            if known is None:
                if index < len(node.values) - 1:
                    skipped.append(dict(state))
                continue
            if is_and and known is False:
                break             # later operands never run
            if not is_and and known is True:
                break
        merged = _join_all(skipped + [state])
        state.clear()
        state.update(merged)
        return join_info(infos)

    def _eval_ifexp(self, node: ast.IfExp, state) -> Info:
        """Only the selected arm runs; a dead arm cannot clear taint."""
        self._eval_inner(node.test, state)
        known = self._truth(node.test)
        if known is True:
            return self._eval_inner(node.body, state)
        if known is False:
            return self._eval_inner(node.orelse, state)
        # Unknown: evaluate each arm from the same incoming state so neither
        # arm's side effects leak into the other.
        snapshot = dict(state)
        body = self._eval_inner(node.body, state)
        body_state = dict(state)
        state.clear()
        state.update(snapshot)
        orelse = self._eval_inner(node.orelse, state)
        other_state = dict(state)
        merged = merge(body_state, other_state)
        state.clear()
        state.update(merged)
        return join_info((body, orelse))
