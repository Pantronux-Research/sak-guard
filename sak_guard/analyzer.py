"""
Code Analyzer — The worker agent's brain.

Analyzes code for bugs, logic errors, security issues, and intent compliance.
Worker owners can swap this out with their own approach — the subnet doesn't
prescribe HOW to analyze, only WHAT to return.

LLM-enhanced mode: When use_llm=True, the analyzer uses an LLM for deeper
semantic intent verification, falling back to heuristics if the LLM is
unavailable. Configure via environment variables:
    LLM_PROVIDER   = "openai" | "anthropic" | "ollama"  (default: "openai")
    LLM_MODEL      = model name  (default depends on provider)
    LLM_API_KEY    = API key     (not needed for ollama)
    LLM_BASE_URL   = custom endpoint (optional, used for OpenAI-compatible APIs)
    OLLAMA_HOST    = Ollama server URL (default: "http://localhost:11434")
"""

import ast
import json
import logging
import os
import re
from typing import List, Dict, Optional
from .limits import analysis_entry

logger = logging.getLogger(__name__)


# ─── LLM Client ──────────────────────────────────────────────────────────────

class LLMClient:
    """
    Thin wrapper over multiple LLM providers.
    Supports OpenAI-compatible APIs, Anthropic, and Ollama.
    Uses only stdlib + the provider's own lightweight SDK via HTTP.
    """

    def __init__(self):
        self.provider = os.environ.get("LLM_PROVIDER", "openai").lower()
        self.model = os.environ.get("LLM_MODEL", self._default_model())
        self.api_key = os.environ.get("LLM_API_KEY", "")
        self.base_url = os.environ.get("LLM_BASE_URL", "")
        self.ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def _default_model(self) -> str:
        defaults = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-sonnet-4-20250514",
            "ollama": "llama3",
        }
        return defaults.get(self.provider, "gpt-4o-mini")

    def chat(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Optional[str]:
        """
        Send a chat completion request. Returns the assistant response text,
        or None on any failure (so callers can fall back).
        """
        try:
            if self.provider == "openai":
                return self._chat_openai(system_prompt, user_prompt, temperature)
            elif self.provider == "anthropic":
                return self._chat_anthropic(system_prompt, user_prompt, temperature)
            elif self.provider == "ollama":
                return self._chat_ollama(system_prompt, user_prompt, temperature)
            else:
                logger.warning(f"Unknown LLM provider: {self.provider}")
                return None
        except Exception as e:
            logger.warning(f"LLM call failed ({self.provider}): {e}")
            return None

    # ── Provider implementations using urllib (no extra deps) ──

    def _http_post(self, url: str, headers: dict, body: dict, timeout: int = 30) -> dict:
        """POST JSON and return parsed response."""
        import urllib.request
        import urllib.error

        data = json.dumps(body).encode("utf-8")
        headers["User-Agent"] = "AgentVerificationNetwork/1.0"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise ValueError("LLM response exceeds the 1 MiB limit")
            return json.loads(payload.decode("utf-8"))

    def _chat_openai(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        base = self.base_url or "https://api.openai.com/v1"
        url = f"{base}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        body = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        resp = self._http_post(url, headers, body)
        return resp["choices"][0]["message"]["content"]

    def _chat_anthropic(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        body = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }
        resp = self._http_post(url, headers, body)
        return resp["content"][0]["text"]

    def _chat_ollama(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        url = f"{self.ollama_host}/api/chat"
        headers = {"Content-Type": "application/json"}
        body = {
            "model": self.model,
            "stream": False,
            "options": {"temperature": temperature},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        resp = self._http_post(url, headers, body)
        return resp["message"]["content"]

    def chat_vision(self, system_prompt: str, user_prompt: str,
                    image_b64: str, mime_type: str = "image/jpeg",
                    temperature: float = 0.2) -> Optional[str]:
        """
        Send an image + text to a vision-capable model (OpenAI-compatible only).
        Works with Venice AI (qwen3-vl-235b-a22b) via LLM_BASE_URL.
        Returns assistant response text, or None on failure.
        """
        try:
            if self.provider not in ("openai",):
                logger.warning(f"Vision not supported for provider: {self.provider}")
                return None

            base = self.base_url or "https://api.openai.com/v1"
            url = f"{base}/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
            body = {
                "model": self.model,
                "temperature": temperature,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": [
                        {"type": "text", "text": user_prompt},
                        {"type": "image_url", "image_url": {
                            "url": f"data:{mime_type};base64,{image_b64}"
                        }},
                    ]},
                ],
            }
            resp = self._http_post(url, headers, body, timeout=60)
            return resp["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"Vision LLM call failed ({self.provider}): {e}")
            return None


# Singleton — created once, reused across calls
_llm_client: Optional[LLMClient] = None


def _get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


# ─── LLM-powered intent analysis ─────────────────────────────────────────────

_INTENT_SYSTEM_PROMPT = """\
You are a code verification agent for a decentralized audit network.
Your job is to compare source code against its stated intent and find mismatches,
subtle logic errors, and security issues that pattern-matching cannot catch.

You MUST respond with valid JSON only — no markdown, no explanation outside the JSON.
"""

_INTENT_USER_TEMPLATE = """\
## Stated Intent
{intent}

## Language
{language}

## Source Code
```{language}
{code}
```

Analyze whether the code fulfills the stated intent. Look for:
1. **Intent mismatches** — the code does something different from what the intent describes.
2. **Subtle logic errors** — off-by-one, wrong operator, inverted conditions, missing edge cases.
3. **Security issues** — injection, hardcoded secrets, unsafe deserialization.
4. **Missing functionality** — features described in the intent but absent in code.

Return a JSON object with this exact schema:
{{
  "issues": [
    {{
      "type": "intent_mismatch | logic_error | security | missing_feature",
      "severity": "critical | high | medium | low",
      "line": <int, 0 if not line-specific>,
      "description": "<what is wrong>",
      "suggestion": "<how to fix it>"
    }}
  ],
  "summary": "<one-sentence overall assessment>"
}}

If the code perfectly matches the intent with no issues, return:
{{"issues": [], "summary": "Code correctly implements the stated intent."}}
"""


def _llm_analyze_intent(code: str, intent: str, language: str) -> Optional[List[Dict]]:
    """
    Use an LLM to semantically verify code against its stated intent.
    Returns a list of issue dicts (same format as heuristic analyzers),
    or None if the LLM call fails.
    """
    client = _get_llm_client()
    user_prompt = _INTENT_USER_TEMPLATE.format(
        intent=intent,
        language=language,
        code=code,
    )

    raw = client.chat(_INTENT_SYSTEM_PROMPT, user_prompt)
    if not isinstance(raw, str):
        return None

    # Parse the JSON response — be tolerant of markdown wrappers
    text = raw.strip()
    if text.startswith("```"):
        # Strip ```json ... ``` wrapper
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        logger.warning("LLM returned non-JSON response, falling back to heuristics")
        return None

    if not isinstance(data, dict):
        logger.warning("LLM response was not an object; falling back to heuristics")
        return None
    issues = data.get("issues", [])
    if not isinstance(issues, list):
        logger.warning("LLM 'issues' was not a list; falling back to heuristics")
        return None

    # Normalize issue format to match our standard schema. Each entry must be an
    # object: `[null]` or `["text"]` used to raise AttributeError on .get and
    # crash the optional pass (SG-20).
    normalized: List[Dict] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        sev = str(issue.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        try:
            line = int(issue.get("line", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            line = 0
        line = max(0, min(line, len(code.split("\n"))))
        normalized.append({
            "type": str(issue.get("type") or "intent_mismatch"),
            "severity": sev,
            "line": line,
            "description": str(issue.get("description") or ""),
            "suggestion": str(issue.get("suggestion") or ""),
        })

    return normalized


# ─── Main entry point ────────────────────────────────────────────────────────

@analysis_entry
def analyze_code(code: str, intent: str, language: str = "python", use_llm: bool = False) -> dict:
    """
    Main analysis entry point. Runs all analysis passes and combines results.

    Args:
        code: Source code to analyze.
        intent: Natural-language description of what the code should do.
        language: Programming language (default "python").
        use_llm: If True, attempt LLM-based intent analysis before falling
                 back to heuristic intent matching.

    Returns:
        {
            "issues": [...],
            "confidence": float,
            "passed": bool,
            "suggestions": [...]
        }
    """
    all_issues = []

    # Pass 1: AST / Syntax analysis
    ast_issues = analyze_syntax(code, language)
    all_issues.extend(ast_issues)

    # Pass 2: Pattern-based bug detection
    pattern_issues = analyze_patterns(code, language)
    all_issues.extend(pattern_issues)

    # Pass 3: Intent verification (LLM with heuristic fallback)
    intent_issues = None
    llm_used = False

    if use_llm:
        intent_issues = _llm_analyze_intent(code, intent, language)
        if intent_issues is not None:
            llm_used = True
            logger.info(f"LLM intent analysis returned {len(intent_issues)} issues")

    if intent_issues is None:
        # Fallback to heuristic intent matching
        intent_issues = analyze_intent(code, intent, language)

    all_issues.extend(intent_issues)

    # Solana client/agent patterns (PS-SOL-1..3). Run here so the default
    # strategy enforces the domain guardrail too -- previously only
    # security-focused called this, so --strategy default silently disabled it
    # (SG-07). Appended before de-duplication and before `passed` is derived, so
    # a critical PS-SOL-* finding can never ship with passed=true (SG-08).
    from .solana import scan_solana
    _sol = scan_solana(code)
    if _sol.get("issues"):
        all_issues.extend(_sol["issues"])
    # A rule that raised must not read as a clean file (F4-01/SG-17).
    for _err in (_sol.get("errors") or []):
        all_issues.append({
            "type": "analysis_error",
            "severity": "critical",
            "line": 0,
            "description": f"Required analysis did not complete: {_err}. "
                           "This result is not a clean verdict.",
            "suggestion": "Treat as a scan failure and fix the rule or the input.",
        })

    # Calculate confidence
    # De-duplicate here, at the single point where every channel's issues meet.
    # This was previously placed inside analyze_intent, so findings emitted by
    # analyze_patterns (notably base:off_by_one) were never deduplicated -- the same
    # finding appeared three times on one line. Dedupe where the streams merge, not
    # inside one of them.
    _seen, _uniq = set(), []
    for _i in all_issues:
        _k = (_i.get("description"), _i.get("line"), _i.get("severity"))
        if _k in _seen:
            continue
        _seen.add(_k)
        _uniq.append(_i)
    all_issues = _uniq

    confidence = calculate_confidence(all_issues, llm_used=llm_used)

    # Determine pass/fail
    critical_or_high = [i for i in all_issues if i.get("severity") in ("critical", "high")]
    passed = len(critical_or_high) == 0

    # Generate suggestions
    suggestions = generate_suggestions(all_issues, code)

    return {
        "issues": all_issues,
        "confidence": confidence,
        "passed": passed,
        "suggestions": suggestions,
    }


def analyze_syntax(code: str, language: str) -> List[Dict]:
    """Parse code and check for syntax/structural issues."""
    issues = []

    if language != "python":
        return issues

    # Try to parse the AST
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        issues.append({
            "type": "syntax_error",
            "severity": "critical",
            "line": e.lineno or 0,
            "description": f"Syntax error: {e.msg}",
            "suggestion": "Fix the syntax error before proceeding",
        })
        return issues

    # Walk the AST looking for common issues
    for node in ast.walk(tree):

        # Check for bare except clauses
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append({
                "type": "bad_practice",
                "severity": "medium",
                "line": node.lineno,
                "description": "Bare 'except:' clause catches all exceptions including KeyboardInterrupt and SystemExit",
                "suggestion": "Use 'except Exception:' instead",
            })

        # Check for assert statements (removed in optimized mode)
        if isinstance(node, ast.Assert):
            issues.append({
                "type": "reliability",
                "severity": "medium",
                "line": node.lineno,
                "description": "Assert statements are removed when Python runs with -O flag",
                "suggestion": "Use explicit if/raise for production validation",
            })

        # Check for mutable default arguments
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    issues.append({
                        "type": "bug",
                        "severity": "high",
                        "line": node.lineno,
                        "description": f"Mutable default argument in function '{node.name}'. Default mutable objects are shared across calls.",
                        "suggestion": "Use None as default and create the mutable object inside the function",
                    })

        # Check for unused variables (simple heuristic)
        if isinstance(node, ast.FunctionDef):
            assigned = set()
            used = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            assigned.add(target.id)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    used.add(child.id)
            unused = assigned - used - {"_", "__"}
            for var in unused:
                issues.append({
                    "type": "code_quality",
                    "severity": "low",
                    "line": node.lineno,
                    "description": f"Variable '{var}' is assigned but never used in function '{node.name}'",
                    "suggestion": f"Remove unused variable '{var}' or prefix with underscore",
                })

    return issues


def _ast_division_lines(code: str, *, tree=None):
    """Line numbers carrying a REAL division (BinOp with ast.Div).

    The regex division heuristic below scans raw source lines, so a `/` inside a string
    literal -- a URL, a file path, a regex -- is indistinguishable from the operator. That
    flagged `Client("https://api.mainnet-beta.solana.com")` as "division by variable
    without zero-check", because `/api` matched.

    Rather than trying to teach a regex about string context, gate the rule on the parser:
    a line only qualifies if the AST actually contains a division node on it. Returns None
    when the source does not parse (non-Python language, or a syntax error), so callers
    fall back to the old behaviour instead of silently reporting nothing.
    """
    import ast as _ast
    try:
        if tree is None:
            tree = _ast.parse(code)
    except SyntaxError:
        return None
    lines = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Div):
            # divisor must be a genuine runtime variable. Excluded:
            #  - plain literals (/2)
            #  - module-level UPPER_CASE constants (LAMPORTS_PER_SOL): those are
            #    fixed at import and are never zero, so flagging them is noise.
            right = node.right
            if isinstance(right, _ast.Constant):
                continue
            if isinstance(right, _ast.Name) and right.id.isupper():
                continue
            lines.add(getattr(node, "lineno", 0))
    return lines


def _ast_unsafe_eval_lines(code: str, *, tree=None):
    """Line numbers holding a real eval()/exec() call.

    The previous check was `if "eval(" in line`, which flagged
    `ast.literal_eval(...)` -- the exact safe alternative the rule's own
    suggestion recommends -- while `eval (x)` with a space walked through
    (SG-23). Resolving the call through the AST separates the two, because
    `literal_eval` is a different attribute name.
    Returns None when the source does not parse, so the caller can fall back to
    a word-boundary regex instead of dropping the rule.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None
    lines = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            name = f.id
        elif isinstance(f, ast.Attribute):
            name = f.attr
        else:
            name = ""
        if name in ("eval", "exec"):
            lines.add(getattr(node, "lineno", 0))
    return lines


NUMERIC_NAME_HINTS = ("age", "count", "num", "id", "year", "price", "amount",
                      "total", "size", "length", "index", "score")


def _iter_nodes_local(root):
    """Iterative pre-order walk; no recursion, so deep expressions cannot crash."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(ast.iter_child_nodes(node))




def _ast_concat_suspects(code: str, *, tree=None):
    """line -> [variable] for `"text" + var + "text"` where var looks numeric.

    Flattens each *maximal* Add chain exactly once. Processing every Add node in
    the tree re-walked the same left-associated subtree repeatedly, which was
    quadratic: an 8,000-term addition (16 KB) exceeded ten seconds (seventh-pass
    F7-H09). Returns None when the source does not parse.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    from .dataflow import Interpreter
    analysis = Interpreter(tree, lambda node, state: False, {}).run()

    # Parent map, so a node that is itself an operand of an Add is skipped: its
    # enclosing chain already covers it.
    parent: Dict[int, ast.AST] = {}
    for node in _iter_nodes_local(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    def _is_add(node) -> bool:
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)

    out = {}
    for node in _iter_nodes_local(tree):
        if not _is_add(node):
            continue
        par = parent.get(id(node))
        if par is not None and _is_add(par):
            continue                      # part of a bigger chain
        names, has_str = [], False
        stack = [node]
        while stack:
            cur = stack.pop()
            if _is_add(cur):
                stack.append(cur.left)
                stack.append(cur.right)
            elif isinstance(cur, ast.Constant) and isinstance(cur.value, str):
                has_str = True
            elif isinstance(cur, ast.Name):
                info = analysis.values.get(id(cur))
                if info is not None and info.numeric:
                    names.append(cur.id)
            elif isinstance(cur, ast.Constant) and isinstance(cur.value, (int, float)):
                names.append(repr(cur.value))
        if not has_str or not names:
            continue
        for v in names:
            out.setdefault(getattr(node, "lineno", 0), []).append(v)
    return out


def _ast_sql_injection(code: str, *, tree=None):
    """execute()/query() calls whose SQL is built by interpolation (SG-21).

    The old check matched `execute(` followed by `%s` anywhere on the line, so a
    correctly parameterized query (`execute("... WHERE id=%s", (v,))`) was
    reported as critical while a query built into a variable and then passed
    (`q = f"...{v}"; execute(q)`) was missed. What matters is whether the *query
    string itself* is assembled, so that is what is checked -- including through
    a variable.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    from .dataflow import Interpreter, UNKNOWN

    def constant(expr, state):
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.Name):
            return expr.id in state and state[expr.id].constant is not UNKNOWN
        if isinstance(expr, (ast.Tuple, ast.List)):
            return all(constant(e, state) for e in expr.elts)
        return False

    def assembled(expr, state):
        if isinstance(expr, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) and not constant(v.value, state)
                       for v in expr.values)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            operands = []
            stack = [expr]
            while stack:
                sub = stack.pop()
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Add, ast.Mod)):
                    stack.extend((sub.left, sub.right))
                else:
                    operands.append(sub)
            has_string = any(isinstance(e, ast.Constant) and isinstance(e.value, str)
                             or isinstance(e, ast.Name) and e.id in state and isinstance(state[e.id].constant, str)
                             for e in operands)
            return has_string and not all(constant(e, state) for e in operands)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return any(not constant(a, state) for a in expr.args) or any(not constant(k.value, state) for k in expr.keywords)
        return False

    analysis = Interpreter(tree, assembled, {}).run()

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
        if name not in ("execute", "executemany", "query", "raw"):
            continue
        if not node.args:
            continue
        args = analysis.arguments.get(id(node), [])
        if args and args[0][1].tainted:
            out.append((getattr(node, "lineno", 0), name))
    return out




# Values that are labels, not secrets: short public symbols like "SOL", "USD".
_PUBLIC_LABEL = re.compile(r"^[A-Z0-9_\-]{1,10}$")


def _ast_hardcoded_secrets(code: str, *, tree=None):
    """Assignments of a literal to a credential-shaped name (SG-22).

    The old regex scanned raw text, so `token = "SOL"` (a ticker) was a critical
    finding while `password: str = "..."` (an annotated assignment) was missed
    entirely.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    names = re.compile(r"(password|passwd|secret|api_key|apikey|token|"
                       r"private_key|access_key|auth_token)$", re.I)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = getattr(node, "value", None)
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        text = value.value
        if not text:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and names.search(t.id):
                if t.id.lower() == "token" and re.fullmatch(r"[A-Z]{2,5}", text):
                    continue   # ticker-shaped public label, not a password exemption
                out.append((getattr(node, "lineno", 0), t.id))
                break
    return out


def _ast_nonterminating_loops(code: str, *, tree=None):
    """`while` loops with no exit path and no progress (SG-24).

    The old check treated any `while x > 0:` without a later assignment as
    infinite, so `while n > 0: break` was critical while a loop whose counter was
    bumped *outside* the body was not reported at all.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.While):
            continue
        if any(isinstance(n, ast.Call) for n in ast.walk(node.test)):
            continue  # polling a predicate can observe progress outside this body
        watched = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        exits = False
        mutates = False
        pending = [(s, 0) for s in node.body]
        while pending:
            sub, loop_depth = pending.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(sub, (ast.Return, ast.Raise)) or isinstance(sub, ast.Break) and loop_depth == 0:
                exits = True
            if isinstance(sub, (ast.AugAssign, ast.Assign, ast.AnnAssign)):
                targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                changed = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
                same = isinstance(getattr(sub, "value", None), ast.Name) and changed == {sub.value.id}
                mutates |= bool(changed & watched) and not same
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                mutates |= isinstance(sub.func.value, ast.Name) and sub.func.value.id in watched
            nested = loop_depth + isinstance(sub, (ast.For, ast.AsyncFor, ast.While))
            pending.extend((child, nested) for child in ast.iter_child_nodes(sub))
        if exits or mutates:
            continue
        out.append(getattr(node, "lineno", 0))
    return out


def _ast_incomplete_functions(code: str, *, tree=None):
    """Function bodies that are a deliberate stub (SG-27).

    The old check was `"pass" in code and "def " in code` over the whole file, so
    `def f(): return "password"` was critical because the *word* appears
    somewhere, while an ellipsis-only body was missed.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any((d.id if isinstance(d, ast.Name) else getattr(d, "attr", ""))
               in ("abstractmethod", "overload") for d in node.decorator_list):
            continue
        body = [s for s in node.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                        and isinstance(s.value.value, str))]     # drop docstring
        if not body:
            out.append(getattr(node, "lineno", 0))
            continue
        if len(body) == 1:
            only = body[0]
            if isinstance(only, ast.Pass):
                out.append(getattr(node, "lineno", 0))
            elif isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) \
                    and only.value.value is Ellipsis:
                out.append(getattr(node, "lineno", 0))
            elif isinstance(only, ast.Raise) and only.exc is not None:
                exc = only.exc.func if isinstance(only.exc, ast.Call) else only.exc
                ename = exc.id if isinstance(exc, ast.Name) else getattr(exc, "attr", "")
                if ename == "NotImplementedError":
                    out.append(getattr(node, "lineno", 0))
    return out


def _ast_missing_return(code: str, *, tree=None):
    """Functions that promise a value but can fall off the end.

    The old check was `if 'return' not in body` on a regex-extracted body, so any
    procedure (`def save(): persist()`) was reported as a high-severity defect,
    while a `return` inside a string literal suppressed a genuine omission (SG-25).
    A missing return is only a defect when a value is actually expected: the
    function is annotated to return something, or some path returns a value while
    another falls through.
    """
    try:
        if tree is None:
            tree = ast.parse(code)
    except SyntaxError:
        return None

    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name = node.name
        returns_value = False
        bare_return = False
        has_yield = False
        # Only this function's own returns count: a nested `def` has its own
        # return discipline, and counting its bare `return`s made every function
        # with a helper closure look inconsistent.
        stack = list(node.body)
        while stack:
            sub = stack.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(sub, (ast.Yield, ast.YieldFrom)):
                has_yield = True
            if isinstance(sub, ast.Return):
                if sub.value is None:
                    bare_return = True
                else:
                    returns_value = True
            stack.extend(ast.iter_child_nodes(sub))
        if has_yield:
            continue
        ann = node.returns
        ann_name = ann.id if isinstance(ann, ast.Name) else getattr(ann, "attr", None)
        if ann_name in ("NoReturn", "Never") or isinstance(ann, ast.Constant) and ann.value in ("NoReturn", "Never", "None"):
            continue
        if _body_terminates(node.body) and not bare_return:
            continue
        if not returns_value:
            # Nothing returns a value: a procedure, unless it is annotated.
            ann = node.returns
            annotated = ann is not None and not (
                isinstance(ann, ast.Constant) and ann.value is None)
            if annotated:
                out.setdefault(getattr(node, "lineno", 0),
                               []).append((name, "annotated to return a value"))
            continue
        # Some paths return a value; does another fall through?
        falls_through = False
        body = node.body
        if body:
            last = body[-1]
            if not isinstance(last, (ast.Return, ast.Raise, ast.If, ast.For,
                                     ast.While, ast.Try, ast.With, ast.Match)):
                falls_through = True
            elif isinstance(last, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.Match)):
                falls_through = not _body_terminates(body)
        if falls_through or bare_return:
            out.setdefault(getattr(node, "lineno", 0),
                           []).append((name, "inconsistent return paths"))
    return out


def _body_terminates(body):
    """Conservative structural proof of a return/raise on every route."""
    for stmt in body:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return True
        if isinstance(stmt, ast.If) and stmt.orelse:
            if _body_terminates(stmt.body) and _body_terminates(stmt.orelse):
                return True
        if isinstance(stmt, (ast.With, ast.AsyncWith)) and _body_terminates(stmt.body):
            return True
        if isinstance(stmt, ast.Try):
            if _body_terminates(stmt.finalbody):
                return True
            if (_body_terminates(stmt.body) and not stmt.orelse
                    and all(_body_terminates(h.body) for h in stmt.handlers)):
                return True
    return False


def analyze_patterns(code: str, language: str) -> List[Dict]:
    """Pattern-based detection for common bugs and security issues."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        tree = None

    def check(helper):
        return helper(code, tree=tree) if tree is not None else None

    _div_lines = check(_ast_division_lines)
    _eval_lines = check(_ast_unsafe_eval_lines)
    _concat = check(_ast_concat_suspects)
    _missing_return = check(_ast_missing_return)
    _sql = check(_ast_sql_injection)
    _loops = check(_ast_nonterminating_loops)
    _secrets = check(_ast_hardcoded_secrets)
    issues = []
    lines = code.split("\n")
    full_code = code

    # Multi-line checks first (need full code context)

    # SQL Injection — the query string itself must be assembled (SG-21).
    if _sql is not None:
        for line_num, cname in _sql:
            issues.append({
                "type": "security",
                "severity": "critical",
                "line": line_num,
                "description": f"SQL injection risk — query passed to {cname}() is "
                               "built by string interpolation",
                "suggestion": "Use parameterized queries instead of string formatting",
            })
    elif re.search(r'f["\'].*SELECT.*FROM', full_code, re.IGNORECASE):
        line_num = next((i for i, l in enumerate(lines, 1) if 'SELECT' in l.upper()), 0)
        issues.append({
            "type": "security",
            "severity": "critical",
            "line": line_num,
            "description": "SQL injection vulnerability — user input interpolated into query via f-string",
            "suggestion": "Use parameterized queries instead of string formatting",
        })

    # Infinite loop — no exit path and no progress (SG-24).
    if _loops is not None:
        for line_num in _loops:
            issues.append({
                "type": "bug",
                "severity": "medium",
                "line": line_num,
                "description": "Potential infinite loop — the while body has no "
                               "break, return or counter update",
                "suggestion": "Add an exit condition or update the loop variable "
                              "inside the body",
            })

    # Hardcoded credentials — AST-resolved so annotated assignments count and
    # public labels like "SOL" do not (SG-22).
    if _secrets is not None:
        for line_num, name in _secrets:
            issues.append({
                "type": "security",
                "severity": "critical",
                "line": line_num,
                "description": f"Hardcoded secret/credential detected ('{name}')",
                "suggestion": "Use environment variables or a secrets manager",
            })

    # Off-by-one in range -- flag only shapes that actually smell.
    #
    # `range(n)` is idiomatic Python, not a defect: an exclusive bound is what you want
    # far more often than not, and whether the caller wanted inclusive is not knowable
    # from the source. The previous version flagged every `range(<name>)` unconditionally,
    # which made this the worst rule in the bank -- on real upstream code it produced 3 of
    # 6 false positives, all the same `range(max_retries)` line.
    #
    # What genuinely suggests an off-by-one is an ADJUSTED bound, or a comparison that
    # uses `<=` against the loop subject. Both are signals in the source, not guesses
    # about intent.
    # Use the AST for the adjusted-bound shape: a regex cannot see past the nested
    # parenthesis in range(len(x) + 1), so it silently missed exactly the case it was
    # written to catch. Structural question -> parser, not pattern.
    import ast as _ast2
    _tree = tree
    if _tree is not None:
        for node in _ast2.walk(_tree):
            if not (isinstance(node, _ast2.Call)
                    and isinstance(node.func, _ast2.Name)
                    and node.func.id == "range"):
                continue
            for arg in node.args:
                adj = (isinstance(arg, _ast2.BinOp)
                       and isinstance(arg.op, _ast2.Add)
                       and isinstance(arg.right, _ast2.Constant)
                       and arg.right.value == 1)
                if adj:
                    issues.append({
                        "type": "off_by_one",
                        "severity": "medium",
                        "line": getattr(node, "lineno", 0),
                        "description": "range() upper bound is unconditionally +1 -- a "
                                       "common off-by-one shape (an extra iteration)",
                        "suggestion": "Check whether the +1 is correct; prefer range(len(x)) "
                                      "over range(len(x) + 1).",
                    })
                    break
    if _tree is not None:
        import ast as _a
        for fnode in _a.walk(_tree):
            if not isinstance(fnode, _a.For):
                continue
            if not (isinstance(fnode.iter, _a.Call)
                    and isinstance(fnode.iter.func, _a.Name)
                    and fnode.iter.func.id == "range"):
                continue
            if not isinstance(fnode.target, _a.Name):
                continue
            subject = fnode.target.id
            for sub in _a.walk(fnode):
                # The loop subject is the LEFT operand of `i <= bound`, not a
                # comparator -- checking comparators for it was inverted and matched
                # nothing. Require: left is the loop subject, op is LtE, and the
                # right side is a name (the bound being compared against).
                if (isinstance(sub, _a.Compare)
                        and isinstance(sub.left, _a.Name)
                        and sub.left.id == subject
                        and any(isinstance(op, _a.LtE) for op in sub.ops)
                        and any(isinstance(c, _a.Name) for c in sub.comparators)):
                    issues.append({
                        "type": "off_by_one",
                        "severity": "medium",
                        "line": getattr(fnode, "lineno", 0),
                        "description": f"Loop over range() compares '{subject}' with `<=`, "
                                       "which admits one value past the iterated bound",
                        "suggestion": "Use `<` against the exclusive bound, or widen the "
                                      "range explicitly to show the intent.",
                    })
                    break

    # Missing return, only where a value is actually expected (SG-25).
    if _missing_return is not None:
        for line_num, hits in _missing_return.items():
            func_name, reason = hits[0]
            issues.append({
                "type": "bug",
                "severity": "high",
                "line": line_num,
                "description": f"Function '{func_name}' may return None "
                               f"({reason})",
                "suggestion": "Return a value on every path, or annotate -> None "
                              "if this is a procedure",
            })

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # SQL Injection (single-line) — only when the source does not parse, so
        # the AST check above is authoritative (SG-21).
        if _sql is None and re.search(
                r'(execute|query)\s*\(\s*(f["\']|[^"\']*\.format\()', stripped):
            if not any(iss["type"] == "security" for iss in issues):
                issues.append({
                    "type": "security",
                    "severity": "critical",
                    "line": i,
                    "description": "Potential SQL injection: string formatting used in database query",
                    "suggestion": "Use parameterized queries instead of string formatting",
                })

        # Hardcoded secrets — resolved from the AST so annotated assignments are
        # caught and public labels like "SOL" are not (SG-22).
        if _secrets is None:
            if re.search(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']',
                         stripped, re.IGNORECASE):
                issues.append({
                    "type": "security",
                    "severity": "critical",
                    "line": i,
                    "description": "Hardcoded secret/credential detected",
                    "suggestion": "Use environment variables or a secrets manager",
                })

        # Division without zero check.
        # Gated on the AST: a `/` inside a string literal is not a division. When the
        # source does not parse (_div_lines is None) fall back to the regex unchanged.
        _is_div = True if _div_lines is None else (i in _div_lines)
        if (_is_div and re.search(r'/\s*\w+', stripped)
                and "/ 0" not in stripped and "try" not in stripped):
            # Simple heuristic — check if there's a division with a variable
            if re.search(r'/\s*[a-zA-Z_]\w*', stripped) and "def " not in stripped:
                issues.append({
                    "type": "bug",
                    "severity": "medium",
                    "line": i,
                    "description": "Division by variable without zero-check",
                    "suggestion": "Add a check for zero before dividing",
                })

        # Type error — string concatenation with a likely-numeric variable.
        # Resolved from the AST (RV-07); the regex fallback only runs on source
        # that does not parse, so there is no length cutoff and no lost coverage.
        if _concat is not None:
            _suspects = _concat.get(i, [])
        else:
            _suspects = []
            if len(stripped) <= 2000 and re.search(
                    r'["\'][^"\']*\+\s*\w+[^"\']*\+\s*["\']', stripped):
                _suspects = [v for v in re.findall(r'\+\s*(\w+)', stripped)
                             if any(h in v.lower() for h in NUMERIC_NAME_HINTS)][:1]
        for var in _suspects:
            issues.append({
                "type": "type_error",
                "severity": "high",
                "line": i,
                "description": f"Potential TypeError — concatenating string with likely numeric variable '{var}'. Use str({var}) for safe concatenation",
                "suggestion": f"Wrap '{var}' with str() before concatenation",
            })
            break

        # eval()/exec() usage -- resolved through the AST so literal_eval is not
        # mistaken for eval (SG-23).
        if _eval_lines is None:
            _is_eval = re.search(r'\b(?:eval|exec)\s*\(', stripped) is not None
        else:
            _is_eval = i in _eval_lines
        if _is_eval:
            issues.append({
                "type": "security",
                "severity": "critical",
                "line": i,
                "description": "Use of eval() is a security risk — allows arbitrary code execution",
                "suggestion": "Use ast.literal_eval() for safe evaluation or avoid eval entirely",
            })

        # TODO/FIXME/HACK markers
        if re.search(r'#\s*(TODO|FIXME|HACK|XXX)', stripped, re.IGNORECASE):
            issues.append({
                "type": "code_quality",
                "severity": "low",
                "line": i,
                "description": f"Unresolved marker found: {stripped.split('#')[1].strip()[:50]}",
                "suggestion": "Resolve or remove before shipping to production",
            })

    return issues


def analyze_intent(code: str, intent: str, language: str) -> List[Dict]:
    """
    Check if code matches its stated intent.
    This is the key differentiator — not just "are there bugs?"
    but "does this code do what it was supposed to do?"

    For the hackathon demo, this uses heuristic matching.
    In production, this would use an LLM for semantic analysis.
    """
    _incomplete = _ast_incomplete_functions(code)
    issues = []
    intent_lower = intent.lower()
    code_lower = code.lower()

    # Check for common intent mismatches

    # Intent says "add" but code uses wrong operator
    if ("add" in intent_lower or "sum" in intent_lower):
        # Check for subtraction instead of addition
        if "-" in code and "+" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": f"Intent says '{intent}' but code appears to subtract instead of add",
                "suggestion": "Replace subtraction operator with addition",
            })
        # Check for multiplication instead of addition
        if re.search(r'\w+\s*\*\s*\w+', code) and "+" not in code and "**" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": f"Intent says '{intent}' but code uses multiplication (*) instead of addition (+)",
                "suggestion": "Replace multiplication operator with addition",
            })
        # Check for division instead of addition
        if re.search(r'\w+\s*/\s*\w+', code) and "+" not in code and "//" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": f"Intent says '{intent}' but code uses division (/) instead of addition (+)",
                "suggestion": "Replace division operator with addition",
            })

    # Intent says "positive" but code checks negative (logic inversion)
    if "positive" in intent_lower and ("< 0" in code or "<= 0" in code):
        # Check if the logic is inverted
        if re.search(r'return\s+\w+\s*<\s*0', code) or re.search(r'return\s+\w+\s*<=\s*0', code):
            issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": "Logic inverted — intent asks for positive check but code returns True for negative/non-positive values",
                "suggestion": "Use > 0 instead of < 0 to check for positive numbers",
            })
        if re.search(r'if\s+\w+\s*<=?\s*0:\s*\n\s*return\s+True', code):
            issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": "Logic inverted — returns True when number is non-positive, should return True when positive",
                "suggestion": "Reverse the condition to check for n > 0",
            })

    # Intent says "average" but code doesn't divide
    if "average" in intent_lower:
        if "sum" in code_lower and "/" not in code and "len" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "high",
                "line": 0,
                "description": "Intent asks for average but code computes sum without dividing by count",
                "suggestion": "Divide the total by len(numbers) to compute the average",
            })
        # Check for multiply instead of divide in average calc
        if re.search(r'total\s*\*\s*count|total\s*\*\s*len', code_lower):
            issues.append({
                "type": "intent_mismatch",
                "severity": "high",
                "line": 0,
                "description": "Intent asks for average but code multiplies total by count instead of dividing",
                "suggestion": "Use total / count instead of total * count",
            })

    # Intent says "sort ascending" but code sorts descending
    if "ascending" in intent_lower and "reverse=True" in code:
        issues.append({
            "type": "intent_mismatch",
            "severity": "high",
            "line": 0,
            "description": "Intent specifies ascending sort but code uses reverse=True (descending)",
            "suggestion": "Remove reverse=True or set to False",
        })

    # Intent says "return list" but function returns single value
    if ("list" in intent_lower or "array" in intent_lower) and "return" in code:
        returns = re.findall(r"return\s+(.+)", code)
        for ret in returns:
            if "[" not in ret and "list" not in ret and "[]" not in ret:
                issues.append({
                    "type": "intent_mismatch",
                    "severity": "medium",
                    "line": 0,
                    "description": f"Intent expects a list/array return but function returns: {ret.strip()[:30]}",
                    "suggestion": "Ensure the function returns a list as specified",
                })

    # Intent mentions "handle errors" but no try/except
    if ("error" in intent_lower or "exception" in intent_lower or "handle" in intent_lower):
        if "try" not in code and "except" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "medium",
                "line": 0,
                "description": "Intent mentions error handling but no try/except blocks found",
                "suggestion": "Add error handling as specified in the intent",
            })

    # Intent says "validate" or "check" but no validation logic
    if ("validate" in intent_lower or "check" in intent_lower):
        if "if " not in code and "assert" not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "medium",
                "line": 0,
                "description": "Intent mentions validation but no conditional checks found in code",
                "suggestion": "Add input validation as specified in the intent",
            })

    # Intent mentions "empty" handling but no length/empty check
    if "empty" in intent_lower or "handle empty" in intent_lower:
        if "len(" not in code and "not " not in code and "if " not in code:
            issues.append({
                "type": "intent_mismatch",
                "severity": "high",
                "line": 0,
                "description": "Intent requires handling empty input but no empty check found",
                "suggestion": "Add a check for empty input before processing",
            })

    # Intent says "safely" or "safe" but code has no safety measures
    if "safely" in intent_lower or "safe" in intent_lower:
        if "try" not in code and "if " not in code and "parameterized" not in code_lower:
            issues.append({
                "type": "intent_mismatch",
                "severity": "medium",
                "line": 0,
                "description": "Intent specifies safe operation but no safety checks found in code",
                "suggestion": "Add safety checks, input validation, or parameterized queries",
            })

    # Intent says "environment" but code has hardcoded values
    if "environment" in intent_lower and re.search(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
        issues.append({
            "type": "intent_mismatch",
            "severity": "critical",
            "line": 0,
            "description": "Intent says to use environment configuration but credentials are hardcoded",
            "suggestion": "Use os.environ or a config/secrets manager instead of hardcoded values",
        })

    # Incomplete function bodies — AST, so a stray "pass" elsewhere in the file
    # no longer condemns a complete function (SG-27).
    if _incomplete is not None:
        for line_num in _incomplete:
            issues.append({
                "type": "incomplete",
                "severity": "medium",
                "line": line_num,
                "description": "Function body is a stub (pass, ... or NotImplementedError)",
                "suggestion": "Implement the function or raise NotImplementedError explicitly",
            })

    for issue in issues:
        if issue.get("type") == "intent_mismatch":
            issue["severity"] = "medium"
    return issues


def calculate_confidence(issues: List[Dict], llm_used: bool = False) -> float:
    """Calculate confidence score based on analysis depth."""
    # Base confidence from having done analysis
    confidence = 0.7

    # LLM-based analysis is more thorough — higher base confidence
    if llm_used:
        confidence = 0.85

    # More issues found = more thorough analysis = higher confidence
    if len(issues) > 0:
        confidence += min(0.2, len(issues) * 0.05)

    # Critical issues found = high confidence something is wrong
    critical_count = len([i for i in issues if i.get("severity") == "critical"])
    if critical_count > 0:
        confidence += 0.1

    return min(1.0, confidence)


def generate_suggestions(issues: List[Dict], code: str) -> List[Dict]:
    """Generate actionable fix suggestions from issues."""
    suggestions = []
    for issue in issues:
        if issue.get("suggestion"):
            suggestions.append({
                "line": issue.get("line", 0),
                "description": issue["suggestion"],
                "severity": issue.get("severity", "medium"),
            })
    return suggestions
