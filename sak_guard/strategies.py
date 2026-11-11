"""
Worker Strategies — Different analysis approaches for competing workers.

Each strategy wraps the base analyze_code() function but tweaks which
passes run, how severity is weighted, and what extra checks are performed.
This makes workers produce genuinely different results for the same job,
so the leaderboard reflects real competition.

Strategies:
    - ast-heavy:         Full AST + patterns, skip LLM. Higher confidence on structural bugs.
    - security-focused:  Standard checks plus security API checks.
    - intent-focused:    Enhanced intent heuristics; LLM only with explicit opt-in.
    - default:           Runs everything as-is (backward compatible).
"""

import ast
import re
import logging
from typing import Dict, List
from .limits import analysis_entry

from .solana import scan_solana
from .analyzer import (
    analyze_code,
    analyze_syntax,
    analyze_patterns,
    analyze_intent,
    calculate_confidence,
    generate_suggestions,
    _llm_analyze_intent,
)

logger = logging.getLogger(__name__)


# ─── Security diagnostic catalogue (matching is AST-based) ──────────────────

_EXTRA_SECURITY_PATTERNS = [
    # Pickle deserialization
    (r'pickle\.loads?\(', "Unsafe pickle deserialization — can execute arbitrary code", "Use json or a safe serialization format"),
    # subprocess with shell=True
    (r'subprocess\.\w+\(.*shell\s*=\s*True', "subprocess with shell=True allows shell injection", "Use shell=False and pass args as a list"),
    # os.system usage
    (r'os\.system\(', "os.system() is vulnerable to command injection", "Use subprocess.run() with shell=False instead"),
    # yaml.load without a SAFE loader. SafeLoader/CSafeLoader are safe; FullLoader
    # and UnsafeLoader are not, and `yaml.safe_load` is the correct call.
    (r'yaml\.load\((?![^)]*SafeLoader)[^)]*\)', "yaml.load() without SafeLoader can execute arbitrary code", "Use yaml.safe_load() instead"),
    # Binding to 0.0.0.0
    (r'0\.0\.0\.0', "Service bound to all interfaces (0.0.0.0) — may expose to public network", "Bind to 127.0.0.1 for local-only access"),
    # JWT without verification
    (r'jwt\.decode\(.*verify\s*=\s*False', "JWT decoded without signature verification", "Set verify=True and provide the signing key"),
    # Hardcoded IP addresses
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Hardcoded IP address detected", "Use configuration or DNS names instead"),
    # chmod 777
    (r'chmod.*777', "World-readable/writable permissions (777)", "Use restrictive permissions like 644 or 600"),
    # MD5/SHA1 for security
    (r'(md5|sha1)\(', "Weak hash algorithm (MD5/SHA1) — not suitable for security", "Use SHA-256 or bcrypt for password hashing"),
    # Temporary file with predictable name
    (r'/tmp/\w+', "Predictable temporary file path — potential symlink attack", "Use tempfile.mkstemp() for secure temp files"),
]


def _extra_security_ast(code):
    from .solana import _binding_events, _scope_map, _origin_at, _dotted

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    bindings = _binding_events(tree)
    scopes = _scope_map(tree)
    out = []

    def origin(expr, line, scope):
        name = _dotted(expr)
        head, dot, tail = name.partition(".")
        resolved = _origin_at(bindings, head, line, scope)
        return resolved + dot + tail

    def emit(index, node, severity="high"):
        _, description, suggestion = _EXTRA_SECURITY_PATTERNS[index]
        out.append({"type": "security", "severity": severity,
                    "line": node.lineno, "description": description,
                    "suggestion": suggestion})

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        line, scope = (call.lineno, call.col_offset), scopes.get(id(call))
        name = origin(call.func, line, scope)
        kw = {k.arg: k.value for k in call.keywords if k.arg is not None}

        def literal(key, value):
            return key in kw and isinstance(kw[key], ast.Constant) and kw[key].value == value

        if name in ("pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"):
            emit(0, call)
        if name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in {
                "run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}:
            if literal("shell", True) or name.endswith((".getoutput", ".getstatusoutput")):
                emit(1, call)
        if name == "os.system":
            emit(2, call)
        if name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"):
            loader = kw.get("Loader") or (call.args[1] if len(call.args) > 1 else None)
            if loader is None or origin(loader, line, scope) not in ("yaml.SafeLoader", "yaml.CSafeLoader"):
                emit(3, call)
        if literal("host", "0.0.0.0") or (name.endswith(".bind") and call.args
                and isinstance(call.args[0], (ast.Tuple, ast.List)) and call.args[0].elts
                and isinstance(call.args[0].elts[0], ast.Constant) and call.args[0].elts[0].value == "0.0.0.0"):
            emit(4, call)
        if name == "jwt.decode":
            disabled = literal("verify", False)
            options = kw.get("options")
            if isinstance(options, ast.Dict):
                disabled |= any(isinstance(k, ast.Constant) and k.value == "verify_signature"
                                and isinstance(v, ast.Constant) and v.value is False
                                for k, v in zip(options.keys, options.values))
            if disabled:
                emit(5, call)
        if name in ("os.chmod", "Path.chmod") or name.endswith(".chmod"):
            if any(isinstance(a, ast.Constant) and a.value == 0o777 for a in call.args):
                emit(7, call)
        if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1") and not literal("usedforsecurity", False):
            emit(8, call, "medium")
    return out


# ─── Enhanced intent keywords (used by intent-focused strategy) ───────────────

_EXTRA_INTENT_CHECKS = {
    # Sorting mismatches
    "descending": lambda code: "reverse=False" in code or ("sorted(" in code and "reverse" not in code),
    "largest": lambda code: "min(" in code and "max(" not in code,
    "smallest": lambda code: "max(" in code and "min(" not in code,
    "multiply": lambda code: "+" in code and "*" not in code and "sum" not in code,
    "subtract": lambda code: "+" in code and "-" not in code,
    "divide": lambda code: ("*" in code or "+" in code) and "/" not in code,
    "unique": lambda code: "set(" not in code and "unique" not in code and "distinct" not in code.lower(),
    "recursive": lambda code: "def " in code and code.split("def ")[1].split("(")[0] not in code.split("def ")[1].split(":")[1] if "def " in code else True,
    "fibonacci": lambda code: "def " in code and ("-" not in code or "1" not in code),
    "reverse": lambda code: "reverse" not in code and "[::-1]" not in code and "reversed" not in code,
    "count": lambda code: "len(" not in code and "count" not in code and "+= 1" not in code,
    "maximum": lambda code: "max(" not in code and "> " not in code,
    "minimum": lambda code: "min(" not in code and "< " not in code,
    "palindrome": lambda code: "[::-1]" not in code and "reversed" not in code,
    "flatten": lambda code: "for " not in code and "itertools" not in code and "chain" not in code,
}


@analysis_entry
def run_strategy(strategy: str, code: str, intent: str, language: str = "python", use_llm: bool = False) -> dict:
    """
    Run analysis using the specified strategy.

    Args:
        strategy: One of "ast-heavy", "security-focused", "intent-focused", "default".
        code: Source code to analyze.
        intent: Natural-language description of what the code should do.
        language: Programming language.

    Returns:
        Same dict format as analyze_code(): {issues, confidence, passed, suggestions}
    """
    if strategy == "default" or strategy is None:
        return analyze_code(code=code, intent=intent, language=language, use_llm=use_llm)
    elif strategy == "ast-heavy":
        result = _strategy_ast_heavy(code, intent, language)
    elif strategy == "security-focused":
        result = _strategy_security_focused(code, intent, language)
    elif strategy == "intent-focused":
        return _strategy_intent_focused(code, intent, language, use_llm=use_llm)
    else:
        logger.warning(f"Unknown strategy '{strategy}', falling back to default")
        return analyze_code(code=code, intent=intent, language=language, use_llm=False)
    if use_llm:
        extra = _llm_analyze_intent(code, intent, language)
        if extra is not None:
            result["issues"].extend(extra)
            result["passed"] = not any(i.get("severity") in ("high", "critical") for i in result["issues"])
    return result




def _finalize(all_issues: list, confidence: float, code: str) -> dict:
    """Append the Solana domain pass and derive acceptance from the full result.

    A rule that raised is recorded as an explicit critical issue: analysis that
    did not complete is not a clean result. Reporting "clear" for a rule that
    never ran is how a 2.4 KB input produced exit 0 with passed=true on a real
    critical flow (F4-01, SG-17).
    """
    _sol = scan_solana(code)
    if _sol.get("issues"):
        all_issues.extend(_sol["issues"])
    scan_errors = list(_sol.get("errors") or [])
    for err in scan_errors:
        all_issues.append({
            "type": "analysis_error",
            "severity": "critical",
            "line": 0,
            "description": f"Required analysis did not complete: {err}. "
                           "This result is not a clean verdict.",
            "suggestion": "Treat as a scan failure and fix the rule or the input.",
        })
    worst = [i for i in all_issues if i.get("severity") in ("critical", "high")]
    return {
        "issues": all_issues,
        "confidence": min(1.0, confidence),
        "passed": len(worst) == 0,
        "suggestions": generate_suggestions(all_issues, code),
        "scan_errors": scan_errors,
    }


# ─── Strategy A: AST-Heavy ────────────────────────────────────────────────────

def _strategy_ast_heavy(code: str, intent: str, language: str) -> dict:
    """
    Focuses on structural/AST analysis. Runs full AST + patterns but skips
    intent matching (which is heuristic-heavy). Boosts confidence for
    syntax-level findings.
    """
    all_issues = []

    # Full AST analysis (primary focus)
    ast_issues = analyze_syntax(code, language)
    all_issues.extend(ast_issues)

    # Pattern analysis (secondary)
    pattern_issues = analyze_patterns(code, language)
    all_issues.extend(pattern_issues)

    # Skip intent analysis — this strategy trusts structure over semantics
    # But still do a minimal intent check for critical operator mismatches
    intent_lower = intent.lower()
    if ("add" in intent_lower or "sum" in intent_lower):
        if "-" in code and "+" not in code:
            all_issues.append({
                "type": "intent_mismatch",
                "severity": "critical",
                "line": 0,
                "description": f"Intent says '{intent}' but code subtracts instead of adding",
                "suggestion": "Replace - with +",
            })

    # AST-heavy confidence: higher base when AST issues are found
    confidence = 0.65
    ast_count = len(ast_issues)
    if ast_count > 0:
        confidence += min(0.25, ast_count * 0.08)  # AST issues boost more
    if len(pattern_issues) > 0:
        confidence += min(0.1, len(pattern_issues) * 0.03)

    critical_or_high = [i for i in all_issues if i.get("severity") in ("critical", "high")]
    if critical_or_high:
        confidence += 0.05

    confidence = min(1.0, confidence)
    return _finalize(all_issues, confidence, code)


# ─── Strategy B: Security-Focused ─────────────────────────────────────────────

def _strategy_security_focused(code: str, intent: str, language: str) -> dict:
    """
    Prioritizes security issues. Runs all standard checks but adds extra
    security-specific regex patterns and boosts severity of security findings.
    """
    all_issues = []

    # Standard AST analysis
    ast_issues = analyze_syntax(code, language)
    all_issues.extend(ast_issues)

    # Standard pattern analysis
    pattern_issues = analyze_patterns(code, language)
    all_issues.extend(pattern_issues)

    # Standard intent analysis
    intent_issues = analyze_intent(code, intent, language)
    all_issues.extend(intent_issues)

    # Call boundaries and import aliases come from the AST. Token masking is
    # insufficient on Python versions that tokenize an entire f-string as one
    # string, and a DOTALL regex can borrow shell=True from a different call.
    all_issues.extend(_extra_security_ast(code))

    # Keep advisory/heuristic severities; selecting a strategy is not evidence
    # that an uncertain finding is a high-severity security defect.

    # Security-focused confidence: higher when security issues found
    security_count = len([i for i in all_issues if i.get("type") == "security"])
    confidence = 0.68
    if security_count > 0:
        confidence += min(0.25, security_count * 0.07)
    if len(all_issues) > 0:
        confidence += min(0.1, len(all_issues) * 0.02)

    confidence = min(1.0, confidence)
    return _finalize(all_issues, confidence, code)


# ─── Strategy C: Intent-Focused ───────────────────────────────────────────────

def _strategy_intent_focused(code: str, intent: str, language: str, use_llm: bool = False) -> dict:
    """
    Focuses on intent matching — does the code actually do what it claims?
    Uses LLM if available, otherwise runs enhanced heuristic intent checks.
    Lighter on AST, heavier on semantics.
    """
    all_issues = []

    # Light AST — only critical syntax errors, skip style issues
    ast_issues = analyze_syntax(code, language)
    critical_ast = [i for i in ast_issues if i.get("severity") in ("critical", "high")]
    all_issues.extend(critical_ast)

    # Skip heavy pattern analysis, only check for the most critical patterns
    pattern_issues = analyze_patterns(code, language)
    critical_patterns = [i for i in pattern_issues if i.get("severity") in ("critical", "high")]
    all_issues.extend(critical_patterns)

    # Try LLM-based intent analysis first
    llm_used = False
    intent_issues = _llm_analyze_intent(code, intent, language) if use_llm else None
    if intent_issues is not None:
        llm_used = True
        logger.info(f"LLM intent analysis returned {len(intent_issues)} issues")
    else:
        # Enhanced heuristic intent matching (the differentiator)
        intent_issues = analyze_intent(code, intent, language)

        # Run extra intent checks
        extra = _enhanced_intent_check(code, intent)
        intent_issues.extend(extra)

    all_issues.extend(intent_issues)

    # Intent-focused confidence
    confidence = 0.72 if not llm_used else 0.88
    intent_count = len(intent_issues)
    if intent_count > 0:
        confidence += min(0.2, intent_count * 0.06)
    if llm_used:
        confidence += 0.05

    confidence = min(1.0, confidence)
    return _finalize(all_issues, confidence, code)


def _enhanced_intent_check(code: str, intent: str) -> List[Dict]:
    """Extra intent-matching heuristics beyond the base analyzer."""
    issues = []
    intent_lower = intent.lower()
    code_lower = code.lower()

    # Check each keyword in the intent against code behavior
    for keyword, mismatch_fn in _EXTRA_INTENT_CHECKS.items():
        if keyword in intent_lower:
            try:
                if mismatch_fn(code):
                    issues.append({
                        "type": "intent_mismatch",
                        "severity": "medium",
                        "line": 0,
                        "description": f"Intent mentions '{keyword}' but code may not implement it correctly",
                        "suggestion": f"Review the code to ensure it correctly handles '{keyword}' as described in the intent",
                    })
            except Exception:
                pass  # Heuristic failed, skip

    # Check for function name vs intent mismatch
    import re as _re
    func_names = _re.findall(r'def\s+(\w+)\s*\(', code)
    for fname in func_names:
        fname_lower = fname.lower()
        # If intent says "add" but function is named "subtract" (or vice versa)
        opposites = [
            ("add", "subtract"), ("add", "sub"),
            ("multiply", "divide"), ("mul", "div"),
            ("max", "min"), ("minimum", "maximum"),
            ("push", "pop"), ("enqueue", "dequeue"),
            ("encode", "decode"), ("encrypt", "decrypt"),
            ("compress", "decompress"),
            ("upper", "lower"),
            ("read", "write"),
        ]
        for a, b in opposites:
            if a in intent_lower and b in fname_lower:
                issues.append({
                    "type": "intent_mismatch",
                    "severity": "medium",
                    "line": 0,
                    "description": f"Intent says '{a}' but function is named '{fname}' (suggests '{b}')",
                    "suggestion": f"The function name suggests it does '{b}' but intent requires '{a}'",
                })
            elif b in intent_lower and a in fname_lower:
                issues.append({
                    "type": "intent_mismatch",
                    "severity": "medium",
                    "line": 0,
                    "description": f"Intent says '{b}' but function is named '{fname}' (suggests '{a}')",
                    "suggestion": f"The function name suggests it does '{a}' but intent requires '{b}'",
                })

    # Check if return type seems wrong for intent
    if "boolean" in intent_lower or "true or false" in intent_lower or "true/false" in intent_lower:
        returns = _re.findall(r'return\s+(.+)', code)
        for ret in returns:
            ret = ret.strip()
            if ret not in ("True", "False") and "True" not in ret and "False" not in ret and "==" not in ret and "!=" not in ret and ">" not in ret and "<" not in ret and "is " not in ret and "not " not in ret:
                issues.append({
                    "type": "intent_mismatch",
                    "severity": "medium",
                    "line": 0,
                    "description": f"Intent expects boolean return but code returns: {ret[:40]}",
                    "suggestion": "Ensure the function returns True or False as specified",
                })

    # Check if intent mentions "string" but code returns numeric
    if "string" in intent_lower or "str" in intent_lower:
        returns = _re.findall(r'return\s+(\d+)', code)
        if returns:
            issues.append({
                "type": "intent_mismatch",
                "severity": "medium",
                "line": 0,
                "description": "Intent expects string return but code returns a numeric value",
                "suggestion": "Wrap the return value with str() or return a string",
            })

    return issues
