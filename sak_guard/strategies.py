"""
Worker Strategies — Different analysis approaches for competing workers.

Each strategy wraps the base analyze_code() function but tweaks which
passes run, how severity is weighted, and what extra checks are performed.
This makes workers produce genuinely different results for the same job,
so the leaderboard reflects real competition.

Strategies:
    - ast-heavy:         Full AST + patterns, skip LLM. Higher confidence on structural bugs.
    - security-focused:  All patterns with boosted severity for security. Extra security regexes.
    - intent-focused:    Lighter AST but enhanced intent heuristics. Uses LLM if available.
    - default:           Runs everything as-is (backward compatible).
"""

import re
import logging
from typing import Dict, List

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


# ─── Extra security patterns (used by security-focused strategy) ─────────────

_EXTRA_SECURITY_PATTERNS = [
    # Pickle deserialization
    (r'pickle\.loads?\(', "Unsafe pickle deserialization — can execute arbitrary code", "Use json or a safe serialization format"),
    # subprocess with shell=True
    (r'subprocess\.\w+\(.*shell\s*=\s*True', "subprocess with shell=True allows shell injection", "Use shell=False and pass args as a list"),
    # os.system usage
    (r'os\.system\(', "os.system() is vulnerable to command injection", "Use subprocess.run() with shell=False instead"),
    # yaml.load without SafeLoader
    (r'yaml\.load\([^)]*\)', "yaml.load() without SafeLoader can execute arbitrary code", "Use yaml.safe_load() instead"),
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


def run_strategy(strategy: str, code: str, intent: str, language: str = "python") -> dict:
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
        return analyze_code(code=code, intent=intent, language=language, use_llm=False)
    elif strategy == "ast-heavy":
        return _strategy_ast_heavy(code, intent, language)
    elif strategy == "security-focused":
        return _strategy_security_focused(code, intent, language)
    elif strategy == "intent-focused":
        return _strategy_intent_focused(code, intent, language)
    else:
        logger.warning(f"Unknown strategy '{strategy}', falling back to default")
        return analyze_code(code=code, intent=intent, language=language, use_llm=False)


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
    passed = len(critical_or_high) == 0
    suggestions = generate_suggestions(all_issues, code)

    return {
        "issues": all_issues,
        "confidence": confidence,
        "passed": passed,
        "suggestions": suggestions,
    }


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

    # Extra security patterns (the differentiator)
    lines = code.split("\n")
    for regex, description, suggestion in _EXTRA_SECURITY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(regex, line):
                # Avoid duplicate security issues
                if not any(
                    iss.get("description", "").lower() == description.lower()
                    for iss in all_issues
                ):
                    all_issues.append({
                        "type": "security",
                        "severity": "high",
                        "line": i,
                        "description": description,
                        "suggestion": suggestion,
                    })
                break  # One match per pattern is enough

    # Boost severity: upgrade medium security issues to high
    for issue in all_issues:
        if issue.get("type") == "security" and issue.get("severity") == "medium":
            issue["severity"] = "high"

    # Security-focused confidence: higher when security issues found
    security_count = len([i for i in all_issues if i.get("type") == "security"])
    confidence = 0.68
    if security_count > 0:
        confidence += min(0.25, security_count * 0.07)
    if len(all_issues) > 0:
        confidence += min(0.1, len(all_issues) * 0.02)

    confidence = min(1.0, confidence)
    critical_or_high = [i for i in all_issues if i.get("severity") in ("critical", "high")]
    passed = len(critical_or_high) == 0
    suggestions = generate_suggestions(all_issues, code)

    return {
        "issues": all_issues,
        "confidence": confidence,
        "passed": passed,
        "suggestions": suggestions,
    }


# ─── Strategy C: Intent-Focused ───────────────────────────────────────────────

def _strategy_intent_focused(code: str, intent: str, language: str) -> dict:
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
    intent_issues = _llm_analyze_intent(code, intent, language)
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
    critical_or_high = [i for i in all_issues if i.get("severity") in ("critical", "high")]
    passed = len(critical_or_high) == 0
    suggestions = generate_suggestions(all_issues, code)

    return {
        "issues": all_issues,
        "confidence": confidence,
        "passed": passed,
        "suggestions": suggestions,
    }


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
                        "severity": "high",
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
                    "severity": "critical",
                    "line": 0,
                    "description": f"Intent says '{a}' but function is named '{fname}' (suggests '{b}')",
                    "suggestion": f"The function name suggests it does '{b}' but intent requires '{a}'",
                })
            elif b in intent_lower and a in fname_lower:
                issues.append({
                    "type": "intent_mismatch",
                    "severity": "critical",
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
