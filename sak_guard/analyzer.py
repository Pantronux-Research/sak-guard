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
            return json.loads(resp.read().decode("utf-8"))

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
    if raw is None:
        return None

    # Parse the JSON response — be tolerant of markdown wrappers
    text = raw.strip()
    if text.startswith("```"):
        # Strip ```json ... ``` wrapper
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("LLM returned non-JSON response, falling back to heuristics")
        return None

    issues = data.get("issues", [])

    # Normalize issue format to match our standard schema
    normalized: List[Dict] = []
    for issue in issues:
        normalized.append({
            "type": issue.get("type", "intent_mismatch"),
            "severity": issue.get("severity", "medium"),
            "line": issue.get("line", 0),
            "description": issue.get("description", ""),
            "suggestion": issue.get("suggestion", ""),
        })

    return normalized


# ─── Main entry point ────────────────────────────────────────────────────────

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

    # Calculate confidence
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
        if isinstance(node, ast.FunctionDef):
            for default in node.args.defaults:
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


def analyze_patterns(code: str, language: str) -> List[Dict]:
    """Pattern-based detection for common bugs and security issues."""
    issues = []
    lines = code.split("\n")
    full_code = code

    # Multi-line checks first (need full code context)

    # SQL Injection — f-string or format in query + execute nearby
    if re.search(r'f["\'].*SELECT.*FROM', full_code, re.IGNORECASE):
        line_num = next((i for i, l in enumerate(lines, 1) if 'SELECT' in l.upper()), 0)
        issues.append({
            "type": "security",
            "severity": "critical",
            "line": line_num,
            "description": "SQL injection vulnerability — user input interpolated into query via f-string",
            "suggestion": "Use parameterized queries instead of string formatting",
        })
    elif re.search(r'\.format\(.*\).*SELECT', full_code, re.IGNORECASE | re.DOTALL):
        issues.append({
            "type": "security",
            "severity": "critical",
            "line": 0,
            "description": "SQL injection vulnerability — .format() used in query string",
            "suggestion": "Use parameterized queries instead of string formatting",
        })

    # Infinite loop detection — while loop without modification of loop variable
    while_matches = list(re.finditer(r'while\s+(\w+)\s*([><=!]+)', full_code))
    for match in while_matches:
        var_name = match.group(1)
        # Check if the variable is modified inside the loop body
        loop_start = match.start()
        # Simple check: is the variable assigned or modified after the while?
        remaining = full_code[loop_start:]
        if f"{var_name} =" not in remaining.split("\n", 1)[-1] and f"{var_name} -=" not in remaining and f"{var_name} +=" not in remaining:
            line_num = full_code[:loop_start].count("\n") + 1
            issues.append({
                "type": "bug",
                "severity": "critical",
                "line": line_num,
                "description": f"Potential infinite loop — '{var_name}' is not modified inside the while loop",
                "suggestion": f"Add '{var_name} -= 1' or similar modification inside the loop body",
            })

    # Off-by-one in range — check if intent mentions inclusive
    if "range(" in full_code:
        range_matches = re.findall(r'range\((\w+)\)', full_code)
        for var in range_matches:
            # This could be off-by-one if the intent requires inclusive range
            line_num = next((i for i, l in enumerate(lines, 1) if f'range({var})' in l), 0)
            issues.append({
                "type": "off_by_one",
                "severity": "medium",
                "line": line_num,
                "description": f"range({var}) produces values 0 to {var}-1. If inclusive range is needed, use range(1, {var}+1)",
                "suggestion": f"Check if range should be range(1, {var}+1) for 1 to {var} inclusive",
            })

    # Missing return in function that should return a value
    func_defs = re.findall(r'def\s+(\w+)\([^)]*\):', full_code)
    for func_name in func_defs:
        # Extract function body (simple heuristic)
        func_match = re.search(rf'def\s+{func_name}\([^)]*\):\s*\n((?:\s+.+\n?)+)', full_code)
        if func_match:
            body = func_match.group(1)
            if 'return' not in body and 'yield' not in body and 'print' not in body:
                line_num = next((i for i, l in enumerate(lines, 1) if f'def {func_name}' in l), 0)
                issues.append({
                    "type": "bug",
                    "severity": "high",
                    "line": line_num,
                    "description": f"Function '{func_name}' has no return statement — implicitly returns None",
                    "suggestion": "Add a return statement with the expected value",
                })

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # SQL Injection (single-line patterns)
        if re.search(r'(execute|query)\s*\(.*(%s|\.format|\+.*input|f["\'])', stripped):
            if not any(iss["type"] == "security" for iss in issues):
                issues.append({
                    "type": "security",
                    "severity": "critical",
                    "line": i,
                    "description": "Potential SQL injection: string formatting used in database query",
                    "suggestion": "Use parameterized queries instead of string formatting",
                })

        # Hardcoded secrets
        if re.search(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']', stripped, re.IGNORECASE):
            issues.append({
                "type": "security",
                "severity": "critical",
                "line": i,
                "description": "Hardcoded secret/credential detected",
                "suggestion": "Use environment variables or a secrets manager",
            })

        # Division without zero check
        if re.search(r'/\s*\w+', stripped) and "/ 0" not in stripped and "try" not in stripped:
            # Simple heuristic — check if there's a division with a variable
            if re.search(r'/\s*[a-zA-Z_]\w*', stripped) and "def " not in stripped:
                issues.append({
                    "type": "bug",
                    "severity": "medium",
                    "line": i,
                    "description": "Division by variable without zero-check",
                    "suggestion": "Add a check for zero before dividing",
                })

        # Type error — string concatenation with non-string variables
        if re.search(r'["\'].*\+\s*\w+.*\+\s*["\']', stripped) or re.search(r'["\'].*\+\s*\w+\s*\+\s*["\']', stripped):
            # Check if any variable in the concatenation is likely numeric (based on name)
            numeric_vars = re.findall(r'\+\s*(\w+)', stripped)
            for var in numeric_vars:
                if any(hint in var.lower() for hint in ['age', 'count', 'num', 'id', 'year', 'price', 'amount', 'total', 'size', 'length', 'index', 'score']):
                    issues.append({
                        "type": "type_error",
                        "severity": "high",
                        "line": i,
                        "description": f"Potential TypeError — concatenating string with likely numeric variable '{var}'. Use str({var}) for safe concatenation",
                        "suggestion": f"Wrap '{var}' with str() before concatenation",
                    })
                    break

        # eval() usage
        if "eval(" in stripped:
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

    # Check for empty function bodies
    if "pass" in code and "def " in code:
        issues.append({
            "type": "incomplete",
            "severity": "critical",
            "line": 0,
            "description": "Function body contains only 'pass' — not implemented",
            "suggestion": "Implement the function logic as described in the intent",
        })

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
