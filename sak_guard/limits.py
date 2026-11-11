"""Shared, fail-closed limits for public analysis entry points."""
import ast
import functools
import inspect

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_AST_NODES = 200_000
MAX_ANALYSIS_STEPS = 500_000


def failure(message, line=0):
    issue = {"type": "analysis_error", "severity": "critical", "line": line,
             "description": f"Required analysis did not complete: {message}",
             "suggestion": "Resolve the scan error before accepting this file."}
    return {"issues": [issue], "passed": False, "confidence": 0.0,
            "suggestions": [issue["suggestion"]]}


def validate_source(code, language="python"):
    if language != "python":
        raise ValueError("only Python source is supported")
    if not isinstance(code, str):
        raise TypeError("source must be a string")
    if len(code.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError(f"source exceeds the {MAX_SOURCE_BYTES}-byte analysis limit")
    tree = ast.parse(code)
    for count, _ in enumerate(ast.walk(tree), 1):
        if count > MAX_AST_NODES:
            raise ValueError(f"source exceeds the {MAX_AST_NODES}-node AST limit")
    return tree


def analysis_entry(fn):
    """A failed required pass cannot escape as a clean result or a traceback."""
    signature = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            code = bound.arguments["code"]
            language = bound.arguments.get("language", "python")
            validate_source(code, language)
            return fn(*args, **kwargs)
        except SyntaxError as exc:
            return failure(f"Syntax error: {exc.msg}", exc.lineno or 0)
        except Exception as exc:
            return failure(f"{type(exc).__name__}: {exc}")
    return wrapped
