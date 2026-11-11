"""Isolated CLI worker. Only the analyzer executes; submitted code never does."""
import json
import sys

from .limits import MAX_SOURCE_BYTES, failure

# json.dumps defaults to ensure_ascii=True. A single source byte can expand to
# six ASCII bytes (e.g. a control character encoded as \\u0000). Supplementary
# Unicode uses surrogate pairs but still fits this bound per UTF-8 source byte.
# Reserve a separate allowance for JSON field names, intent and strategy/options.
MAX_REQUEST_BYTES = MAX_SOURCE_BYTES * 6 + 8192


def main():
    # A killed or memory-limited worker is an explicit scan failure in the CLI.
    # resource is unavailable on Windows; the parent timeout still applies.
    try:
        import resource
        if sys.platform.startswith("linux"):
            cap = 1024 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except (ImportError, OSError, ValueError):
        pass
    try:
        payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("worker request exceeds its JSON transport limit")
        request = json.loads(payload)
        from .strategies import run_strategy
        result = run_strategy(**request)
        if len(result.get("issues", [])) > 10_000:
            result = failure("finding count exceeded the 10000-issue reporting limit")
    except Exception as exc:
        result = failure(f"{type(exc).__name__}: {exc}")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
