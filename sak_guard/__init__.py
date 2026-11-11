"""sak-guard -- static pre-commit security guardrail for Solana agent code."""
__version__ = "0.2.0a1"
from .analyzer import analyze_code          # noqa: F401
from .strategies import run_strategy        # noqa: F401
