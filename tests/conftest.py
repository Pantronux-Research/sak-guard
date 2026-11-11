"""Make the repo root importable before any test module is imported.

Without this, pytest's rootdir handling puts `tests/` on sys.path but not the
repository root, so `import sak_guard` resolves to whatever copy is installed in
site-packages. That copy can be older than the working tree -- it lacked
solana.py entirely -- and because Python caches the module on first import, one
test module importing it first silently forces every later test module to run
against the installed code instead of the source under test.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
