"""A small, well-behaved module."""
import subprocess


def fetch(url: str) -> str:
    """Fetch a URL with an argument list -- no shell involved."""
    out = subprocess.run(["curl", "--silent", url], capture_output=True,
                         check=False, timeout=10)
    return out.stdout.decode("utf-8", "replace")


def add(a: int, b: int) -> int:
    return a + b
