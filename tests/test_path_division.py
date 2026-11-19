import pytest

from sak_guard.analyzer import analyze_patterns


@pytest.mark.parametrize('source, expected', [
    ('from pathlib import Path\n'
     'def output(directory: Path, filename):\n'
     '    result = directory / filename\n', []),
    ('import pathlib as paths\n'
     'BASE = paths.Path(__file__).resolve().parent\n'
     'def output(filename):\n'
     '    result = BASE / filename\n', []),
    ('def divide(total, count):\n    result = total / count\n', [2]),
    ('from elsewhere import Path\n'
     'def divide(total: Path, count):\n    result = total / count\n', [3]),
    ('from pathlib import Path\n'
     'def divide(total: Path, count):\n    total = 42\n    result = total / count\n', [4]),
    ('from pathlib import Path\n'
     'def divide(total: Path, count, amount):\n'
     '    result = (total / count, amount / count)\n', [3]),
    ('from pathlib import Path\n'
     'def outer(total: Path, count):\n'
     '    def divide(other):\n        result = total / other\n', [4]),
])
def test_division_advisory_distinguishes_known_path_joins(source, expected):
    issues = analyze_patterns(source, 'python')
    assert [i['line'] for i in issues
            if i['description'] == 'Division by variable without zero-check'] == expected
