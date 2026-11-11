import json

import pytest

from sak_guard import analyzer
from sak_guard.strategies import run_strategy
from sak_guard.solana import scan_solana


@pytest.mark.parametrize("raw", ["[]", "null", "42", '{"issues":[{"line":1e999}]}', '{"issues":[null]}'])
def test_llm_malformed_responses_are_controlled(monkeypatch, raw):
    class Fake:
        def chat(self, *args):
            return raw
    monkeypatch.setattr(analyzer, "_get_llm_client", lambda: Fake())
    result = analyzer._llm_analyze_intent("pass", "test", "python")
    assert result is None or isinstance(result, list)


def test_intent_strategy_requires_explicit_network_opt_in(monkeypatch):
    def forbidden(*args):
        raise AssertionError("source would have left the machine without consent")
    monkeypatch.setattr("sak_guard.strategies._llm_analyze_intent", forbidden)
    run_strategy("intent-focused", "x=1", "a test")


@pytest.mark.parametrize("code,unsafe", [
    ('q=f"SELECT * FROM users WHERE id={user_input}"\nalias=q\ncursor.execute(alias)', True),
    ('q=f"SELECT * FROM users WHERE id={user_input}"\nq="SELECT 1"\ncursor.execute(q)', False),
    ('cursor.execute("SELECT "+"1")', False),
    ('cursor.execute("SELECT * FROM users WHERE id=%s", (user_input,))', False),
])
def test_sql_string_provenance(code, unsafe):
    hits = [i for i in analyzer.analyze_patterns(code, "python") if "SQL" in i["description"]]
    assert bool(hits) is unsafe


@pytest.mark.parametrize("assignment,unsafe", [
    ('password="hunter2"', True),
    ('password: str="SECRET123"', True),
    ('token="SOL"', False),
    ('api_key=""', False),
])
def test_secret_labels_do_not_exempt_passwords(assignment, unsafe):
    hits = [i for i in analyzer.analyze_patterns(assignment, "python") if "Hardcoded secret" in i["description"]]
    assert bool(hits) is unsafe


@pytest.mark.parametrize("code,unsafe", [
    ('subprocess.run(cmd)\nunrelated(shell=True)', False),
    ('subprocess.run(cmd,\n shell=True)', True),
    ('from subprocess import run as execute\nexecute(cmd,shell=True)', True),
    ('text=f"{subprocess.run(cmd,shell=True)}"', True),
    ('text="subprocess.run(cmd,shell=True)"', False),
    ('yaml.load(text, Loader=yaml.SafeLoader)', False),
    ('yaml.load(text, Loader=yaml.UnsafeLoader)\nx="SafeLoader"', True),
])
def test_security_checks_respect_ast_call_boundaries(code, unsafe):
    result = run_strategy("security-focused", code, "")
    hits = [i for i in result["issues"] if i["type"] == "security" and i["severity"] in ("critical", "high")]
    assert bool(hits) is unsafe, result


@pytest.mark.parametrize("words", [12, 15, 18, 21, 24])
def test_mnemonics_use_context_and_all_standard_lengths(words):
    code = 'mnemonic="' + ' '.join(['abandon'] * (words - 1) + ['about']) + '"\n'
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-1b" for i in result["issues"])


def test_ordinary_twelve_word_sentence_is_not_a_critical_secret():
    code = '# solana\ntext="this is a normal sentence for testing only and contains twelve words"\n'
    result = scan_solana(code)
    assert not [i for i in result["issues"] if i.get("pattern") == "PS-SOL-1b" and i["severity"] == "critical"]


@pytest.mark.parametrize("code,missing", [
    ('def f(x) -> int:\n if x: return 1\n else: print(x)', True),
    ('from typing import NoReturn\ndef f() -> NoReturn:\n raise ValueError', False),
    ('def f(x) -> int:\n if x: return 1\n else: return 2', False),
])
def test_return_paths(code, missing):
    hits = [i for i in analyzer.analyze_patterns(code, "python") if "may return None" in i["description"]]
    assert bool(hits) is missing


@pytest.mark.parametrize("code,unsafe", [
    ('x=5\nx="5"\ns="id:"+x+"!"', False),
    ('def other():\n x=5\nx="5"\ns="id:"+x+"!"', False),
    ('a=5\ns="id:"+a+"!"', True),
    ('def f(n:int):\n return "id:"+n+"!"', True),
])
def test_concat_types_are_scoped_and_follow_overwrites(code, unsafe):
    hits = [i for i in analyzer.analyze_patterns(code, "python") if i["type"] == "type_error"]
    assert bool(hits) is unsafe, hits

