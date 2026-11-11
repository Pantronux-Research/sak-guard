"""Security boundary regressions from the remediation handoff review.

These assert externally visible verdicts, including safe neighbours. They do
not execute the submitted source or require the Solana SDK or an LLM provider.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from sak_guard.solana import scan_solana
from sak_guard.strategies import run_strategy


@pytest.mark.parametrize("code", [
    'x="safe"\ny=(x := "safe") if flag else (x := llm.complete(q))\nPubkey(x)',
    'x=llm.complete(q)\ny=flag and (x := "safe")\nPubkey(x)',
    'x=llm.complete(q)\ny=flag or (x := "safe")\nPubkey(x)',
    'box=llm.complete(q)\nk="a"\nif box[k] not in ALLOWED: raise ValueError\nPubkey(box["b"])',
    'box=llm.complete(q)\nif box["a"] not in ALLOWED: raise ValueError\ntransfer(box["a"],box["b"])',
    'box=llm.complete(q)\nmatch box:\n case {"address": x}:\n  Pubkey(x)',
    'x="safe"\nbox={}\nbox[key]=llm.complete(q)\nPubkey(box["address"])',
    'x=llm.complete(q)\nif x not in ALLOWED: raise ValueError\n'
    'box={"a":x}\nother=box\nother={}\nother["a"]="safe"\n'
    'box["a"]=llm.complete(q)\nPubkey(other["a"] if flag else box["a"])',
    'x=llm.complete(q)\nif x not in ALLOWED: raise ValueError\n'
    'box={"a":x}\nother=box\nother={}\nbox["a"]=llm.complete(q)\n'
    'other["a"]="safe"\nPubkey(box["a"])',
    'x="safe"\nPubkey((x := llm.complete(q)))',
    'x="safe"\ntry:\n x=llm.complete(q)\n work()\n x="safe"\nexcept Exception:\n Pubkey(x)',
    'x=llm.complete(q)\ny=0>1>(x:="safe")\nPubkey(x)',
    'x=llm.complete(q)\nif x not in ALLOWED: raise ValueError\ny=transform(x)\nPubkey(y)',
    'x="safe"\ndef outer():\n x="safe"\n def submit():\n  Pubkey(x)\n x=llm.complete(q)\n submit()\nouter()',
    'def pay(q,ALLOWED):\n x=llm.complete(q)\n if x not in ALLOWED: raise ValueError\n Pubkey(x)',
    'def unused(x=Pubkey(llm.complete(q))): pass',
    'def pay(x=llm.complete(q)):\n Pubkey(x)',
    'Pubkey((lambda: llm.complete(q))())',
    'x="safe"\ntry:\n raise ValueError\nexcept ValueError:\n x=llm.complete(q)\n raise\nfinally:\n Pubkey(x)',
    'x="safe"\nwhile (x:=llm.complete(q)):\n Pubkey(x)\n break',
    'x="safe"\nfor _ in [(x:=llm.complete(q))]:\n Pubkey(x)',
])
def test_unchecked_model_flows_fail_closed(code):
    result = scan_solana(code)
    assert not result["errors"], result
    assert any(i.get("pattern") == "PS-SOL-3" for i in result["issues"]), result


@pytest.mark.parametrize("code", [
    'def pay(a):\n transfer(dest,min(a,a+1))',
    'def pay(a,limit):\n transfer(dest,min(a,limit))',
    'def pay(a,limit):\n capped=min(a,limit)\n transfer(dest,capped)',
    'def pay(a,limit):\n if a>limit: raise ValueError\n transfer(dest,a)',
    'def pay(a):\n transfer(dest,(a if flag else 1))',
    'transfer(dest,int(input()))',
    'def pay(a):\n params=TransferParams(from_pubkey=src,to_pubkey=dest,lamports=a)\n transfer(params)',
    'def pay(a):\n transfer(dest,min(a,float("inf")))',
])
def test_unbounded_amount_expressions_are_flagged(code):
    result = scan_solana(code)
    assert not result["errors"], result
    assert any(i.get("pattern") == "PS-SOL-5" for i in result["issues"]), result


@pytest.mark.parametrize("code", [
    'tx=Transaction.from_bytes(raw)\nif tx.message.account_keys!=tx.message.account_keys: raise ValueError\nkp.sign_message(tx.message_data())',
    'tx=Transaction.from_bytes(raw)\nexpected=tx.message.account_keys\nif tx.message.account_keys!=expected: raise ValueError\nkp.sign_message(tx.message_data())',
    'def relay(blob, s):\n return s.signTransaction(blob)',
    'tx=Transaction.from_bytes(raw)\nif tx.message.account_keys[0]!=EXPECTED: raise ValueError\n'
    'tx.message.instructions=attacker\nkp.sign_message(tx.message_data())',
])
def test_unreviewed_messages_are_flagged(code):
    result = scan_solana(code)
    assert not result["errors"], result
    assert any(i.get("pattern") == "PS-SOL-4" for i in result["issues"]), result


@pytest.mark.parametrize("helper", [
    'def verify(m):\n if m.account_keys[0]!=EXPECTED: return',
    'def verify(m):\n return\n if m.account_keys[0]!=EXPECTED: raise ValueError',
    'def verify(m):\n if m.account_keys!=m.account_keys: raise ValueError',
    'def verify(m):\n if m.account_keys[0]!=EXPECTED:\n  return\n  raise ValueError',
    'def verify(m):\n if m.account_keys[0]!=EXPECTED: raise ValueError\nverify=lambda m: None',
])
def test_review_helpers_must_enforce_on_every_return(helper):
    code = helper + '\ntx=Transaction.from_bytes(raw)\nverify(tx.message)\nkp.sign_message(tx.message_data())'
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-4" for i in result["issues"]), result


@pytest.mark.parametrize("code", [
    'x=llm.complete(q)\nif x not in ALLOWED: raise ValueError\n'
    'box={"a":x}\nother={"a":x}\nbox["a"]=llm.complete(q)\nother["a"]="safe"\nPubkey(box["a"])',
    'x="safe"\nwith suppress(Exception):\n x=llm.complete(q)\n raise ValueError\nPubkey(x)',
    'box=llm.complete(q)\nif box["a"] not in ALLOWED: raise ValueError\n'
    'box.update({"a":llm.complete(q)})\nPubkey(box["a"])',
])
def test_mutation_and_suppressed_exit_cannot_hide_model_flows(code):
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-3" for i in result["issues"]), result


@pytest.mark.parametrize("code", [
    'def unused(amount): pass\namount=100\ntransfer(dest,amount)',
    'def pay(a):\n transfer(dest,min(a,100))',
    'def pay(a):\n capped=min(a,100)\n transfer(dest,capped)',
    'x=llm.complete(q)\nif x not in ALLOWED: raise ValueError\nPubkey(x)',
    'box=llm.complete(q)\nif box["a"] not in ALLOWED: raise ValueError\nPubkey(box["a"])',
    'from jupiter_python_sdk.jupiter import Jupiter\nswap=Jupiter.swap\nmin_out=10\nswap(dest,min_amount_out=min_out)',
    'tx=Transaction.from_bytes(raw)\nif tx.message.account_keys[0]!=EXPECTED: raise ValueError\nkp.sign_message(tx.message_data())',
    'x="safe"\nif False:\n x=llm.complete(q)\nPubkey(x)',
])
def test_safe_neighbours_have_no_security_findings(code):
    result = scan_solana(code)
    assert not result["errors"], result
    assert not [i for i in result["issues"] if i["severity"] in ("critical", "high")], result


@pytest.mark.parametrize("strategy", ["default", "ast-heavy", "security-focused", "intent-focused"])
def test_parse_failure_never_reports_passed(strategy):
    result = run_strategy(strategy, 'def broken(:\n', "")
    assert not result["passed"]
    assert any(i["severity"] == "critical" for i in result["issues"])


def test_cli_rejects_oversized_utf8_bytes_before_analysis():
    source = ("#" + "🙂" * 1_100_000 + "\n").encode()
    proc = subprocess.run([sys.executable, "-m", "sak_guard.cli", "-", "--json"],
                          input=source, capture_output=True, timeout=10)
    assert proc.returncode == 2, proc.stdout[:200]
    assert b"analysis limit" in proc.stderr


@pytest.mark.parametrize("code", [
    'if r.value.err: raise ValueError\nr=client.simulate_transaction(tx)',
    'def unused(r):\n if r.value.err: raise ValueError\nr=client.simulate_transaction(tx)',
    'r=client.simulate_transaction(tx)\nif enabled:\n if r.value.err: raise ValueError',
    'r=client.simulate_transaction(tx)\nr=TRUSTED\nif r.value.err: raise ValueError',
    'r=client.simulate_transaction(tx)\nclient.send_transaction(tx,commitment="confirmed")\nif r.value.err: raise ValueError',
])
def test_simulation_check_belongs_to_the_result_and_dominates_submission(code):
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-2b" for i in result["issues"]), result


def test_unreachable_confirmation_does_not_clear_submission():
    code = 'def submit():\n client.send_transaction(tx)\n return\n client.confirm_transaction(sig)'
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-2a" for i in result["issues"]), result


@pytest.mark.parametrize("confirmation,unsafe", [
    ('client.confirm_transaction(sig.value)', True),
    ('await client.confirm_transaction(sig.value)', False),
    ('pending=client.confirm_transaction(sig.value)\n await pending', False),
])
def test_async_confirmation_requires_execution(confirmation, unsafe):
    code = ('from solana.rpc.async_api import AsyncClient\nclient=AsyncClient(URL)\n'
            'async def submit(tx):\n sig=await client.send_transaction(tx)\n ' + confirmation)
    result = scan_solana(code)
    assert bool([i for i in result["issues"] if i.get("pattern") == "PS-SOL-2a"]) is unsafe, result


def test_cli_worker_uses_its_own_package_from_an_untrusted_cwd(tmp_path):
    root = str(Path(__file__).resolve().parents[1])
    marker = tmp_path / "executed"
    fake = tmp_path / "sak_guard"
    fake.mkdir()
    (fake / "__init__.py").write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    target = tmp_path / "unsafe.py"
    target.write_text('eval(user_input)\n')
    bootstrap = 'import sys; sys.path.insert(0,sys.argv[1]); from sak_guard.cli import main; sys.exit(main(sys.argv[2:]))'
    proc = subprocess.run([sys.executable, "-I", "-c", bootstrap, root, str(target), "--json"],
                          cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not marker.exists()
    assert json.loads(proc.stdout)["reports"][0]["passed"] is False


@pytest.mark.parametrize("code,pattern", [
    ('def min(a,b): return a\ndef pay(a):\n transfer(dest,min(a,100))', "PS-SOL-5"),
    ('def verify(m):\n expected=m.account_keys\n if m.account_keys!=expected: raise ValueError\n'
     'tx=Transaction.from_bytes(raw)\nverify(tx.message)\nkp.sign_message(tx.message_data())', "PS-SOL-4"),
    ('def verify(m):\n if m.account_keys[0]!=EXPECTED: raise ValueError\n'
     'def relay(raw,verify):\n tx=Transaction.from_bytes(raw)\n verify(tx.message)\n kp.sign_message(tx.message_data())', "PS-SOL-4"),
])
def test_rebound_contracts_cannot_certify_values(code, pattern):
    result = scan_solana(code)
    assert any(i.get("pattern") == pattern for i in result["issues"]), result


def test_public_import_inside_class_does_not_rebind_module_key_loader():
    code = ('from solders.keypair import Keypair as C\nclass Scope:\n'
            ' from solders.pubkey import Pubkey as C\n'
            'C.from_seed(b"01234567890123456789012345678901")')
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


@pytest.mark.parametrize("prefix", [
    'from solders.pubkey import Pubkey\ndef private_factory():\n from solders.keypair import Keypair\n return Keypair\nPubkey=private_factory()\n',
    'from solders.pubkey import Pubkey as C; from solders.keypair import Keypair as C; ',
    'from solders.pubkey import Pubkey as C\ndef loader(C):\n ',
])
def test_unknown_or_later_private_binding_cannot_gain_public_exemption(prefix):
    name = "Pubkey" if "private_factory" in prefix else "C"
    code = prefix + f'{name}.from_seed(b"01234567890123456789012345678901")'
    result = scan_solana(code)
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_known_non_key_loader_is_not_a_private_key():
    result = scan_solana('n=int.from_bytes(b"12", "big")')
    assert not result["issues"], result


@pytest.mark.parametrize("code,unsafe", [
    ('k=b"01234567890123456789012345678901"\nk=read_secret()\nKeypair.from_seed(k)', False),
    ('def unused():\n k=b"01234567890123456789012345678901"\ndef load(k):\n return Keypair.from_seed(k)', False),
    ('s="01234567890123456789012345678901"\nKeypair.from_seed(s.encode())', True),
    ('s="3mJr7AoUXx2Wqd"\nk=base58.b58decode(s)\nKeypair.from_seed(k)', True),
    ('raw=base58.b58decode("3mJr7AoUXx2Wqd")', False),
    ('def load(k=b"01234567890123456789012345678901"):\n return Keypair.from_seed(k)', True),
])
def test_embedded_key_provenance_is_scoped_and_ordered(code, unsafe):
    result = scan_solana(code)
    assert bool([i for i in result["issues"] if i.get("pattern") == "PS-SOL-1a"]) is unsafe, result


@pytest.mark.parametrize("threshold", ["critical", "high", "never"])
def test_incomplete_analysis_is_an_error_even_in_report_only_mode(threshold):
    proc = subprocess.run([sys.executable, "-m", "sak_guard.cli", "-", "--json", "--fail-on", threshold],
                          input='def broken(:\n', text=True, capture_output=True, timeout=10)
    assert proc.returncode == 2
    report = json.loads(proc.stdout)["reports"][0]
    assert report["passed"] is False
    assert any(i["type"] == "analysis_error" for i in report["issues"])


def test_worker_timeout_returns_a_failure(monkeypatch):
    from sak_guard import cli

    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 15)
    monkeypatch.setattr(cli.subprocess, "run", timed_out)
    issues, _, passed = cli.audit('x=1', '', 'python', False)
    assert passed is False
    assert issues[0]["type"] == "analysis_error"


@pytest.mark.parametrize("strategy", ["default", "ast-heavy", "security-focused", "intent-focused"])
def test_required_analysis_exceptions_cannot_escape_as_clean(monkeypatch, strategy):
    from sak_guard.dataflow import Interpreter

    def fail(*args, **kwargs):
        raise RuntimeError("forced required-pass failure")
    monkeypatch.setattr(Interpreter, "run", fail)
    result = run_strategy(strategy, 'x=llm.complete(q)\nPubkey(x)', '')
    assert result["passed"] is False
    assert any(i["type"] == "analysis_error" and i["severity"] == "critical" for i in result["issues"])

