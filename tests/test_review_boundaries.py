"""Non-Solana controls and qualified positives for the post-handoff review."""
import asyncio.tasks
import json
from pathlib import Path
import subprocess
import sys

import pytest

from sak_guard.solana import scan_solana
from sak_guard.strategies import run_strategy
from sak_guard import analyzer
from sak_guard.limits import analysis_entry

STRATEGIES = ("default", "security-focused", "ast-heavy", "intent-focused")
FIXTURES = Path(__file__).parent / "fixtures"
SWAP_IMPORT = "from jupiter_python_sdk.jupiter import Jupiter\nswap = Jupiter.swap\n"


@pytest.mark.parametrize("strategy", STRATEGIES)
@pytest.mark.parametrize("source", [
    'swap(1, 2)',
    'router.route(request)',
    're_route(msg)',
    'value.swapcase()',
    'frame.swapaxes(0,1)',
    'cache.swapdb(1,2)',
    'jupiter(request)',
    '_py_swap_current_task(loop, task)',
    'from solders.pubkey import Pubkey\nrouter.route(request)',
    'from solders.pubkey import Pubkey\nswap(1, 2)',
    'from third_party.web import Router as Jupiter\nclient=Jupiter()\nclient.swap(request)',
])
def test_unrelated_identifiers_never_block_a_commit(strategy, source):
    result = run_strategy(strategy, source, "")
    assert result["passed"] is True, result
    assert not [i for i in result["issues"] if i.get("severity") in ("high", "critical")], result


@pytest.mark.parametrize("filename", ["clean_generic_swaps.py", "clean_http_routes.py"])
def test_non_solana_fixtures_are_clean(filename):
    result = run_strategy("security-focused", (FIXTURES / filename).read_text(), "")
    assert result["passed"] is True, result
    assert result["issues"] == [], result


@pytest.mark.parametrize("source", [
    SWAP_IMPORT + 'swap(client, amount)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc, wallet)\nclient.swap(input_mint=src,output_mint=dest,amount=100)',
    'import jupiter_python_sdk.jupiter as sdk\nclient=sdk.Jupiter(rpc,wallet)\nother=client\nother.swap(input_mint=src,output_mint=dest,amount=100)',
    'from jupiter_python_sdk.jupiter import Jupiter as Dex\ndef trade(client: Dex):\n return client.swap(amount=100)',
    'from jupiter_python_sdk.jupiter import Jupiter\nJupiter(rpc,wallet).swap(amount=100)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\noperation=client.swap\nclient=Router()\noperation(amount=100)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nif flag:\n client=Router()\nclient.swap(amount=100)',
    'import third_party.web as jupiter_python_sdk\nfrom jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient.swap(amount=100)',
])
def test_unbounded_swaps_with_resolved_solana_origins_still_flag(source):
    result = scan_solana(source)
    assert not result["errors"], result
    assert any(i.get("pattern") == "PS-SOL-5" for i in result["issues"]), result


@pytest.mark.parametrize("source", [
    SWAP_IMPORT + 'swap(client,amount,min_amount_out=100)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient.swap(amount=100,slippage_bps=50)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient.get_indexed_route_map()',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient.get_all_swap_pairs()',
    SWAP_IMPORT + 'if False:\n swap(client,amount)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient.route(request)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclient=Jupiter(rpc,wallet)\nclient=Router()\nclient.swap(1,2)',
    'from jupiter_python_sdk.jupiter import Jupiter\nclass Jupiter:\n def swap(self,a,b):\n  return b,a\nclient=Jupiter()\nclient.swap(1,2)',
])
def test_bounds_and_non_swap_sdk_operations_stay_clean(source):
    result = scan_solana(source)
    assert not result["errors"], result
    assert not [i for i in result["issues"] if i.get("pattern") == "PS-SOL-5"], result


def test_real_asyncio_tasks_has_no_solana_findings():
    result = scan_solana(Path(asyncio.tasks.__file__).read_text())
    assert not result["errors"], result
    assert result["issues"] == [], result


def test_real_asyncio_tasks_passes_the_precommit_exit_threshold():
    result = subprocess.run(
        [sys.executable, "-m", "sak_guard.cli", asyncio.tasks.__file__, "--json", "--fail-on", "high"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(r["passed"] for r in json.loads(result.stdout)["reports"])


def test_pattern_pass_parses_once_without_losing_security_findings(monkeypatch):
    original = analyzer.ast.parse
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(analyzer.ast, "parse", counted)
    source = 'q=f"SELECT * FROM users WHERE id={value}"\ncursor.execute(q)\neval(code)'
    issues = analyzer.analyze_patterns(source, "python")
    assert len(calls) == 1
    assert any("SQL injection" in i["description"] for i in issues)
    assert any("eval()" in i["description"] for i in issues)


def test_analysis_boundary_binds_named_parameters_after_a_rename():
    @analysis_entry
    def renamed(strategy, code, intent="", language="python"):
        return {"issues": [], "passed": True}

    assert renamed("test", "x=1")["passed"] is True
    assert renamed(strategy="test", code="x=1")["passed"] is True
    assert renamed("test", "def broken(:")["passed"] is False


@pytest.mark.parametrize("body", [
    'if (Pubkey:=Keypair):\n Pubkey.from_seed(b"01234567890123456789012345678901")',
    'for Pubkey in [Keypair]:\n Pubkey.from_seed(b"01234567890123456789012345678901")',
    'Pubkey, ignored=Keypair, 0\nPubkey.from_seed(b"01234567890123456789012345678901")',
    'match Keypair:\n case Pubkey:\n  Pubkey.from_seed(b"01234567890123456789012345678901")',
    '[Pubkey.from_seed(b"01234567890123456789012345678901") for Pubkey in [Keypair]]',
    '(lambda Pubkey: Pubkey.from_seed(b"01234567890123456789012345678901"))(Keypair)',
    '[(Pubkey:=Keypair) for _ in [1]]\nPubkey.from_seed(b"01234567890123456789012345678901")',
])
def test_all_assignment_shapes_revoke_a_public_key_exemption(body):
    source = 'from solders.pubkey import Pubkey\nfrom solders.keypair import Keypair\n' + body
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_identity_assignment_keeps_a_private_import_origin():
    source = ('from solders.keypair import Keypair as Pubkey\nPubkey=Pubkey\n'
              'Pubkey.from_seed(b"01234567890123456789012345678901")')
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_identity_assignment_keeps_a_real_public_key_clean():
    source = ('from solders.pubkey import Pubkey\nPubkey=Pubkey\n'
              'Pubkey.from_string("11111111111111111111111111111111")')
    result = run_strategy("security-focused", source, "")
    assert result["issues"] == [], result


@pytest.mark.parametrize("body", [
    '[Pubkey.from_string(address) for address in ["11111111111111111111111111111111"]]',
    '[Pubkey for Pubkey in [object]]\nPubkey.from_string("11111111111111111111111111111111")',
    'identity=lambda Pubkey: Pubkey\nPubkey.from_string("11111111111111111111111111111111")',
    'class Addresses:\n values=[address for address in [Pubkey.from_string("11111111111111111111111111111111")]]',
])
def test_expression_scopes_do_not_poison_public_key_imports(body):
    result = run_strategy("security-focused", 'from solders.pubkey import Pubkey\n' + body, "")
    assert result["issues"] == [], result


def test_wrapper_return_uses_the_methods_local_import_origin():
    source = ('class Destination:\n @staticmethod\n def from_string(value):\n'
              '  from solders.keypair import Keypair as Pubkey\n'
              '  return Pubkey.from_seed(value)\n'
              'Destination.from_string(b"01234567890123456789012345678901")')
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_public_wrapper_return_with_local_alias_stays_clean():
    source = ('class Destination:\n @staticmethod\n def from_string(value):\n'
              '  from solders.pubkey import Pubkey as Parser\n'
              '  return Parser.from_string(value)\n'
              'Destination.from_string("11111111111111111111111111111111")')
    result = run_strategy("security-focused", source, "")
    assert result["issues"] == [], result


def test_opaque_return_does_not_inherit_an_inner_public_constructor_exemption():
    source = ('from solders.pubkey import Pubkey\nclass Destination:\n'
              ' @staticmethod\n def from_string(value):\n'
              '  return opaque(Pubkey.from_string(value))\n'
              'Destination.from_string("11111111111111111111111111111111")')
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


@pytest.mark.parametrize("constructor", ["Pubkey", "PrivatePubkey", "WalletAddress"])
def test_an_opaque_import_cannot_claim_public_key_status_by_its_class_name(constructor):
    source = (f'from opaque_provider import {constructor}\n'
              f'{constructor}.from_seed(b"01234567890123456789012345678901")')
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_a_qualified_opaque_pubkey_cannot_claim_sdk_status():
    source = ('import opaque_provider\n'
              'opaque_provider.Pubkey.from_seed(b"01234567890123456789012345678901")')
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-1a" for i in result["issues"]), result


def test_a_qualified_real_sdk_public_key_stays_clean():
    source = ('import solders.pubkey\n'
              'solders.pubkey.Pubkey.from_string("11111111111111111111111111111111")')
    result = run_strategy("security-focused", source, "")
    assert result["issues"] == [], result


@pytest.mark.parametrize("source", [
    'value=llm.complete(q)\nvalue: str\nPubkey(value)',
    'box=json.loads(llm.complete(q))\ndel box["unused"]\nPubkey(box["recipient"])',
    'box=json.loads(llm.complete(q))\nother=box\ndel other["unused"]\nPubkey(box["recipient"])',
])
def test_annotations_and_deletions_cannot_erase_existing_model_provenance(source):
    result = run_strategy("security-focused", source, "")
    assert result["passed"] is False
    assert any(i.get("pattern") == "PS-SOL-3" for i in result["issues"]), result


@pytest.mark.parametrize("source", [
    'from solders.pubkey import Pubkey\nPubkey: type\nPubkey.from_string("11111111111111111111111111111111")',
    'box={"unused":0,"recipient":TRUSTED}\ndel box["unused"]\nPubkey(box["recipient"])',
])
def test_non_rebinding_annotations_and_trusted_deletions_stay_clean(source):
    result = run_strategy("security-focused", source, "")
    assert result["issues"] == [], result


@pytest.mark.parametrize("source", [
    'box=json.loads(llm.complete(q))\naddress=box[(box:="recipient")]\nPubkey(address)',
    'x=TRUSTED\nbox={}\nbox[(x:=llm.complete(q))]=1\nPubkey(x)',
    'x=TRUSTED\nbox={}\nbox[(x:=llm.complete(q))]: str\nPubkey(x)',
    'x=TRUSTED\nbox={}\ndel box[(x:=llm.complete(q))]\nPubkey(x)',
    'x=TRUSTED\n(get_box(x:=llm.complete(q))).field=1\nPubkey(x)',
    'box=json.loads(llm.complete(q))\nother=box\n'
    'if other["recipient"] not in ALLOWED:\n raise ValueError\n'
    'box["recipient"] += ((box:={}),llm.complete(q))[1]\nPubkey(other["recipient"])',
    'box={llm.complete(q):0}\nPubkey(next(iter(box)))',
    'box={address:0 for address in [llm.complete(q)]}\nPubkey(next(iter(box)))',
    'x=TRUSTED\nunused=f"{1:{len(x:=llm.complete(q))}}"\nPubkey(x)',
    'x=TRUSTED\nunused=[(x:=llm.complete(q)) for _ in [1]]\nPubkey(x)',
    'x=TRUSTED\ng=(x for _ in [1])\nx=llm.complete(q)\nPubkey(next(g))',
    'x=TRUSTED\ng=(x for _ in [1])\nx=str(llm.complete(q))\nPubkey(next(g))',
    'x=TRUSTED\nbox={}\nfor box[(x:=llm.complete(q))] in [1]:\n pass\nPubkey(x)',
    'x=TRUSTED\nbox={}\nwith manager() as box[(x:=llm.complete(q))]:\n pass\nPubkey(x)',
    'box=json.loads(llm.complete(q))\n'
    'if box["recipient"] not in ALLOWED:\n raise ValueError\n'
    'unused=[box.update({"recipient":llm.complete(q)}) for _ in [1]]\n'
    'Pubkey(box["recipient"])',
    'box=json.loads(llm.complete(q))\n'
    'if box["recipient"] not in ALLOWED:\n raise ValueError\n'
    'if flag:\n box.update({"recipient":llm.complete(q)})\n'
    'Pubkey(box["recipient"])',
    'def build():\n x=TRUSTED\n g=(x for _ in [1])\n'
    ' x=llm.complete(q)\n return Pubkey(next(g))',
])
def test_python_expression_side_effects_do_not_erase_model_provenance(source):
    result = run_strategy("security-focused", source, "")
    assert any(i.get("pattern") == "PS-SOL-3" for i in result["issues"]), result


REVIEW_HELPER = ('def verify(message, unused=None):\n'
                 ' if message.account_keys[0] != EXPECTED:\n  raise ValueError\n')


@pytest.mark.parametrize("source", [
    REVIEW_HELPER + 'tx=Transaction.from_bytes(raw)\n'
    'verify(tx.message,(tx:=Transaction.from_bytes(other)))\n'
    'kp.sign_message(tx.message_data())',
    'txs=[Transaction.from_bytes(a),Transaction.from_bytes(b)]\n'
    'if txs[0].message.account_keys[0] != EXPECTED:\n raise ValueError\n'
    'wallet.sign_all_transactions(txs)',
    REVIEW_HELPER + 'txs=[Transaction.from_bytes(a),Transaction.from_bytes(b)]\n'
    'verify(txs[0].message)\nwallet.sign_all_transactions(txs)',
])
def test_review_applies_only_to_the_message_value_that_was_checked(source):
    result = run_strategy("security-focused", source, "")
    assert any(i.get("pattern") == "PS-SOL-4" for i in result["issues"]), result


@pytest.mark.parametrize("source", [
    'x=TRUSTED\nunused=[(x:=llm.complete(q)) for _ in []]\nPubkey(x)',
    'x=TRUSTED\nunused=[(x:=llm.complete(q)) for _ in [1] if False]\nPubkey(x)',
    'x=TRUSTED\nunused=[x for x in [llm.complete(q)]]\nPubkey(x)',
    'x=TRUSTED\ng=(x for _ in [1])\nPubkey(next(g))',
    'xs=[TRUSTED]\ng=(x for x in xs)\nxs=llm.complete(q)\nPubkey(next(g))',
    REVIEW_HELPER + 'tx=Transaction.from_bytes(raw)\nverify(tx.message,0)\n'
    'kp.sign_message(tx.message_data())',
    'txs=[Transaction.from_bytes(a),Transaction.from_bytes(b)]\n'
    'if txs[0].message.account_keys[0] != EXPECTED:\n raise ValueError\n'
    'kp.sign_message(txs[0].message_data())',
])
def test_expression_and_review_safe_neighbours_remain_clean(source):
    result = run_strategy("security-focused", source, "")
    assert not [i for i in result["issues"]
                if i.get("severity") in ("high", "critical")], result
