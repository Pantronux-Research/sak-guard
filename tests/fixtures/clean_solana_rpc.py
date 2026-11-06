"""MUST stay clean for PS-SOL-2. Correct RPC usage."""
from solders.commitment_config import CommitmentLevel
from solders.transaction import VersionedTransaction
from solana.rpc.api import Client
from solana.rpc.types import TxOpts

client = Client("https://api.mainnet-beta.solana.com")


def execute(tx: VersionedTransaction):
    sim = client.simulate_transaction(tx)
    if sim.value.err:
        raise RuntimeError(f"simulation failed: {sim.value.err}")

    blockhash = client.get_latest_blockhash()
    tx.message.recent_blockhash = blockhash.value.blockhash
    sig = client.send_transaction(
        tx, opts=TxOpts(commitment=CommitmentLevel.Confirmed, preflight_commitment=CommitmentLevel.Confirmed)
    )
    client.confirm_transaction(sig.value, commitment="confirmed")
    return sig
