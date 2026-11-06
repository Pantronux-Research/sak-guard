"""MUST stay clean for PS-SOL-3. Model output validated before use."""
import json

from solders.commitment_config import CommitmentLevel
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from solana.rpc.types import TxOpts

client = Client("https://api.mainnet-beta.solana.com")
ALLOWED_RECIPIENTS = {"9xQeWvG816bUx9EPa2rJkQ1y2tFk4r5XcN7bA8dE3fG1"}


def pay(user_request):
    plan = llm.complete(user_request)
    dest = json.loads(plan)["recipient"]
    if dest not in ALLOWED_RECIPIENTS:
        raise ValueError("recipient is not allow-listed")
    tx = transfer(Pubkey(dest), 1)
    sig = client.send_transaction(
        tx, opts=TxOpts(commitment=CommitmentLevel.Confirmed)
    )
    client.confirm_transaction(sig.value, commitment="confirmed")
    return sig
