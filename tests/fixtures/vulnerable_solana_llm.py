"""MUST be flagged by PS-SOL-3. Model output straight into a transfer."""
import json

from solders.pubkey import Pubkey
from solana.rpc.api import Client

client = Client("https://api.mainnet-beta.solana.com")


def pay(user_request):
    plan = llm.complete(user_request)
    dest = json.loads(plan)["recipient"]
    amount = json.loads(plan)["amount"]
    return client.send_transaction(transfer(Pubkey(dest), amount))
