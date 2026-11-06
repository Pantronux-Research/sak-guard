"""MUST be flagged by PS-SOL-2a/2b/2c. RPC misuse in an agent loop."""
from solana.rpc.api import Client

client = Client("https://api.mainnet-beta.solana.com")


def execute(tx, prompt):
    sim = client.simulate_transaction(tx)
    blockhash = client.get_latest_blockhash()
    plan = llm.complete(prompt)
    tx.recent_blockhash = blockhash.value.blockhash
    return client.send_transaction(tx)
