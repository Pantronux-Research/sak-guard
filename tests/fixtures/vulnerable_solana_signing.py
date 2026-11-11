"""MUST be flagged by PS-SOL-4. Signs messages it never inspected.

A client that signs whatever it is handed authorizes transactions it did not
construct: the fee payer, the instructions and the account keys are all chosen
by whoever produced the bytes.
"""
from solders.transaction import VersionedTransaction


def relay(blob, keypair):
    tx = VersionedTransaction.from_bytes(blob)
    return keypair.sign_message(tx.message)


def relay_model(prompt, keypair):
    msg = llm.complete(prompt)
    return keypair.sign_message(msg)
