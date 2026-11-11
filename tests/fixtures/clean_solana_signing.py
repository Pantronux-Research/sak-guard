"""MUST stay clean for PS-SOL-4. Reviews the message before signing."""
from solders.transaction import VersionedTransaction

EXPECTED_FEE_PAYER = "9xQeWvG816bUx9EPa2rJkQ1y2tFk4r5XcN7bA8dE3fG1"


def relay(blob, keypair):
    tx = VersionedTransaction.from_bytes(blob)
    if str(tx.message.account_keys[0]) != EXPECTED_FEE_PAYER:
        raise ValueError("unexpected fee payer")
    for ix in tx.message.instructions:
        if ix.program_id_index > len(tx.message.account_keys):
            raise ValueError("malformed instruction")
    return keypair.sign_message(tx.message)
