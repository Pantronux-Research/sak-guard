"""MUST stay clean for PS-SOL-5. Amounts are capped and swaps are bounded."""
from solders.pubkey import Pubkey
from jupiter_python_sdk.jupiter import Jupiter

MAX_LAMPORTS = 1_000_000_000


def send(dest, amount):
    if amount > MAX_LAMPORTS:
        raise ValueError("amount exceeds the per-transfer cap")
    return transfer(Pubkey(dest), amount)


def send_capped(dest, amount):
    capped = min(amount, MAX_LAMPORTS)
    return transfer(Pubkey(dest), capped)


def trade(client: Jupiter, pool, amount):
    return client.swap(input_mint=INPUT_MINT, output_mint=pool,
                       amount=amount, slippage_bps=50)
