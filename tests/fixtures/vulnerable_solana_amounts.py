"""MUST flag PS-SOL-5: unbounded amounts and a swap with no explicit bound."""
from solders.pubkey import Pubkey
from jupiter_python_sdk.jupiter import Jupiter


def send(dest, amount):
    transfer(Pubkey(dest), amount)


def send_from_input(dest):
    amt = int(input())
    transfer(Pubkey(dest), amt)


def trade(client: Jupiter, pool, amount):
    client.swap(input_mint=INPUT_MINT, output_mint=pool, amount=amount)
