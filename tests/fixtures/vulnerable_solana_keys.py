"""MUST be flagged by PS-SOL-1. Literal key material in agent code."""
import base58
from solders.keypair import Keypair

SECRET = "4Zk8QvN2mLpR7xYwT3bHcJ6dFgA9sWe1oUvXyZ2nQrM8kLpVbCdEfGhJiKnOpQrStUvWxYz12"
keypair = Keypair.from_base58_string(SECRET)
print(f"loaded key {SECRET}")

MNEMONIC = ("abandon ability able about above absent absorb abstract absurd abuse "
            "access accident account accuse achieve acid acoustic acquire across "
            "act action actor actress actual")
derived = Keypair.from_seed(bytes(64))
raw = base58.b58decode("4Zk8QvN2mLpR7xYwT3bHc")
