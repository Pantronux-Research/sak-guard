"""MUST stay clean for PS-SOL-1. No literal key material."""
import json
import logging
import os
from pathlib import Path

from solders.keypair import Keypair

logger = logging.getLogger(__name__)
SECRET = os.environ["SOLANA_PRIVATE_KEY"]
keypair = Keypair.from_base58_string(SECRET)
logger.info("keypair loaded")


def load_keypair(path: Path) -> Keypair:
    return Keypair.from_json(path.read_text())


def public_id(kp: Keypair) -> str:
    return str(kp.pubkey())
