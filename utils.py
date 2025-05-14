# utils.py
import json
import base64
import logging
import os
from typing import Any, Dict

from solders.keypair import Keypair  # type: ignore
from solders.pubkey import Pubkey  # type: ignore
from nacl.signing import SigningKey, VerifyKey  # type: ignore
from nacl.public import PrivateKey, PublicKey, Box  # type: ignore
from nacl.encoding import HexEncoder, Base64Encoder  # type: ignore

import config


def setup_logging():
    logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)

# --- Key Management --- #


def generate_keypair() -> Keypair:
    """Generates a new Solana keypair."""
    return Keypair()


def save_keypair_to_file(keypair: Keypair, filepath: str):
    """Saves a Solana keypair to a file (stores the secret key bytes)."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        f.write(keypair.secret_key())
    logging.info(f"Keypair saved to {filepath}")


def load_keypair_from_file(filepath: str) -> Keypair:
    """Loads a Solana keypair from a file."""
    with open(filepath, 'rb') as f:
        secret_key_bytes = f.read()
    return Keypair.from_bytes(secret_key_bytes)

# --- Cryptographic Operations (using PyNaCl) --- #


def sign_message(message: bytes, signing_key: SigningKey) -> bytes:
    """Signs a message using a private Ed25519 signing key."""
    return signing_key.sign(message).signature


def verify_signature(signed_message: bytes, signature: bytes, verify_key: VerifyKey) -> bool:
    """Verifies a signature using a public Ed25519 verify key."""
    try:
        verify_key.verify(signed_message, signature)
        return True
    except Exception:
        return False


def get_signing_key_from_seed(seed: bytes) -> SigningKey:
    """Derives an Ed25519 signing key from a seed (e.g., Solana secret key)."""
    # Solana keypair uses Ed25519. PyNaCl SigningKey can be created from a 32-byte seed.
    # Solana secret key is typically 64 bytes [secret_key_half (32 bytes), public_key_half (32 bytes)]
    # Or just 32 bytes if it's purely the secret part.
    # Keypair.secret_key() returns the 64-byte version for Solana.
    # We need the 32-byte seed part for PyNaCl's SigningKey.
    if len(seed) == 64:
        # Use the first 32 bytes as the seed for Ed25519 signing key
        seed = seed[:32]
    elif len(seed) != 32:
        raise ValueError(
            "Seed must be 32 or 64 bytes long for Ed25519 signing key.")
    return SigningKey(seed)


def get_verify_key(signing_key: SigningKey) -> VerifyKey:
    """Gets the public verification key from an Ed25519 signing key."""
    return signing_key.verify_key


def get_verify_key_from_bytes(public_key_bytes: bytes) -> VerifyKey:
    """Creates a VerifyKey from public key bytes."""
    return VerifyKey(public_key_bytes)


# --- Encryption (using PyNaCl Box for asymmetric encryption) --- #

def generate_encryption_keypair() -> tuple[PrivateKey, PublicKey]:
    """Generates a keypair for asymmetric encryption (Curve25519)."""
    sk = PrivateKey.generate()
    pk = sk.public_key
    return sk, pk


def encrypt_message(message: bytes, public_key: PublicKey, private_key: PrivateKey) -> bytes:
    """Encrypts a message using the recipient's public key and sender's private key."""
    box = Box(private_key, public_key)
    # A nonce is required for encryption, must be unique for each message encrypted with this key pair
    nonce = os.urandom(Box.NONCE_SIZE)
    encrypted = box.encrypt(message, nonce)
    return encrypted  # The nonce is prepended to the ciphertext by default with box.encrypt


def decrypt_message(encrypted_message_with_nonce: bytes, public_key: PublicKey, private_key: PrivateKey) -> bytes:
    """Decrypts an encrypted message using the recipient's private key and sender's public key."""
    box = Box(private_key, public_key)
    # The nonce is prepended to the ciphertext by Box.encrypt
    return box.decrypt(encrypted_message_with_nonce)


# --- Serialization --- #

def serialize_data_to_json(data: Any) -> str:
    """Serializes Python data to a JSON string."""
    return json.dumps(data, sort_keys=True)


def deserialize_data_from_json(json_str: str) -> Any:
    """Deserializes a JSON string to Python data."""
    return json.loads(json_str)


def b64encode_str(data: str) -> str:
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def b64decode_str(encoded_data: str) -> str:
    return base64.b64decode(encoded_data.encode('utf-8')).decode('utf-8')


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def b64decode_bytes(encoded_data: str) -> bytes:
    return base64.b64decode(encoded_data.encode('utf-8'))

# --- Solana specific helpers --- #


def pubkey_to_str(pubkey: Pubkey) -> str:
    return str(pubkey)


def str_to_pubkey(s: str) -> Pubkey:
    return Pubkey.from_string(s)


# Initialize logging when the module is imported
setup_logging()
