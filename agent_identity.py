# agent_identity.py
import os
import logging

from solders.keypair import Keypair  # type: ignore
from solders.pubkey import Pubkey  # type: ignore
from nacl.signing import SigningKey, VerifyKey  # type: ignore
from nacl.public import PrivateKey as Curve25519PrivateKey, PublicKey as Curve25519PublicKey  # type: ignore

import utils
import config

logger = logging.getLogger(__name__)


class AgentIdentity:
    """Manages the cryptographic identity of an agent."""

    def __init__(self, solana_keypair: Keypair, encryption_priv_key: Optional[Curve25519PrivateKey] = None):
        self._solana_keypair = solana_keypair
        self._signing_key = utils.get_signing_key_from_seed(
            self._solana_keypair.secret_key())
        self._verify_key = utils.get_verify_key(self._signing_key)

        if encryption_priv_key:
            self._encryption_private_key = encryption_priv_key
            self._encryption_public_key = encryption_priv_key.public_key
        else:
            self._encryption_private_key, self._encryption_public_key = utils.generate_encryption_keypair()

    @property
    def solana_keypair(self) -> Keypair:
        return self._solana_keypair

    @property
    def public_key(self) -> Pubkey:
        """Returns the Solana public key of the agent."""
        return self._solana_keypair.pubkey()

    @property
    def public_key_str(self) -> str:
        """Returns the string representation of the Solana public key."""
        return utils.pubkey_to_str(self.public_key)

    @property
    def signing_key(self) -> SigningKey:
        """Returns the Ed25519 signing key (derived from Solana keypair)."""
        return self._signing_key

    @property
    def verify_key(self) -> VerifyKey:
        """Returns the Ed25519 verification key."""
        return self._verify_key

    @property
    def verify_key_bytes(self) -> bytes:
        """Returns the bytes of the Ed25519 verification key."""
        return bytes(self._verify_key)

    @property
    def encryption_private_key(self) -> Curve25519PrivateKey:
        """Returns the Curve25519 private key for encryption."""
        return self._encryption_private_key

    @property
    def encryption_public_key(self) -> Curve25519PublicKey:
        """Returns the Curve25519 public key for encryption."""
        return self._encryption_public_key

    @property
    def encryption_public_key_b64(self) -> str:
        """Returns the base64 encoded Curve25519 public key for encryption."""
        return utils.b64encode_bytes(bytes(self._encryption_public_key))

    @classmethod
    def generate(cls) -> 'AgentIdentity':
        """Generates a new agent identity with a new Solana keypair."""
        solana_kp = utils.generate_keypair()
        logger.info(
            f"Generated new agent identity with public key: {solana_kp.pubkey()}")
        return cls(solana_keypair=solana_kp)

    @classmethod
    def from_keypair_file(cls, filepath: str, encryption_priv_key_bytes: Optional[bytes] = None) -> 'AgentIdentity':
        """Loads agent identity from a Solana keypair file."""
        solana_kp = utils.load_keypair_from_file(filepath)
        enc_priv_key = None
        if encryption_priv_key_bytes:
            enc_priv_key = Curve25519PrivateKey(encryption_priv_key_bytes)
        logger.info(
            f"Loaded agent identity from {filepath}, public key: {solana_kp.pubkey()}")
        return cls(solana_keypair=solana_kp, encryption_priv_key=enc_priv_key)

    def save_to_keypair_file(self, filepath: str, save_encryption_key: bool = False, enc_key_filepath: Optional[str] = None):
        """Saves the agent's Solana keypair to a file.
        Optionally saves the encryption private key to a separate file.
        """
        utils.save_keypair_to_file(self._solana_keypair, filepath)
        if save_encryption_key:
            enc_path = enc_key_filepath or filepath + "_enc.key"
            os.makedirs(os.path.dirname(enc_path), exist_ok=True)
            with open(enc_path, 'wb') as f:
                f.write(bytes(self.encryption_private_key))
            logger.info(f"Encryption private key saved to {enc_path}")

    def sign_data(self, data: bytes) -> bytes:
        """Signs data using the agent's Ed25519 signing key."""
        return utils.sign_message(data, self.signing_key)

    def verify_data_signature(self, data: bytes, signature: bytes, source_verify_key_bytes: bytes) -> bool:
        """Verifies a signature from another agent/source."""
        source_verify_key = utils.get_verify_key_from_bytes(
            source_verify_key_bytes)
        return utils.verify_signature(data, signature, source_verify_key)

    def encrypt_for_recipient(self, data: bytes, recipient_enc_pub_key_bytes: bytes) -> bytes:
        """Encrypts data for a recipient using their Curve25519 public key."""
        recipient_pk = Curve25519PublicKey(recipient_enc_pub_key_bytes)
        return utils.encrypt_message(data, recipient_pk, self.encryption_private_key)

    def decrypt_from_sender(self, encrypted_data: bytes, sender_enc_pub_key_bytes: bytes) -> bytes:
        """Decrypts data from a sender using their Curve25519 public key."""
        sender_pk = Curve25519PublicKey(sender_enc_pub_key_bytes)
        return utils.decrypt_message(encrypted_data, sender_pk, self.encryption_private_key)


def get_default_identity_filepath(agent_name: str = "default_agent") -> str:
    return os.path.join(config.AGENT_KEYS_DIR, f"{agent_name}_solana.json")


def get_default_encryption_key_filepath(agent_name: str = "default_agent") -> str:
    return os.path.join(config.AGENT_KEYS_DIR, f"{agent_name}_encryption.key")


def load_or_generate_identity(agent_name: str = "default_agent") -> AgentIdentity:
    """Loads an agent identity from default file path, or generates a new one if not found."""
    identity_filepath = get_default_identity_filepath(agent_name)
    encryption_key_filepath = get_default_encryption_key_filepath(agent_name)

    enc_priv_key_bytes: Optional[bytes] = None
    if os.path.exists(encryption_key_filepath):
        with open(encryption_key_filepath, 'rb') as f:
            enc_priv_key_bytes = f.read()

    if os.path.exists(identity_filepath):
        logger.info(
            f"Loading identity for '{agent_name}' from {identity_filepath}")
        identity = AgentIdentity.from_keypair_file(
            identity_filepath, enc_priv_key_bytes)
    else:
        logger.info(
            f"No identity found for '{agent_name}' at {identity_filepath}. Generating new identity.")
        identity = AgentIdentity.generate()
        identity.save_to_keypair_file(
            identity_filepath, save_encryption_key=True, enc_key_filepath=encryption_key_filepath)
    return identity
