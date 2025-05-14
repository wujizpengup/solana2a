# secure_messaging.py
import logging
import uuid
from typing import Tuple, Optional, Dict, Any

from agent_identity import AgentIdentity
from a2a_protocol import A2AMessage, A2AMessageHeader, MessageType
import utils

logger = logging.getLogger(__name__)


class SecureMessenger:
    """Handles creation and processing of secure A2A messages."""

    def __init__(self, agent_identity: AgentIdentity):
        self.identity = agent_identity

    def create_message(
        self,
        receiver_id_str: str,
        message_type: MessageType,
        payload: Dict[str, Any],
        session_id: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> A2AMessage:
        """Creates a new A2AMessage, serializes and signs the payload."""
        if message_id is None:
            message_id = str(uuid.uuid4())

        header = A2AMessageHeader(
            message_id=message_id,
            sender_id=self.identity.public_key_str,
            receiver_id=receiver_id_str,
            message_type=message_type,
            session_id=session_id,
        )

        # Serialize payload for signing
        serialized_payload = utils.serialize_data_to_json(
            payload).encode('utf-8')

        # Sign the serialized payload
        signature_bytes = self.identity.sign_data(serialized_payload)
        header.signature = utils.b64encode_bytes(signature_bytes)

        message = A2AMessage(header=header, payload=payload)
        logger.debug(
            f"Created message: {message_id} of type {message_type} to {receiver_id_str}")
        return message

    def verify_message(self, message: A2AMessage, sender_public_key_bytes: Optional[bytes] = None) -> bool:
        """Verifies the signature of an incoming A2AMessage.
        If sender_public_key_bytes is provided, it's used directly.
        Otherwise, message.header.sender_id is converted to Pubkey then to bytes.
        """
        if not message.header.signature:
            logger.warning(
                f"Message {message.header.message_id} has no signature.")
            return False

        try:
            signature_bytes = utils.b64decode_bytes(message.header.signature)
            serialized_payload = utils.serialize_data_to_json(
                message.payload).encode('utf-8')

            if sender_public_key_bytes:
                verify_key = utils.get_verify_key_from_bytes(
                    sender_public_key_bytes)
            else:
                sender_pubkey = utils.str_to_pubkey(message.header.sender_id)
                verify_key = utils.get_verify_key_from_bytes(
                    bytes(sender_pubkey))

            is_valid = utils.verify_signature(
                serialized_payload, signature_bytes, verify_key)
            if not is_valid:
                logger.warning(
                    f"Invalid signature for message {message.header.message_id}")
            return is_valid
        except Exception as e:
            logger.error(
                f"Error verifying message {message.header.message_id}: {e}")
            return False

    def encrypt_payload(self, payload: Dict[str, Any], recipient_enc_pub_key_b64: str) -> str:
        """Serializes, encrypts, and base64 encodes a payload for a recipient."""
        serialized_payload = utils.serialize_data_to_json(
            payload).encode('utf-8')
        recipient_enc_pub_key_bytes = utils.b64decode_bytes(
            recipient_enc_pub_key_b64)
        encrypted_payload_bytes = self.identity.encrypt_for_recipient(
            serialized_payload,
            recipient_enc_pub_key_bytes
        )
        return utils.b64encode_bytes(encrypted_payload_bytes)

    def decrypt_payload(self, encrypted_payload_b64: str, sender_enc_pub_key_b64: str) -> Dict[str, Any]:
        """Base64 decodes, decrypts, and deserializes an encrypted payload from a sender."""
        encrypted_payload_bytes = utils.b64decode_bytes(encrypted_payload_b64)
        sender_enc_pub_key_bytes = utils.b64decode_bytes(
            sender_enc_pub_key_b64)
        decrypted_payload_bytes = self.identity.decrypt_from_sender(
            encrypted_payload_bytes,
            sender_enc_pub_key_bytes
        )
        return utils.deserialize_data_from_json(decrypted_payload_bytes.decode('utf-8'))

    def create_signed_and_encrypted_message(
        self,
        receiver_id_str: str,
        receiver_enc_pub_key_b64: str,  # Receiver's Curve25519 public key for encryption
        message_type: MessageType,
        actual_payload: Dict[str, Any],
        session_id: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> A2AMessage:
        """Creates a message where the payload is encrypted and the whole message is signed."""

        # 1. Encrypt the actual_payload
        encrypted_b64_payload_content = self.encrypt_payload(
            actual_payload, receiver_enc_pub_key_b64)

        # 2. The A2AMessage.payload will now carry this encrypted string and info needed for decryption
        # The receiver will need to know our (sender's) encryption public key to decrypt.
        wrapper_payload = {
            "encrypted_content": encrypted_b64_payload_content,
            "sender_enc_pub_key_b64": self.identity.encryption_public_key_b64,
            # Potentially other metadata about encryption if needed
        }

        # 3. Create the message with this wrapper_payload (this will sign the wrapper_payload)
        message = self.create_message(
            receiver_id_str=receiver_id_str,
            message_type=message_type,
            # The payload to be signed is the one containing encrypted data
            payload=wrapper_payload,
            session_id=session_id,
            message_id=message_id
        )
        return message

    def decrypt_and_verify_message(
        self,
        message: A2AMessage,
        # Optional: verify against a specific sender Solana Pubkey
        expected_sender_id_str: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Verifies the message signature and then decrypts its payload.
        Returns the decrypted actual_payload if successful, otherwise None.
        """
        # 1. Verify the outer message signature
        sender_pubkey_bytes = None
        if expected_sender_id_str:
            sender_pubkey_bytes = bytes(
                utils.str_to_pubkey(expected_sender_id_str))

        if not self.verify_message(message, sender_public_key_bytes=sender_pubkey_bytes):
            logger.warning(
                f"Signature verification failed for message {message.header.message_id}")
            return None

        # 2. Check if the payload seems to be an encrypted one
        if not (
            isinstance(message.payload, dict)
            and "encrypted_content" in message.payload
            and "sender_enc_pub_key_b64" in message.payload
        ):
            logger.warning(
                f"Message {message.header.message_id} payload is not in expected encrypted format. Returning as is.")
            # If it's not encrypted, but signature is valid, return the payload as is.
            # Or, you might want to raise an error if encryption was expected.
            return message.payload

        # 3. Decrypt the content
        try:
            encrypted_content_b64 = message.payload["encrypted_content"]
            sender_enc_pub_key_b64 = message.payload["sender_enc_pub_key_b64"]

            decrypted_actual_payload = self.decrypt_payload(
                encrypted_content_b64, sender_enc_pub_key_b64)
            logger.debug(
                f"Successfully decrypted payload for message {message.header.message_id}")
            return decrypted_actual_payload
        except Exception as e:
            logger.error(
                f"Failed to decrypt payload for message {message.header.message_id}: {e}")
            return None
