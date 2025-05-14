# a2a_protocol.py
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum
import time

from solders.pubkey import Pubkey  # type: ignore
import utils


class MessageType(Enum):
    # Discovery & Capability Exchange
    QUERY_CAPABILITIES = "QUERY_CAPABILITIES"
    CAPABILITIES_RESPONSE = "CAPABILITIES_RESPONSE"
    ANNOUNCE_PRESENCE = "ANNOUNCE_PRESENCE"

    # Service Invocation
    INVOKE_SERVICE = "INVOKE_SERVICE"
    SERVICE_RESPONSE = "SERVICE_RESPONSE"
    SERVICE_ERROR = "SERVICE_ERROR"

    # Task Management
    TASK_PROPOSAL = "TASK_PROPOSAL"
    TASK_ACCEPT = "TASK_ACCEPT"
    TASK_REJECT = "TASK_REJECT"
    TASK_STATUS_UPDATE = "TASK_STATUS_UPDATE"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"

    # Generic Data Exchange
    DATA_MESSAGE = "DATA_MESSAGE"

    # Secure Channel Setup (Conceptual - details TBD)
    SECURE_HANDSHAKE_INIT = "SECURE_HANDSHAKE_INIT"
    SECURE_HANDSHAKE_RESPONSE = "SECURE_HANDSHAKE_RESPONSE"

    # ... other message types as needed


@dataclass
class A2AMessageHeader:
    """Header for all A2A messages."""
    message_id: str  # Unique ID for this message
    sender_id: str  # Pubkey of the sender agent
    # Pubkey of the receiver agent (can be a broadcast address or specific agent)
    receiver_id: str
    message_type: MessageType
    timestamp: float = field(default_factory=time.time)
    # For correlating messages in a sequence or conversation
    session_id: Optional[str] = None
    version: str = "1.0"
    signature: Optional[str] = None  # B64 encoded signature of the payload


@dataclass
class A2AMessage:
    """Base structure for an A2A message, including header and payload."""
    header: A2AMessageHeader
    # Content of the message, structure depends on message_type
    payload: Dict[str, Any]
    # The actual payload_hash (as mentioned in tech.md) would be generated from `utils.serialize_data_to_json(payload).encode()`
    # and then signed. The signature is stored in the header.

    def to_json(self) -> str:
        # Custom serialization to handle Enum and Pubkey if they were here directly
        # For now, assuming payload is JSON-serializable and header fields are basic types or handled
        return utils.serialize_data_to_json(self.__dict__)

    @classmethod
    def from_json(cls, json_str: str) -> 'A2AMessage':
        data = utils.deserialize_data_from_json(json_str)
        data['header']['message_type'] = MessageType(
            data['header']['message_type'])
        return cls(header=A2AMessageHeader(**data['header']), payload=data['payload'])

# --- Example Payload Structures (can be expanded significantly) --- #


@dataclass
class QueryCapabilitiesPayload:
    pass  # No specific payload needed, the header's sender_id is who is querying


@dataclass
class Capability:
    name: str
    description: str
    input_schema_uri: Optional[str] = None
    output_schema_uri: Optional[str] = None
    # Further details like version, cost, etc.


@dataclass
class CapabilitiesResponsePayload:
    capabilities: List[Capability]


@dataclass
class InvokeServicePayload:
    service_name: str
    parameters: Dict[str, Any]
    # May include execution preferences like timeout, priority


@dataclass
class ServiceResponsePayload:
    request_message_id: str  # ID of the InvokeService message this is responding to
    status: str  # e.g., "success", "error"
    result: Optional[Dict[str, Any]] = None
    error_details: Optional[str] = None


@dataclass
class TaskProposalPayload:
    task_id: str
    task_description: str
    # Link to a more detailed workflow definition
    workflow_uri: Optional[str] = None
    input_params: Dict[str, Any]
    # Could include proposed reward, deadlines etc.

# --- Service Definition (as per tech.md) --- #
# This is more for registration than direct messaging, but related.


@dataclass
class ServiceDefinition:
    name: str
    description: Optional[str] = None
    # Link to schema for service inputs (e.g., JSON schema)
    input_schema_uri: Optional[str] = None
    # Link to schema for service outputs
    output_schema_uri: Optional[str] = None
    # How to call: e.g., {"type": "A2A_MESSAGE", "invoke_message_type": "INVOKE_MY_SERVICE"}
    endpoint_info: Dict[str, Any]
    # or {"type": "HTTP_POST", "url": "..."}
    version: str = "1.0"

# Note: The A2AMessage conceptual structure from tech.md (with payload_hash)
# is implemented by how A2AMessage is signed: the `payload` dict is serialized,
# hashed, then signed, and the signature stored in `A2AMessageHeader.signature`.
# The `sender_id`, `receiver_id` are Pubkey strings.
# `session_id` maps to `session_id`.
# `message_type` maps to `message_type`.
# `timestamp` maps to `timestamp`.
