# sdk.py
import logging
from typing import Optional, Dict, Any, List, Callable, Awaitable

from solana.rpc.api import Client
from solders.keypair import Keypair  # type: ignore
from solders.pubkey import Pubkey  # type: ignore

import config
import utils
from agent_identity import AgentIdentity, load_or_generate_identity
from a2a_protocol import A2AMessage, MessageType, ServiceDefinition
from secure_messaging import SecureMessenger
from agent_registry_client import AgentRegistryClient, AgentProfile
from task_engine_client import TaskEngineClient, TaskState, TaskStatus

# Type alias for message handlers
MessageHandler = Callable[[A2AMessage,
                           Optional[Dict[str, Any]]], Awaitable[None]]
# The second arg for MessageHandler is the decrypted payload if applicable

logger = logging.getLogger(__name__)


class Solana2A_SDK:
    """Main SDK class for interacting with the Solana2A ecosystem."""

    def __init__(self, agent_name: str = "default_agent", solana_rpc_url: Optional[str] = None):
        utils.setup_logging()  # Ensure logging is configured
        self.agent_name = agent_name
        self.identity = load_or_generate_identity(agent_name)

        rpc_url = solana_rpc_url or config.SOLANA_RPC_URL
        self.solana_client = Client(rpc_url)

        self.messenger = SecureMessenger(self.identity)
        self.registry_client = AgentRegistryClient(
            self.solana_client, self.identity)
        self.task_client = TaskEngineClient(self.solana_client, self.identity)

        self._message_handlers: Dict[MessageType, MessageHandler] = {}
        self._default_message_handler: Optional[MessageHandler] = None

        logger.info(
            f"Solana2A SDK initialized for agent: {self.identity.public_key_str}")
        logger.info(
            f"Agent encryption public key (b64): {self.identity.encryption_public_key_b64}")

    # --- Identity and Keys --- #
    def get_agent_public_key(self) -> str:
        return self.identity.public_key_str

    def get_agent_encryption_public_key_b64(self) -> str:
        return self.identity.encryption_public_key_b64

    # --- Agent Registry --- #
    async def register_self(self, metadata_uri: str, services: List[ServiceDefinition]) -> bool:
        profile = AgentProfile(
            agent_id_str=self.identity.public_key_str,
            owner_id_str=self.identity.public_key_str,  # Self-owned
            metadata_uri=metadata_uri,
            services=services,
            encryption_public_key_b64=self.identity.encryption_public_key_b64
        )
        return await self.registry_client.register_agent(profile)

    async def get_agent_profile(self, agent_id_str: str) -> Optional[AgentProfile]:
        return await self.registry_client.get_agent_profile(agent_id_str)

    async def find_agents_by_service(self, service_name: str) -> List[AgentProfile]:
        return await self.registry_client.find_agents_by_service(service_name)

    # --- Messaging --- #
    def create_message(
        self,
        receiver_id_str: str,
        message_type: MessageType,
        payload: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> A2AMessage:
        return self.messenger.create_message(receiver_id_str, message_type, payload, session_id)

    def create_encrypted_message(
        self,
        receiver_id_str: str,
        receiver_enc_pub_key_b64: str,
        message_type: MessageType,
        actual_payload: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> A2AMessage:
        return self.messenger.create_signed_and_encrypted_message(
            receiver_id_str,
            receiver_enc_pub_key_b64,
            message_type,
            actual_payload,
            session_id
        )

    def verify_and_decrypt_message(self, message_json: str) -> Tuple[Optional[A2AMessage], Optional[Dict[str, Any]]]:
        """Verifies signature and decrypts payload if necessary.
        Returns the A2AMessage object and the (potentially decrypted) application-level payload.
        """
        try:
            a2a_message = A2AMessage.from_json(message_json)
        except Exception as e:
            logger.error(f"Failed to parse message JSON: {e}")
            return None, None

        decrypted_payload = self.messenger.decrypt_and_verify_message(
            a2a_message)
        if decrypted_payload is None:  # Signature verification failed or decryption failed
            logger.warning(
                f"Message verification/decryption failed for {a2a_message.header.message_id}")
            # Return the raw message but no payload if failed.
            return a2a_message, None

        return a2a_message, decrypted_payload

    # --- Message Handling/Dispatch (for an agent acting as a server/listener) --- #
    def register_message_handler(self, message_type: MessageType, handler: MessageHandler):
        """Register a handler for a specific message type."""
        self._message_handlers[message_type] = handler
        logger.info(
            f"Registered handler for message type: {message_type.value}")

    def set_default_message_handler(self, handler: MessageHandler):
        """Register a default handler for unhandled message types."""
        self._default_message_handler = handler
        logger.info("Registered default message handler.")

    async def process_incoming_message_json(self, message_json: str):
        """Processes an incoming JSON message string, verifies, decrypts, and dispatches to handler."""
        a2a_message, app_payload = self.verify_and_decrypt_message(
            message_json)

        if not a2a_message:  # Parsing failed
            return

        if app_payload is None:  # Verification or decryption failed
            logger.warning(
                f"Skipping dispatch for message {a2a_message.header.message_id} due to verification/decryption failure.")
            return

        handler = self._message_handlers.get(a2a_message.header.message_type)
        if handler:
            await handler(a2a_message, app_payload)
        elif self._default_message_handler:
            await self._default_message_handler(a2a_message, app_payload)
        else:
            logger.warning(
                f"No handler for message type {a2a_message.header.message_type.value} from {a2a_message.header.sender_id}")

    # --- Task Engine --- #
    async def propose_task(self, workflow_uri: Optional[str], input_params: Dict[str, Any]) -> Optional[str]:
        return await self.task_client.propose_task(self.identity.public_key_str, workflow_uri, input_params)

    async def get_task_state(self, task_id: str) -> Optional[TaskState]:
        return await self.task_client.get_task_state(task_id)

    async def update_task_status(
        self, task_id: str, new_status: TaskStatus,
        current_step: Optional[int] = None,
        results_hash: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> bool:
        return await self.task_client.update_task_status(task_id, new_status, current_step, results_hash, error_message)

    # --- Lower level Solana client access (if needed) --- #
    def get_solana_client(self) -> Client:
        return self.solana_client

    def get_agent_keypair(self) -> Keypair:
        return self.identity.solana_keypair

    # Other SDK methods would go here, e.g., for interacting with specific on-chain A2A protocol features
    # like direct message sending/receiving if not using an external transport, oracle interactions etc.


# Example usage (conceptual)
async def sdk_example_usage():
    sdk = Solana2A_SDK(agent_name="my_example_agent")
    print(f"SDK Initialized for Agent: {sdk.get_agent_public_key()}")
    print(
        f"Agent Encryption PubKey: {sdk.get_agent_encryption_public_key_b64()}")

    # Example: Registering the agent
    # Define services
    echo_service = ServiceDefinition(
        name="echo", description="Echoes back the payload", endpoint_info={"type": "A2A"})
    math_service = ServiceDefinition(
        name="add", description="Adds two numbers", endpoint_info={"type": "A2A"})

    # Register agent with its services
    # Note: metadata_uri would point to a JSON file with agent's name, description, logo etc.
    # Example: {"name": "MyExampleAgent", "description": "An agent that can echo and add.", "logoUrl": "ipfs://..."}
    # This URI should be resolvable by other agents.
    registration_success = await sdk.register_self(
        metadata_uri="ipfs://QmExampleMetadataHash",
        services=[echo_service, math_service]
    )
    print(f"Agent registration successful: {registration_success}")

    # Example: Find other agents
    found_echo_agents = await sdk.find_agents_by_service("echo")
    if found_echo_agents:
        print(f"Found {len(found_echo_agents)} agents offering 'echo' service:")
        for agent_profile in found_echo_agents:
            print(
                f"  - Agent ID: {agent_profile.agent_id_str}, Encryption Key: {agent_profile.encryption_public_key_b64}")
            # Store this encryption key to send encrypted messages to this agent
    else:
        print("No agents found offering 'echo' service.")

    # Assume we found an agent to talk to
    if found_echo_agents:
        target_agent_profile = found_echo_agents[0]
        target_agent_id = target_agent_profile.agent_id_str
        target_agent_enc_key_b64 = target_agent_profile.encryption_public_key_b64

        if target_agent_enc_key_b64:
            # Example: Sending an encrypted message
            encrypted_msg_to_send = sdk.create_encrypted_message(
                receiver_id_str=target_agent_id,
                receiver_enc_pub_key_b64=target_agent_enc_key_b64,
                message_type=MessageType.INVOKE_SERVICE,
                actual_payload={"service_name": "echo", "parameters": {
                    "data": "Hello Solana2A from SDK!"}}
            )
            message_json_to_send = encrypted_msg_to_send.to_json()
            print(
                f"\nSending encrypted message JSON: {message_json_to_send[:200]}...")
            # In a real app, this JSON would be sent over a transport (e.g., HTTP, WebSocket, gossip network)

            # --- Simulating receiving this message by the target agent ---
            # Target agent would do something like this:
            # (sdk_target = Solana2A_SDK(agent_name=target_agent_profile.agent_id_str) # if it's another instance)
            # received_message, received_payload = sdk_target.verify_and_decrypt_message(message_json_to_send)

            # For this example, let's process it with the same SDK instance to show decryption
            # This implies the sender is also the receiver, which is not typical for encryption test
            # but demonstrates the decryption part of the SecureMessenger via SDK.
            # A better test would be to have two SDK instances.

            # To properly test encryption/decryption, the receiver (target_agent) must use *its* private key.
            # Our current `sdk.messenger` uses `sdk.identity` which is `my_example_agent`.
            # If target_agent_id is different, this won't decrypt unless it's a message to self.

            # Let's assume the message was sent to self for this local test of decryption logic:
            if target_agent_id == sdk.get_agent_public_key() and target_agent_enc_key_b64 == sdk.get_agent_encryption_public_key_b64():
                processed_msg, payload_app_level = sdk.verify_and_decrypt_message(
                    message_json_to_send)
                if processed_msg and payload_app_level:
                    print(f"Successfully processed self-sent encrypted message!")
                    print(
                        f"  Original Message ID: {processed_msg.header.message_id}")
                    print(f"  Sender: {processed_msg.header.sender_id}")
                    print(f"  Decrypted Payload: {payload_app_level}")
                    assert payload_app_level["service_name"] == "echo"
                else:
                    print("Failed to process self-sent encrypted message.")
            else:
                print(
                    f"Skipping decryption test as target agent ({target_agent_id}) is not self ({sdk.get_agent_public_key()}).")
        else:
            print(
                f"Target agent {target_agent_id} does not have an encryption public key listed.")

    # Example: Proposing a task
    task_input_params = {"url": "http://some.api/data",
                         "processing_steps": ["fetch", "analyze"]}
    task_id = await sdk.propose_task(workflow_uri="ipfs://QmWorkflowHash", input_params=task_input_params)
    if task_id:
        print(f"\nTask proposed with ID: {task_id}")
        # Later, check status
        await asyncio.sleep(0.1)  # mock processing time
        task_state = await sdk.get_task_state(task_id)
        if task_state:
            print(f"Task {task_id} current status: {task_state.status.value}")
            # An agent responsible for the task would update its status
            update_success = await sdk.update_task_status(task_id, TaskStatus.COMPLETED, results_hash="QmResultsHash")
            print(f"Task update successful: {update_success}")
            final_state = await sdk.get_task_state(task_id)
            if final_state:
                print(
                    f"Task {task_id} final status: {final_state.status.value}, Results: {final_state.results_hash}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(sdk_example_usage())
