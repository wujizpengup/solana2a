# example_agent.py
import asyncio
import logging
from typing import Dict, Any, Optional

from sdk import Solana2A_SDK
from a2a_protocol import MessageType, A2AMessage, ServiceDefinition, CapabilitiesResponsePayload, Capability, ServiceResponsePayload

logger = logging.getLogger(__name__)


class ExampleAgent:
    def __init__(self, agent_name: str = "example_agent_alpha"):
        self.sdk = Solana2A_SDK(agent_name=agent_name)
        self.agent_name = agent_name
        self._setup_handlers()
        self.running = False

        # Agent specific capabilities/services
        self.my_services = [
            ServiceDefinition(
                name="echo_service",
                description="An example echo service that repeats what you send.",
                input_schema_uri="TBD_echo_input_schema.json",
                output_schema_uri="TBD_echo_output_schema.json",
                # Or specific invoke type
                endpoint_info={"type": "A2A_MESSAGE",
                               "message_type": "INVOKE_SERVICE"}
            ),
            ServiceDefinition(
                name="ping_service",
                description="A simple ping service to check agent liveness.",
                endpoint_info={"type": "A2A_MESSAGE"}
            )
        ]
        # Placeholder
        self.metadata_uri = f"ipfs://example_metadata_for_{self.agent_name}"

    def _setup_handlers(self):
        self.sdk.register_message_handler(
            MessageType.QUERY_CAPABILITIES, self.handle_query_capabilities)
        self.sdk.register_message_handler(
            MessageType.INVOKE_SERVICE, self.handle_invoke_service)
        # A general handler for other message types for logging/debugging
        # self.sdk.set_default_message_handler(self.handle_default_message)
        logger.info(f"Message handlers set up for {self.agent_name}")

    async def handle_query_capabilities(self, message: A2AMessage, decrypted_payload: Optional[Dict[str, Any]]):
        logger.info(
            f"Received QUERY_CAPABILITIES from {message.header.sender_id}")

        capabilities_payload = CapabilitiesResponsePayload(
            capabilities=[
                Capability(
                    name=s.name,
                    description=s.description or "",
                    input_schema_uri=s.input_schema_uri,
                    output_schema_uri=s.output_schema_uri
                ) for s in self.my_services
            ]
        )

        response_msg = self.sdk.create_message(
            receiver_id_str=message.header.sender_id,
            message_type=MessageType.CAPABILITIES_RESPONSE,
            payload=capabilities_payload.__dict__,
            session_id=message.header.session_id
        )

        # In a real scenario, this response_msg.to_json() would be sent over a transport layer
        logger.info(
            f"Responding with capabilities to {message.header.sender_id}: {response_msg.to_json()[:100]}...")
        # For simulation, we can just print. A real agent would use a transport client here.
        # await self.send_message_via_transport(response_msg.to_json())

    async def handle_invoke_service(self, message: A2AMessage, decrypted_payload: Optional[Dict[str, Any]]):
        logger.info(
            f"Received INVOKE_SERVICE from {message.header.sender_id} with payload: {decrypted_payload}")

        if decrypted_payload is None:
            logger.error(
                "Invoke service called with no (or undecryptable) payload.")
            # Potentially send back an error response
            return

        service_name = decrypted_payload.get("service_name")
        parameters = decrypted_payload.get("parameters", {})
        status = "error"
        result_payload = None
        error_details = "Service not found or internal error."

        if service_name == "echo_service":
            logger.info(f"Executing echo_service with params: {parameters}")
            result_payload = {"echoed_data": parameters.get(
                "data", "Nothing to echo!")}
            status = "success"
            error_details = None
        elif service_name == "ping_service":
            logger.info(f"Executing ping_service")
            result_payload = {"response": "pong"}
            status = "success"
            error_details = None
        else:
            logger.warning(f"Unknown service invoked: {service_name}")
            error_details = f"Service '{service_name}' not implemented by this agent."

        response_payload_data = ServiceResponsePayload(
            request_message_id=message.header.message_id,
            status=status,
            result=result_payload,
            error_details=error_details
        )

        # Determine if encryption is needed based on original message or recipient profile
        # For simplicity, if the incoming message was encrypted (i.e. decrypted_payload was not the raw payload),
        # we might assume the sender expects an encrypted response.
        # This requires knowing the sender's encryption public key.

        # Let's try to find the sender's profile to get their encryption key
        sender_profile = await self.sdk.get_agent_profile(message.header.sender_id)
        response_msg = None

        if sender_profile and sender_profile.encryption_public_key_b64 and decrypted_payload != message.payload:
            # If original message was likely encrypted (decrypted_payload is different from raw message.payload)
            # AND we have sender's encryption key, send encrypted response.
            logger.info(
                f"Sending encrypted response to {message.header.sender_id}")
            response_msg = self.sdk.create_encrypted_message(
                receiver_id_str=message.header.sender_id,
                receiver_enc_pub_key_b64=sender_profile.encryption_public_key_b64,
                message_type=MessageType.SERVICE_RESPONSE,
                actual_payload=response_payload_data.__dict__,
                session_id=message.header.session_id
            )
        else:
            logger.info(
                f"Sending unencrypted response to {message.header.sender_id}")
            response_msg = self.sdk.create_message(
                receiver_id_str=message.header.sender_id,
                message_type=MessageType.SERVICE_RESPONSE,
                payload=response_payload_data.__dict__,
                session_id=message.header.session_id
            )

        logger.info(
            f"Responding to INVOKE_SERVICE: {response_msg.to_json()[:150]}...")
        # await self.send_message_via_transport(response_msg.to_json())

    # async def handle_default_message(self, message: A2AMessage, decrypted_payload: Optional[Dict[str, Any]]):
    #     logger.info(f"Default handler caught message type {message.header.message_type} from {message.header.sender_id}")
    #     logger.debug(f"Message: {message}, Decrypted Payload: {decrypted_payload}")

    async def start(self):
        logger.info(
            f"Starting agent {self.agent_name} ({self.sdk.get_agent_public_key()})...")
        # 1. Register self with the Agent Registry
        reg_success = await self.sdk.register_self(self.metadata_uri, self.my_services)
        if reg_success:
            logger.info(f"Agent {self.agent_name} registered successfully.")
        else:
            logger.error(f"Agent {self.agent_name} registration failed.")
            return  # Don't start if registration fails

        # 2. Start listening for incoming messages (e.g., via a WebSocket, HTTP endpoint, or other transport)
        # This part is highly dependent on the chosen transport mechanism.
        # For this example, we'll simulate an incoming message queue or direct calls.
        self.running = True
        logger.info(
            f"Agent {self.agent_name} is now 'listening' (simulated). Send messages via process_message_json_str.")
        # In a real agent, this would be a loop like:
        # while self.running:
        #     raw_message = await self.transport_client.receive_message()
        #     if raw_message:
        #         await self.sdk.process_incoming_message_json(raw_message)
        #     await asyncio.sleep(0.1)

    async def stop(self):
        self.running = False
        logger.info(f"Agent {self.agent_name} stopping...")
        # Perform any cleanup, e.g., de-register from registry (optional)
        # await self.sdk.registry_client.deregister_agent(self.sdk.get_agent_public_key())
        logger.info(f"Agent {self.agent_name} stopped.")

    # --- Simulation of receiving a message --- #
    async def process_message_json_str(self, message_json_str: str):
        """Simulates receiving a raw JSON message string and processing it."""
        logger.info(
            f"\n--- {self.agent_name} Received Raw Message ---\n{message_json_str}\n-------------------------------------")
        await self.sdk.process_incoming_message_json(message_json_str)


async def main():
    # Configure logging for the example
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.getLogger("example_agent").setLevel(
        logging.DEBUG)  # More verbose for our agent
    logging.getLogger("Solana2A_SDK").setLevel(logging.DEBUG)
    logging.getLogger("agent_registry_client").setLevel(logging.DEBUG)

    agent = ExampleAgent(agent_name="echo_bot_9000")
    await agent.start()

    # --- Simulate an external agent (or SDK test) sending messages to our ExampleAgent --- #
    # For this simulation, we'll use another SDK instance to create messages
    # In reality, these messages would come over a network connection.

    # Create a dummy "client" agent identity to send messages
    client_sdk = Solana2A_SDK(agent_name="test_client_for_echo_bot")
    # Client also registers itself
    await client_sdk.register_self("ipfs://client_meta", [])

    # 1. Client queries capabilities of our echo_bot_9000
    echo_bot_id = agent.sdk.get_agent_public_key()
    query_caps_msg = client_sdk.create_message(
        receiver_id_str=echo_bot_id,
        message_type=MessageType.QUERY_CAPABILITIES,
        payload={}
    )
    await agent.process_message_json_str(query_caps_msg.to_json())
    await asyncio.sleep(0.1)  # Allow handler to process

    # 2. Client invokes the echo_service on echo_bot_9000 (unencrypted first)
    invoke_echo_payload = {"service_name": "echo_service", "parameters": {
        "data": "Hello from unencrypted client!"}}
    invoke_echo_msg = client_sdk.create_message(
        receiver_id_str=echo_bot_id,
        message_type=MessageType.INVOKE_SERVICE,
        payload=invoke_echo_payload
    )
    await agent.process_message_json_str(invoke_echo_msg.to_json())
    await asyncio.sleep(0.1)

    # 3. Client invokes echo_service (encrypted)
    #    The client needs echo_bot_9000's encryption public key.
    #    It should get this from the agent registry.
    echo_bot_profile = await client_sdk.get_agent_profile(echo_bot_id)
    if echo_bot_profile and echo_bot_profile.encryption_public_key_b64:
        encrypted_invoke_payload = {"service_name": "echo_service", "parameters": {
            "data": "Hello from encrypted client!"}}
        encrypted_invoke_msg = client_sdk.create_encrypted_message(
            receiver_id_str=echo_bot_id,
            receiver_enc_pub_key_b64=echo_bot_profile.encryption_public_key_b64,
            message_type=MessageType.INVOKE_SERVICE,
            actual_payload=encrypted_invoke_payload
        )
        await agent.process_message_json_str(encrypted_invoke_msg.to_json())
        await asyncio.sleep(0.1)
    else:
        logger.error(
            f"Could not get encryption key for {echo_bot_id} to send encrypted message.")

    # 4. Client invokes ping_service (unencrypted)
    invoke_ping_payload = {"service_name": "ping_service", "parameters": {}}
    invoke_ping_msg = client_sdk.create_message(
        receiver_id_str=echo_bot_id,
        message_type=MessageType.INVOKE_SERVICE,
        payload=invoke_ping_payload
    )
    await agent.process_message_json_str(invoke_ping_msg.to_json())
    await asyncio.sleep(0.1)

    # Keep the agent running for a bit for manual interaction or further tests if needed
    # try:
    #     while agent.running:
    #         await asyncio.sleep(1)
    # except KeyboardInterrupt:
    #     logger.info("Keyboard interrupt received.")
    # finally:
    #     await agent.stop()

    # For this example, we'll just stop it after the simulated interactions
    await agent.stop()

if __name__ == "__main__":
    asyncio.run(main())
