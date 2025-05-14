# agent_registry_client.py
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict

from solders.pubkey import Pubkey  # type: ignore
from solders.keypair import Keypair  # type: ignore
from solana.rpc.api import Client
from solana.transaction import Transaction, TransactionInstruction
# from anchorpy import Program, Provider, Wallet #  If using Anchor

import config
import utils
from a2a_protocol import ServiceDefinition
from agent_identity import AgentIdentity

logger = logging.getLogger(__name__)

# Mocking on-chain data structure, as per tech.md AgentProfile


@dataclass
class AgentProfile:
    agent_id_str: str  # Solana Pubkey string
    owner_id_str: str  # Solana Pubkey string of the agent's owner/controller
    metadata_uri: str  # Link to off-chain JSON metadata (name, desc, logo)
    services: List[ServiceDefinition]
    # Agent's Curve25519 public key for encryption
    encryption_public_key_b64: Optional[str] = None
    # Additional fields like reputation, last_seen, etc. can be added


# In-memory mock registry for now
_MOCK_REGISTRY: Dict[str, AgentProfile] = {}


class AgentRegistryClient:
    """Client for interacting with the Agent Registry.
    Currently uses a mock in-memory registry.
    """

    def __init__(self, solana_client: Optional[Client] = None, identity: Optional[AgentIdentity] = None):
        self.solana_client = solana_client if solana_client else Client(
            config.SOLANA_RPC_URL)
        self.identity = identity  # Current agent's identity, needed for on-chain registration
        # self.program = None # Initialize Anchor program here if/when available
        logger.info("AgentRegistryClient initialized (using MOCK registry).")

    def _get_program(self):
        # Placeholder for Anchor program initialization
        # provider = Provider(self.solana_client, Wallet(self.identity.solana_keypair))
        # self.program = Program.at(config.AGENT_REGISTRY_PROGRAM_ID, provider)
        # return self.program
        raise NotImplementedError(
            "On-chain program interaction is not yet implemented.")

    async def register_agent(self, profile: AgentProfile) -> bool:
        """Registers or updates an agent's profile in the registry."""
        if not self.identity:
            logger.error("Agent identity not set. Cannot register agent.")
            return False

        # Ensure the agent registering is the owner specified in the profile or the agent itself
        if not (self.identity.public_key_str == profile.agent_id_str or self.identity.public_key_str == profile.owner_id_str):
            logger.error(
                f"Identity mismatch: Current agent {self.identity.public_key_str} cannot register/update profile for {profile.agent_id_str} owned by {profile.owner_id_str}")
            return False

        # Mock implementation
        _MOCK_REGISTRY[profile.agent_id_str] = profile
        logger.info(
            f"Agent {profile.agent_id_str} registered/updated in MOCK registry.")
        # logger.debug(f"Profile data: {asdict(profile)}")
        return True

        # TODO: Replace with actual on-chain interaction
        # program = self._get_program()
        # try:
        #     await program.rpc["register_agent"](
        #         profile.metadata_uri,
        #         [asdict(s) for s in profile.services],
        #         profile.encryption_public_key_b64,
        #         # accounts={...}, signers=[self.identity.solana_keypair]
        #     )
        #     logger.info(f"Agent {profile.agent_id_str} registered on-chain.")
        #     return True
        # except Exception as e:
        #     logger.error(f"Failed to register agent {profile.agent_id_str} on-chain: {e}")
        #     return False

    async def get_agent_profile(self, agent_id_str: str) -> Optional[AgentProfile]:
        """Retrieves an agent's profile from the registry."""
        # Mock implementation
        profile_data = _MOCK_REGISTRY.get(agent_id_str)
        if profile_data:
            logger.debug(
                f"Retrieved profile for {agent_id_str} from MOCK registry.")
            return profile_data
        logger.warning(f"Agent {agent_id_str} not found in MOCK registry.")
        return None

        # TODO: Replace with actual on-chain interaction
        # program = self._get_program()
        # try:
        #     account_data = await program.account["AgentProfileAccount"].fetch(utils.str_to_pubkey(agent_id_str))
        #     # Deserialize account_data into AgentProfile object
        #     # ... this depends on the on-chain account structure
        #     return AgentProfile(...)
        # except Exception as e:
        #     logger.error(f"Failed to fetch agent profile {agent_id_str} from on-chain: {e}")
        #     return None

    async def find_agents_by_service(self, service_name: str) -> List[AgentProfile]:
        """Finds agents that offer a specific service."""
        found_agents: List[AgentProfile] = []
        # Mock implementation
        for agent_id, profile in _MOCK_REGISTRY.items():
            for service in profile.services:
                if service.name == service_name:
                    found_agents.append(profile)
                    break
        logger.info(
            f"Found {len(found_agents)} agents offering service '{service_name}' in MOCK registry.")
        return found_agents

        # TODO: Replace with actual on-chain interaction (likely involving custom RPC or off-chain indexer)
        # This kind of query can be complex on-chain without specific indexing accounts.
        # An off-chain indexer that listens to registration events might be more practical.

    async def list_all_agents(self) -> List[AgentProfile]:
        """Lists all registered agents (potentially with pagination in a real scenario)."""
        # Mock implementation
        all_profiles = list(_MOCK_REGISTRY.values())
        logger.info(
            f"Retrieved {len(all_profiles)} agent profiles from MOCK registry.")
        return all_profiles

        # TODO: On-chain might require fetching multiple accounts or a specific master list account.

    async def deregister_agent(self, agent_id_str: str) -> bool:
        """Deregisters an agent. Requires owner's signature."""
        if not self.identity:
            logger.error("Agent identity not set. Cannot deregister agent.")
            return False

        # Mock implementation
        profile = _MOCK_REGISTRY.get(agent_id_str)
        if profile:
            if not (self.identity.public_key_str == profile.agent_id_str or self.identity.public_key_str == profile.owner_id_str):
                logger.error(
                    f"Identity mismatch: Current agent {self.identity.public_key_str} cannot deregister agent {profile.agent_id_str}")
                return False
            del _MOCK_REGISTRY[agent_id_str]
            logger.info(
                f"Agent {agent_id_str} deregistered from MOCK registry.")
            return True
        logger.warning(
            f"Agent {agent_id_str} not found in MOCK registry for deregistration.")
        return False

        # TODO: Replace with actual on-chain interaction
        # program = self._get_program()
        # try:
        #     await program.rpc["deregister_agent"](
        #         # accounts={...}, signers=[self.identity.solana_keypair]
        #     )
        #     logger.info(f"Agent {agent_id_str} deregistered on-chain.")
        #     return True
        # except Exception as e:
        #     logger.error(f"Failed to deregister agent {agent_id_str} on-chain: {e}")
        #     return False

# Example usage (if run directly, for testing)


async def main_registry_test():
    import asyncio
    utils.setup_logging()
    logging.getLogger().setLevel(logging.DEBUG)  # Show debug for this test

    # Create a dummy identity for the client
    client_identity = AgentIdentity.generate()
    registry_client = AgentRegistryClient(identity=client_identity)

    # Create a sample agent profile
    agent1_identity = AgentIdentity.generate()
    service1 = ServiceDefinition(name="echo_service", description="Echoes input",
                                 input_schema_uri="N/A", output_schema_uri="N/A", endpoint_info={"type": "A2A_MESSAGE"})
    agent1_profile = AgentProfile(
        agent_id_str=agent1_identity.public_key_str,
        owner_id_str=agent1_identity.public_key_str,  # Self-owned
        metadata_uri="ipfs://some_metadata_hash_for_agent1",
        services=[service1],
        encryption_public_key_b64=agent1_identity.encryption_public_key_b64
    )

    # Register agent1 (using its own identity to register itself)
    agent1_registry_client = AgentRegistryClient(identity=agent1_identity)
    success = await agent1_registry_client.register_agent(agent1_profile)
    print(f"Agent 1 registration successful: {success}")

    # Retrieve agent1's profile using the general client
    retrieved_profile = await registry_client.get_agent_profile(agent1_identity.public_key_str)
    if retrieved_profile:
        print(
            f"Retrieved Agent 1 Profile: {retrieved_profile.agent_id_str}, Services: {len(retrieved_profile.services)}")
        assert retrieved_profile.services[0].name == "echo_service"

    # Find agents offering "echo_service"
    echo_agents = await registry_client.find_agents_by_service("echo_service")
    print(f"Agents offering 'echo_service': {len(echo_agents)}")
    assert len(echo_agents) == 1

    all_agents = await registry_client.list_all_agents()
    print(f"Total agents in mock registry: {len(all_agents)}")

    # Deregister agent1 (using its own identity)
    success_deregister = await agent1_registry_client.deregister_agent(agent1_identity.public_key_str)
    print(f"Agent 1 deregistration successful: {success_deregister}")
    assert success_deregister

    retrieved_profile_after_deregister = await registry_client.get_agent_profile(agent1_identity.public_key_str)
    assert retrieved_profile_after_deregister is None
    print("Agent 1 profile not found after deregistration, as expected.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main_registry_test())
