# config.py

# Solana network configuration
# Default to devnet, can be changed to mainnet-beta or a local validator
SOLANA_RPC_URL = "https://api.devnet.solana.com"
SOLANA_WS_URL = "wss://api.devnet.solana.com"

# Agent Registry Program ID (Placeholder - to be replaced with actual deployed program ID)
AGENT_REGISTRY_PROGRAM_ID = "REGISTRY_PROGRAM_ID_PLACEHOLDER"

# A2A Protocol Program ID (Placeholder)
A2A_PROTOCOL_PROGRAM_ID = "A2A_PROTOCOL_PROGRAM_ID_PLACEHOLDER"

# Task Engine Program ID (Placeholder)
TASK_ENGINE_PROGRAM_ID = "TASK_ENGINE_PROGRAM_ID_PLACEHOLDER"

# Default directory for agent keys
AGENT_KEYS_DIR = ".agent_keys"

# Logging configuration (basic)
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
