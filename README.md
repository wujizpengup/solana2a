# Solana2A: Agent-to-Agent Communication Protocol on Solana

![Solana2A Banner](https://user-images.githubusercontent.com/11396544/203911315-12a5136a-0b3a-4b8c-8d80-3072e2f1f7f5.png) <!-- Replace with an actual banner if you have one -->

**Solana2A is building the future of Agent-to-Agent (A2A) protocols in the crypto space. Built on the high-performance Solana blockchain, we aim to provide a standardized, secure, and efficient communication and collaboration framework for on-chain intelligent agents.**

Traditional on-chain agents often operate in isolation, making effective collaboration and information exchange difficult. Solana2A addresses this by offering an open protocol suite that enables agents with diverse functionalities, developed by different entities, to discover each other, understand capabilities, and execute complex collaborative tasks. This is more than simple message passing; it's about trusted interactions based on smart contracts and decentralized identities, unlocking new possibilities for intelligent and automated decentralized applications (dApps).

We are committed to fostering a powerful ecosystem for developers, empowering them to build highly interoperable and autonomous agents.

## Table of Contents

- [Solana2A: Agent-to-Agent Communication Protocol on Solana](#solana2a-agent-to-agent-communication-protocol-on-solana)
  - [Table of Contents](#table-of-contents)
  - [Features \& Benefits](#features--benefits)
  - [System Architecture](#system-architecture)
  - [Technology Stack](#technology-stack)
  - [Project Structure](#project-structure)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
  - [Usage](#usage)
    - [Running the Example Agent](#running-the-example-agent)
    - [Using the SDK](#using-the-sdk)
  - [Future Work](#future-work)
  - [Contributing](#contributing)
  - [License](#license)

## Features & Benefits

Solana2A offers a rich set of features designed to simplify collaboration between on-chain agents:

*   **Standardized A2A Protocol:** Provides a clearly defined set of protocols and message formats ensuring compatibility between different agents.
*   **High Performance (Solana-based):** Leverages Solana's high throughput and low latency for rapid and reliable inter-agent communication.
*   **Atomic Transaction Support:** Enables agents to perform complex, indivisible multi-step operations.
*   **On-chain Identity and Authentication:** Assigns unique on-chain identities to agents, with decentralized authentication and authorization.
*   **Agent Registry & Discovery:** Features an agent registry for mutual discovery and connection.
*   **Secure Messaging:** Utilizes cryptographic techniques to ensure privacy and security in agent communications.
*   **Task Automation System:**
    *   Securely call external resources to fetch web data.
    *   Analyze smart contract code for vulnerabilities or optimizations.
    *   Coordinate multiple on-chain and off-chain tools (data platforms, ML models, APIs) for complex tasks.
*   **Rich SDKs and Tools:** Offers SDKs in multiple languages (Python first) and development tools to lower the barrier to entry.
*   **Modular Design:** Allows developers to select and extend functionalities as needed.
*   **Empowering Crypto Operations:**
    *   Automated trade execution on DEXs.
    *   Intelligent on-chain fund management (staking, lending, yield farming).
    *   Automated risk management for investment portfolios.
    *   Data collection and analysis for investment insights and academic research.

For a more detailed technical breakdown, please refer to the [Technical Architecture Document (tech.md)](tech.md).

## System Architecture

The Solana2A system is designed with a layered architecture:

1.  **Solana Blockchain Layer:** The foundation providing the distributed ledger, smart contract environment, and native token features.
2.  **A2A Protocol Layer:** Solana smart contracts defining rules, message formats, and interaction patterns.
3.  **Agent Services Layer:** Core on-chain services like Agent Registry, Identity Management, and Task Orchestration.
4.  **Agent Application & Tooling Layer:** Off-chain agents, SDKs, developer tools, and external services.

Key components include:
*   A2A Protocol Suite (Smart Contracts)
*   Agent Registry & Discovery Service
*   Agent Identity & Authentication Module
*   Secure Messaging Service
*   Task Execution Engine
*   Oracle Service Integration
*   SDKs & Developer Tools

Refer to [tech.md](tech.md) for a detailed architectural overview and component descriptions.

## Technology Stack

*   **Blockchain Platform:** Solana
*   **Smart Contract Language:** Rust (Anchor framework recommended)
*   **Agent Identity:** Solana Keypairs (exploring DIDs/VCs for the future)
*   **Messaging Security:** PyNaCl (libsodium bindings) for Ed25519 signatures and Curve25519 encryption.
*   **Off-chain Components/SDK:**
    *   **Primary:** Python (FastAPI/Flask for web, rich AI/ML ecosystem)
    *   **Future:** Rust, JavaScript/TypeScript
*   **Databases (for off-chain agent state):** PostgreSQL, SQLite, MongoDB (agent-specific)
*   **Containerization:** Docker

## Project Structure

The project currently follows a relatively flat structure for the Python SDK and example components:

```
.solana2a/
├── .venv/                      # Virtual environment
├── .gitignore
├── .python-version
├── a2a_protocol.py             # Defines A2A message structures and types.
├── agent_identity.py           # Manages agent cryptographic identities.
├── agent_registry_client.py    # Client for the (mock) Agent Registry.
├── config.py                   # Project configuration settings.
├── example_agent.py            # An example agent demonstrating SDK usage.
├── LICENSE                     # Project License (Apache 2.0 or MIT typical)
├── main.py                     # (Currently a placeholder, example_agent.py is runnable)
├── proj.md                     # Project vision and functional description (Chinese).
├── pyproject.toml              # Python project metadata (PEP 517/518).
├── README.md                   # This file.
├── requirements.txt            # Python dependencies.
├── sdk.py                      # Main SDK class for developers.
├── secure_messaging.py         # Handles message signing, encryption, etc.
├── task_engine_client.py       # Client for the (mock) Task Engine.
├── tech.md                     # Detailed technical architecture document.
└── utils.py                    # Common utilities (crypto, serialization).
```

## Getting Started

### Prerequisites

*   Python 3.10+ (recommend using `pyenv` to manage Python versions)
*   Pip (Python package installer)
*   Virtual environment tool (e.g., `venv`)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/solana2a.git # Replace with your repo URL
    cd solana2a
    ```

2.  **Set up a Python virtual environment:**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running the Example Agent

The `example_agent.py` script demonstrates core functionalities like agent registration, service definition, and message handling (including encrypted messages). It simulates an "echo bot" agent and a "client" agent interacting with it.

To run the example:

```bash
python example_agent.py
```

You should see log output detailing the agent's startup, registration, and the simulated message exchanges between the example agent and a test client SDK instance.

Key files to inspect for understanding the example:
*   `example_agent.py`: The main agent logic.
*   `sdk.py`: The SDK used by the agent.
*   `agent_registry_client.py`: Shows mock registration and discovery.
*   `secure_messaging.py`: Handles the encryption/decryption demonstrated.

### Using the SDK

The `Solana2A_SDK` class in `sdk.py` is the primary entry point for developers building agents.

**Initialization:**
```python
from sdk import Solana2A_SDK

sdk = Solana2A_SDK(agent_name="my_cool_agent")
print(f"Agent Public Key: {sdk.get_agent_public_key()}")
print(f"Agent Encryption Public Key (Base64): {sdk.get_agent_encryption_public_key_b64()}")
```

**Registering an Agent:**
```python
from a2a_protocol import ServiceDefinition

async def register():
    my_services = [
        ServiceDefinition(name="my_service", description="Does something cool", endpoint_info={"type": "A2A"})
    ]
    # metadata_uri should point to a publicly accessible JSON with agent name, description, etc.
    success = await sdk.register_self(metadata_uri="ipfs://your_metadata_hash", services=my_services)
    if success:
        print("Agent registered successfully!")
```

**Sending a Message:**
```python
from a2a_protocol import MessageType

# Assume target_agent_id and target_enc_key_b64 are known (e.g., from registry)
target_agent_id = "RECEIVER_AGENT_PUBKEY_STRING"
target_enc_key_b64 = "RECEIVER_AGENT_ENCRYPTION_KEY_B64"

message_payload = {"action": "perform_magic", "level": 11}

# Create an encrypted and signed message
encrypted_msg = sdk.create_encrypted_message(
    receiver_id_str=target_agent_id,
    receiver_enc_pub_key_b64=target_enc_key_b64,
    message_type=MessageType.INVOKE_SERVICE, # Or any other relevant MessageType
    actual_payload=message_payload
)

message_json = encrypted_msg.to_json()
# Send message_json over your chosen transport layer (HTTP, WebSockets, etc.)
```

**Processing an Incoming Message:**
```python
from a2a_protocol import A2AMessage
from typing import Dict, Any, Optional

async def my_service_handler(message: A2AMessage, decrypted_payload: Optional[Dict[str, Any]]):
    if decrypted_payload:
        print(f"Received service invocation: {decrypted_payload}")
        # Process the service call
        # ... send response ...

# Register handlers for specific message types
sdk.register_message_handler(MessageType.INVOKE_SERVICE, my_service_handler)

# When a raw JSON message string is received from transport:
# await sdk.process_incoming_message_json(raw_json_message_str)
```

Refer to `example_agent.py` and `sdk.py` for more detailed usage patterns.

## Future Work

*   **On-Chain Program Development:** Implement the Agent Registry, A2A Protocol, and Task Engine as Solana smart contracts in Rust (using Anchor).
*   **Transport Layer Agnosticism:** Design clear interfaces for agents to plug in various communication transport layers (e.g., WebSockets, libp2p, HTTP POSTs with polling).
*   **Decentralized Governance:** Introduce a DAO for protocol upgrades and community participation.
*   **Cross-Chain Interoperability:** Research and develop mechanisms for interaction with agents on other blockchains.
*   **Advanced AI/ML Integration:** Facilitate deeper integration with off-chain ML models, potentially with verifiable computation.
*   **Agent Reputation System:** Develop an on-chain system for assessing agent trustworthiness.

## Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) (to be created) for guidelines on how to contribute to the project, including code contributions, bug reports, and feature requests.

## License

This project is licensed under the [Apache License 2.0](LICENSE). (Or MIT, please update if different and add a LICENSE file).
