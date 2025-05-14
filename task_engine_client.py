# task_engine_client.py
import logging
import uuid
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import time

from solana.rpc.api import Client
# from anchorpy import Program, Provider, Wallet # If using Anchor

import config
import utils
from agent_identity import AgentIdentity
from a2a_protocol import A2AMessage  # For task-related messages if sent via A2A

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"  # Proposed and accepted by participant(s)
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"  # Proposal rejected


@dataclass
class TaskState:
    task_id: str
    initiator_agent_id_str: str
    # participating_agent_ids_str: List[str] = field(default_factory=list) # Agents involved if multi-agent task
    status: TaskStatus
    workflow_uri: Optional[str] = None  # Link to workflow definition
    input_params_hash: Optional[str] = None  # b64 encoded hash of input params
    results_hash: Optional[str] = None      # b64 encoded hash of results
    current_step: int = 0
    total_steps: Optional[int] = None
    last_updated: float = field(default_factory=time.time)
    error_message: Optional[str] = None
    # On-chain representation might include more details like PDA addresses,Lamports for escrow, etc.


# In-memory mock task store
_MOCK_TASK_STORE: Dict[str, TaskState] = {}


class TaskEngineClient:
    """Client for interacting with the Task Automation Engine.
    Currently uses a mock in-memory task store.
    """

    def __init__(self, solana_client: Optional[Client] = None, identity: Optional[AgentIdentity] = None):
        self.solana_client = solana_client if solana_client else Client(
            config.SOLANA_RPC_URL)
        self.identity = identity  # Current agent's identity, needed for on-chain interactions
        # self.program = None # Initialize Anchor program here if/when available
        logger.info("TaskEngineClient initialized (using MOCK task store).")

    def _get_program(self):
        # Placeholder for Anchor program initialization
        # provider = Provider(self.solana_client, Wallet(self.identity.solana_keypair))
        # self.program = Program.at(config.TASK_ENGINE_PROGRAM_ID, provider)
        # return self.program
        raise NotImplementedError(
            "On-chain program interaction is not yet implemented.")

    async def propose_task(self, initiator_agent_id: str, workflow_uri: Optional[str], input_params: Dict[str, Any]) -> Optional[str]:
        """Proposes a new task to the engine."""
        if not self.identity or self.identity.public_key_str != initiator_agent_id:
            logger.error("Task proposer identity mismatch or not set.")
            return None

        task_id = str(uuid.uuid4())
        serialized_params = utils.serialize_data_to_json(
            input_params).encode('utf-8')
        # In a real system, you might use a proper hashing algorithm like SHA256
        # For simplicity, let's assume this is a placeholder or a simple representation
        # For stronger integrity, a cryptographic hash (e.g., SHA256) of serialized_params would be used.
        # For this mock, we'll just store the string representation or a simple hash for now.
        input_params_hash_str = utils.b64encode_bytes(
            serialized_params)  # Placeholder for actual hash

        task_state = TaskState(
            task_id=task_id,
            initiator_agent_id_str=initiator_agent_id,
            status=TaskStatus.PENDING,
            workflow_uri=workflow_uri,
            input_params_hash=input_params_hash_str
        )
        _MOCK_TASK_STORE[task_id] = task_state
        logger.info(f"Task {task_id} proposed by {initiator_agent_id} (MOCK).")
        # Here, you might emit an A2A message of type TASK_PROPOSAL to potential participants
        return task_id

        # TODO: On-chain interaction to create a task account

    async def get_task_state(self, task_id: str) -> Optional[TaskState]:
        """Retrieves the current state of a task."""
        state = _MOCK_TASK_STORE.get(task_id)
        if state:
            logger.debug(f"Retrieved state for task {task_id} (MOCK).")
        else:
            logger.warning(f"Task {task_id} not found in MOCK store.")
        return state
        # TODO: On-chain interaction to fetch task account data

    async def update_task_status(self, task_id: str, new_status: TaskStatus, current_step: Optional[int] = None, results_hash: Optional[str] = None, error_message: Optional[str] = None) -> bool:
        """Updates the status of a task. Performed by an authorized agent (initiator or participant)."""
        if not self.identity:
            logger.error("Agent identity not set. Cannot update task.")
            return False

        task = _MOCK_TASK_STORE.get(task_id)
        if not task:
            logger.error(f"Task {task_id} not found for status update (MOCK).")
            return False

        # Basic authorization: only initiator can update for now in mock
        # Real system would have more granular control, e.g. assigned agent for current step
        if self.identity.public_key_str != task.initiator_agent_id_str:
            logger.warning(
                f"Agent {self.identity.public_key_str} not authorized to update task {task_id} (MOCK).")
            # In a multi-agent scenario, a participating agent might update status for their part.
            # This logic needs to be more robust based on workflow.
            # For now, let's allow any identity to update for testing mock store if the task exists.
            # return False

        task.status = new_status
        task.last_updated = time.time()
        if current_step is not None:
            task.current_step = current_step
        if results_hash:
            task.results_hash = results_hash
        if error_message:
            task.error_message = error_message

        _MOCK_TASK_STORE[task_id] = task  # Update the store
        logger.info(
            f"Task {task_id} status updated to {new_status} by {self.identity.public_key_str} (MOCK).")
        # Here, you might emit an A2A message of type TASK_STATUS_UPDATE
        return True
        # TODO: On-chain interaction to update task account state

    async def list_tasks_by_status(self, status: TaskStatus) -> List[TaskState]:
        """Lists tasks with a specific status."""
        tasks = [t for t in _MOCK_TASK_STORE.values() if t.status == status]
        logger.info(f"Found {len(tasks)} tasks with status {status} (MOCK).")
        return tasks

    async def list_tasks_by_initiator(self, initiator_id_str: str) -> List[TaskState]:
        """Lists tasks initiated by a specific agent."""
        tasks = [t for t in _MOCK_TASK_STORE.values(
        ) if t.initiator_agent_id_str == initiator_id_str]
        logger.info(
            f"Found {len(tasks)} tasks initiated by {initiator_id_str} (MOCK).")
        return tasks

# Example usage (if run directly, for testing)


async def main_task_engine_test():
    import asyncio
    utils.setup_logging()
    logging.getLogger().setLevel(logging.DEBUG)

    test_identity = AgentIdentity.generate()
    task_client = TaskEngineClient(identity=test_identity)

    # Propose a task
    task_id = await task_client.propose_task(
        initiator_agent_id=test_identity.public_key_str,
        workflow_uri="ipfs://some_workflow_definition",
        input_params={"data_url": "http://example.com/data.csv",
                      "operation": "sum_column_A"}
    )
    assert task_id is not None
    print(f"Task proposed with ID: {task_id}")

    # Get task state
    state = await task_client.get_task_state(task_id)
    assert state is not None
    assert state.status == TaskStatus.PENDING
    print(
        f"Initial task state: {state.status}, Input hash: {state.input_params_hash}")

    # Update task status
    update_success = await task_client.update_task_status(task_id, TaskStatus.IN_PROGRESS, current_step=1)
    assert update_success
    state = await task_client.get_task_state(task_id)
    assert state.status == TaskStatus.IN_PROGRESS
    assert state.current_step == 1
    print(
        f"Updated task state: {state.status}, Current step: {state.current_step}")

    # Complete task
    results_hash_example = utils.b64encode_bytes(b"hash_of_results_data")
    complete_success = await task_client.update_task_status(task_id, TaskStatus.COMPLETED, current_step=2, results_hash=results_hash_example)
    assert complete_success
    state = await task_client.get_task_state(task_id)
    assert state.status == TaskStatus.COMPLETED
    assert state.results_hash == results_hash_example
    print(
        f"Completed task state: {state.status}, Results hash: {state.results_hash}")

    # List tasks by status
    completed_tasks = await task_client.list_tasks_by_status(TaskStatus.COMPLETED)
    assert len(completed_tasks) >= 1
    print(f"Number of completed tasks: {len(completed_tasks)}")

    # List tasks by initiator
    initiator_tasks = await task_client.list_tasks_by_initiator(test_identity.public_key_str)
    assert len(initiator_tasks) >= 1
    print(
        f"Tasks initiated by {test_identity.public_key_str}: {len(initiator_tasks)}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main_task_engine_test())
