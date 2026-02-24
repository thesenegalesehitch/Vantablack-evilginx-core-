from celery import Celery
from typing import Dict, Any
import json

# Configure Celery to use Redis as the broker and result backend
# This assumes Redis is running on localhost. In production, use a config file.
app = Celery(
    'vantablack_events',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
)

def publish_event(event_type: str, data: Dict[str, Any]):
    """
    Publishes an event to a dynamic Celery task queue.

    Args:
        event_type: The name of the event (e.g., 'credential_captured').
                    This will be used as the task name.
        data: The JSON-serializable payload of the event.
    """
    # The task name is the event type. Workers will listen for specific task names.
    app.send_task(f'vantablack.events.{event_type}', args=[data])
