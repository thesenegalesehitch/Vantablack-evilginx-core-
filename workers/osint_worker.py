from core.event_bus import app, publish_event
import logging
import httpx
from bs4 import BeautifulSoup
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("OSINTWorker")

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

@app.task(name='vantablack.osint.find_emails_from_domain')
def find_emails_from_domain(domain: str):
    """
    Performs a basic Google search to find public email addresses for a given domain.
    """
    logger.info(f"[OSINT] Starting email search for domain: {domain}")
    search_query = f'"@{domain}"'
    google_url = f"https://www.google.com/search?q={search_query}"

    try:
        with httpx.Client() as client:
            # Use a realistic user agent to avoid being blocked
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = client.get(google_url, headers=headers)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            found_emails = set(re.findall(EMAIL_REGEX, soup.get_text()))

            if found_emails:
                logger.info(f"[OSINT] Found {len(found_emails)} potential emails for {domain}: {found_emails}")
                # Publish an event with the findings
                publish_event('osint_result_found', {
                    'domain': domain,
                    'type': 'emails',
                    'data': list(found_emails)
                })
                return list(found_emails)
            else:
                logger.info(f"[OSINT] No public emails found for {domain} via Google search.")
                return []

    except Exception as e:
        logger.error(f"[OSINT] Error during email search for {domain}: {e}")
        return []

# To run this worker:
# celery -A workers.osint_worker worker --loglevel=info
