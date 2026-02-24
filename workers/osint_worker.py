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

import json
from core.llm_client import generate_text

@app.task(name='vantablack.osint.generate_spear_phishing_email')
async def generate_spear_phishing_email(target_info: dict):
    """
    Generates a personalized spear phishing email using a local LLM.
    """
    logger.info(f"[OSINT] Generating spear phishing email for: {target_info.get('name')}")

    # Create a detailed prompt for the LLM
    prompt = f"""
    You are a creative social engineer. Your task is to write a highly convincing and personalized spear phishing email.
    
    **Target Information:**
    - Name: {target_info.get('name')}
    - Position: {target_info.get('position')}
    - Company: {target_info.get('company')}
    - Recent Activity: {target_info.get('activity', 'None')}

    **Instructions:**
    1. Create a plausible scenario. Examples: a fake security alert, a project update, a request from a colleague, an HR notification.
    2. The tone should be professional and urgent, but not suspicious.
    3. The email should contain a clear call to action, asking the user to click a link. Represent the link with the placeholder `{{phishing_link}}`.
    4. The email should have a subject and a body.
    5. Output the result as a JSON object with two keys: "subject" and "body".
    
    Example Output:
    {{
        "subject": "Urgent: Security Policy Update",
        "body": "Hello {target_info.get('name')},\n\nDue to a recent security incident, all employees are required to review and accept the new security policy here: {{phishing_link}}\n\nThank you,\nIT Security Team"
    }}
    """

    generated_json_str = await generate_text(prompt)
    
    try:
        # The LLM should return a JSON string. We parse it.
        email_data = json.loads(generated_json_str)
        logger.info(f"[OSINT] Successfully generated email for {target_info.get('name')}")
        
        publish_event('spear_phishing_email_generated', {
            "target_info": target_info,
            "email_data": email_data
        })
        
        return email_data
    except json.JSONDecodeError:
        error_msg = f"[OSINT] LLM did not return valid JSON. Output: {generated_json_str}"
        logger.error(error_msg)
        return {"error": error_msg}


# To run this worker:
# celery -A workers.osint_worker worker --loglevel=info
