import json
import os

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware

try:
    from .engine import ThreatClassifier
except ImportError:
    from engine import ThreatClassifier

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "bert_security_model")
MITRE_FILE = os.path.join(BASE_DIR, "mitre_attack.json")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = ThreatClassifier(
    bert_path=MODEL_DIR,
    mitre_path=MITRE_FILE,
)
active_connections = []

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    data    = await request.json()
    command = data.get("command", "")

    result = model.analyze(command)

    alert = {
        "timestamp":    data.get("timestamp"),
        "attacker_ip":  data.get("attacker_ip"),
        "command":      command,
        "verdict":      result["verdict"],
        "tactic":       result["tactic"],
        "technique_id": result["technique_id"],
        "confidence":   int(result["confidence"] * 100),
        "explanation":  result["explanation"],
        "mitigations":  result["mitigations"],
    }

    for connection in active_connections:
        await connection.send_text(json.dumps(alert))

    action = "BLOCK" if result["kill"] else "ALLOW"
    if result["kill"]:
        print(f"[!] CRITICAL THREAT: {result['tactic']} — {result['technique_id']} ({alert['confidence']}%) — KILL SIGNAL SENT")

    return {
        "status": "processed",
        "action": action,
        "alert": alert
    }

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        active_connections.remove(websocket)